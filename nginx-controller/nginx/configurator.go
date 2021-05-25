/*
Copyright IBM Corporation 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nginx

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/internal"
	"github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser"
	"github.com/golang/glog"
	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1beta1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

const (
	emptyHost               = ""
	oneWaySSLAuthentication = "OneWaySSLAuthentication"
	twoWaySSLAuthentication = "TwoWaySSLAuthentication"
	valueTrue               = "TRUE"
	valueFalse              = "FALSE"
	appIDRequestTypeCheck   = "web"

	// FrontendRole ...
	FrontendRole = "frontend"
	// AllIngressServiceName ...
	AllIngressServiceName = "fd-k8-all"
)

var (
	// SnortUpstreamServers used for Snort, if adding new snort container update this Object
	SnortUpstreamServers = Upstream{
		Name: "proxy_snort", UpstreamServers: []UpstreamServer{
			{
				Address: "127.0.0.1",
				Port:    "7481",
			},
			{
				Address: "127.0.0.1",
				Port:    "7482",
			},
			{
				Address: "127.0.0.1",
				Port:    "7483",
			},
		},
	}

	ingressPodCount = 2
)

// IsDefaultServerConfGlobal ...
var IsDefaultServerConfGlobal = true

// Configurator transforms an Ingress resource into NGINX Configuration
type Configurator struct {
	nginx      *IngressNginxController
	config     *Config
	lock       sync.Mutex
	kubeClient kubernetes.Interface
}

// ProxyPems ...
type ProxyPems struct {
	commonName                     string
	sslAuthentication              string
	proxySslTrustedCertificateFile string
	proxySslCertificateFile        string
	proxySslCertificateKeyFile     string
	proxySslVerifyDepth            int
}

type externalsvc struct {
	path  string
	host  string
	svc   string
	isssl bool
}

// SSLServicesData holds the value of the attrtibutes parsed from the ssl-services annotation of Ingresses
type SSLServicesData struct {
	SecretName          string
	ProxySSLVerifyDepth int
	ProxySSLName        string
}

// NewConfigurator creates a new Configurator
func NewConfigurator(nginx *IngressNginxController, config *Config, kubeClient kubernetes.Interface) *Configurator {
	cnf := Configurator{
		nginx:      nginx,
		config:     config,
		kubeClient: kubeClient,
	}
	return &cnf
}

// GetNginxCertsPath ...
func (cnf *Configurator) GetNginxCertsPath() string {
	return cnf.nginx.nginxCertsPath
}

// AddOrUpdateDHParam ...
func (cnf *Configurator) AddOrUpdateDHParam(content string) (string, error) {
	return cnf.nginx.AddOrUpdateDHParam(content)
}

// AddOrUpdateIngress adds or updates NGINX configuration for an Ingress resource
func (cnf *Configurator) AddOrUpdateIngress(name string, ingEx *IngressEx) {
	cnf.lock.Lock()
	defer cnf.lock.Unlock()

	pems := cnf.updateCertificates(ingEx)
	cnf.generateNginxStreamCfg(name, ingEx)
	nginxCfg := cnf.generateNginxCfg(ingEx, pems)
	cnf.nginx.AddOrUpdateIngress(name, nginxCfg)
	rm := internal.ResourceManager{
		Client: cnf.kubeClient}

	if err := cnf.nginx.Reload(); err != nil {
		glog.Errorf("Error when adding or updating ingress %q: %q", name, err)
		rm.GenerateKubeEvent(internal.EventError{
			MsgCode:      "E0004",
			Ing:          ingEx.Ingress,
			OverwriteMsg: err.Error(),
		})
	} else {
		rm.GenerateKubeEvent(internal.EventError{
			MsgCode: "S0001",
			Ing:     ingEx.Ingress,
		})
	}
}

// GetPodScale ...
func (cnf *Configurator) GetPodScale() int {
	return ingressPodCount
}

// SetPodScale ...
func (cnf *Configurator) SetPodScale(PodVal int) {
	glog.V(4).Info("Setting pod scale in configurator")
	cnf.lock.Lock()
	defer cnf.lock.Unlock()
	ingressPodCount = PodVal
}

func (cnf *Configurator) updateCertificates(ingEx *IngressEx) map[string]string {
	pems := make(map[string]string)

	rm := internal.ResourceManager{
		Client: cnf.kubeClient}

	for _, tls := range ingEx.Ingress.Spec.TLS {
		secretName := tls.SecretName
		secret, exist := ingEx.Secrets[secretName]
		if !exist {
			continue
		}
		cert, ok := secret.Data[api.TLSCertKey]
		if !ok {
			glog.Warningf("Secret %v has no 'tls.crt'", secretName)
			rm.GenerateKubeEvent(internal.EventError{
				MsgCode: "E0005",
				Ing:     ingEx.Ingress,
			})
			continue
		}
		key, ok := secret.Data[api.TLSPrivateKeyKey]
		if !ok {
			glog.Warningf("Secret %v has no 'tls.key'", secretName)
			rm.GenerateKubeEvent(internal.EventError{
				MsgCode: "E0006",
				Ing:     ingEx.Ingress,
			})
			continue
		}

		name := ingEx.Ingress.Namespace + "-" + secretName
		pemFileName := cnf.nginx.AddOrUpdateCertAndKey(name, string(cert), string(key), "")

		for _, host := range tls.Hosts {
			pems[host] = pemFileName
		}
		if len(tls.Hosts) == 0 {
			pems[emptyHost] = pemFileName
		}
	}
	return pems
}

func (cnf *Configurator) updateMutualAuthCertificates(ingEx *IngressEx, secretName string, serverName string) map[string]string {
	pems := make(map[string]string)
	name := ingEx.Ingress.Namespace + "-" + secretName

	rm := internal.ResourceManager{
		Client: cnf.kubeClient}

	secret, exist := ingEx.Secrets[secretName]
	if !exist {
		glog.Errorf("updateMutualAuthCertificates: Secret %v does not exist", secretName)
		rm.GenerateKubeEvent(internal.EventError{
			MsgCode: "E0007",
			Ing:     ingEx.Ingress,
		})
		return pems
	}

	ca, ok := secret.Data["ca.crt"]
	if !ok {
		glog.Infof("updateMutualAuthCertificates: Secret %v has no 'ca.crt', defaulting to 'tls.crt'.", secretName)
		rm.GenerateKubeEvent(internal.EventError{
			MsgCode: "E0008",
			Ing:     ingEx.Ingress,
		})
		ca, ok = secret.Data[api.TLSCertKey]
		if !ok {
			glog.Errorf("updateMutualAuthCertificates: Secret %v has no 'tls.crt'", secretName)
			rm.GenerateKubeEvent(internal.EventError{
				MsgCode: "E0009",
				Ing:     ingEx.Ingress,
			})
			return pems
		}
		pemFileName := cnf.nginx.AddOrUpdateCertAndKey(name, "", "", string(ca))
		pems[serverName] = pemFileName
		return pems
	}

	// Add the tls certs for tls if they exist
	serverCert, okCert := secret.Data[api.TLSCertKey]
	serverKey, okKey := secret.Data[api.TLSPrivateKeyKey]
	if okCert && okKey {
		glog.Infof("updateMutualAuthCertificates: TLS Cert and Private Key have been provided in %s.", secretName)
	}

	pemFileName := cnf.nginx.AddOrUpdateCertAndKey(name, string(serverCert), string(serverKey), string(ca))
	pems[serverName] = pemFileName

	return pems
}

func (cnf *Configurator) generateNginxStreamCfg(name string, ingEx *IngressEx) {
	ingCfg := *cnf.config
	if StreamAnnotation, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/tcp-ports"]; exists {
		ingCfg.Stream = StreamAnnotation
	} else {
		//delete the file if no tcp-ports is found
		filename := cnf.nginx.getIngressNginxStreamConfigFileName(name)
		RemoveFileIfExist(filename)
		return
	}
	//get stream config
	if CfgStream, err := ParseStreamConfigs(ingCfg.Stream); err != nil {
		glog.Error(err)
	} else {
		upstreams := make(map[string]Upstream)
		for i, cfg := range CfgStream {
			upsName := getNameForUpstream(ingEx.Ingress, "stream", cfg.ServiceName)
			var backend networking.IngressBackend
			backend.ServiceName = cfg.ServiceName
			backend.ServicePort.StrVal = cfg.ServicePort
			backend.ServicePort = intstr.FromString(cfg.ServicePort)
			(&CfgStream[i]).ServiceName = upsName
			if _, exists := upstreams[upsName]; !exists {
				upstream := cnf.createUpstream(ingEx, upsName, &backend, ingEx.Ingress.Namespace, "", cfg.ServiceName)
				upstreams[upsName] = upstream
			}
		}
		cnf.nginx.AddOrUpdateIngressStream(name, CfgStream, upstreams)
	}
}

func (cnf *Configurator) generateNginxCfg(ingEx *IngressEx, pems map[string]string) IngressNginxConfig {
	ingCfg := cnf.createConfig(ingEx)
	var err error

	upstreams := make(map[string]Upstream)
	var istioIngressUpstream []Upstream

	wsServices := getWebsocketServices(ingEx)
	spServices := getSessionPersistenceServices(ingEx)
	rewrites := getRewrites(ingEx)

	proxySslPems := make(map[string]ProxyPems)
	if ingEx.IsUpsreamSSLs {
		glog.V(4).Infof("ssl-service is available")
		proxySslPems = cnf.updateProxyCertificates(ingEx)
	} else {
		glog.V(4).Infof("There is no ssl-service")
	}

	// TODO: All these annotations must be moved to handlers
	iamAuthService, iamAuthClientID, iamAuthClientSecret, iamAuthClientSecretNS, iamAuthRedirectURL, iamAuthPresent, iamAuthEnableAll := getUIIAM(ingEx)
	iamCliAuthService, iamCliAllSvc, annotationExists := getCLIIAM(ingEx)
	wtAuthURL := getWatsonAuthURL(ingEx)
	wtAuthServices, wtSecondaryHosts, wtSecondaryIngress, wtUpstreamSvcs, wtPresent := getWatsonAuth(ingEx, cnf) //this has been moved to handler

	statsdEnabled := getCarrierLocationEnable(ingEx)
	proxyUpstreamValues, proxyUpstreamTimeout, proxyUpstreamTries := getProxyNextUpstream(ingEx)
	extSvcs := getExtSvcs(ingEx)

	// annotations
	serviceRatelimitAnnotation, serviceRatelimitAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/service-rate-limit", ingEx)
	var serviceratelimits []RateLimitZone
	var serviceRateLimitErr error

	if serviceRatelimitAnnotationExists {
		serviceratelimits, serviceRateLimitErr = handleLocRateLimitZones(serviceRatelimitAnnotation, ingressPodCount, ingEx.Ingress.Name)
		if serviceRateLimitErr != nil {
			rm := internal.ResourceManager{
				Client: cnf.kubeClient}
			rm.GenerateKubeEvent(internal.EventError{
				MsgCode:      "A0001",
				Ing:          ingEx.Ingress,
				OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/service-rate-limit", serviceRateLimitErr),
			})
		}
		glog.V(3).Infof("service rate limits %v", serviceratelimits)
	}
	connectTimeoutAnnotation, connectAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/proxy-connect-timeout", ingEx)
	readTimeoutAnnotation, readAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/proxy-read-timeout", ingEx)
	proxyBuffersAnnotation, proxyBuffersAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/proxy-buffers", ingEx)
	proxyBufferingAnnotation, proxyBufferingAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/proxy-buffering", ingEx)
	proxyBufferSizeAnnotation, proxyBufferSizeAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/proxy-buffer-size", ingEx)
	addHostPortAnnotation, addHostPortAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/add-host-port", ingEx)
	proxyBusyBufferSizeAnnotation, proxyBusyBufferSizeAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/proxy-busy-buffers-size", ingEx)
	clientMaxBodySizeAnnotation, clientMaxBodySizeAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/client-max-body-size", ingEx)
	globalRatelimitAnnotation, globalRatelimitAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/global-rate-limit", ingEx)
	keepAliveRequestsAnnotation, keepAliveRequestsExists := cnf.GetAnnotationModel("ingress.bluemix.net/keepalive-requests", ingEx)
	keepAliveTimeoutAnnotation, keepAliveTimeoutExists := cnf.GetAnnotationModel("ingress.bluemix.net/keepalive-timeout", ingEx)

	customPortAnnotation, customPortAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/custom-port", ingEx)
	mutualAuthAnnotation, mutualAuthAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/mutual-auth", ingEx)
	largeClientHeaderBuffersAnnotation, largeClientHeaderBuffersAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/large-client-header-buffers", ingEx)
	appIDAuthAnnotation, appIDAuthAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/appid-auth", ingEx)
	locationModifierAnnotation, locationModifierExists := cnf.GetAnnotationModel("ingress.bluemix.net/location-modifier", ingEx)

	defaultServerAnnotation, defaultServerExists := cnf.GetAnnotationModel("ingress.bluemix.net/default-server", ingEx)

	proxySetHeaders := getHeaders(ingEx, "ingress.bluemix.net/proxy-add-headers")
	moreSetHeaders := getHeaders(ingEx, "ingress.bluemix.net/response-add-headers")
	moreClearHeaders := getHeaders(ingEx, "ingress.bluemix.net/response-remove-headers")

	customLocErrors, globalCustomErrors, handlerErr := handleCustomErrors(ingEx)
	if handlerErr != nil {
		rm := internal.ResourceManager{
			Client: cnf.kubeClient}
		rm.GenerateKubeEvent(internal.EventError{
			MsgCode:      "A0001",
			Ing:          ingEx.Ingress,
			OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/custom-errors", handlerErr),
		})
	}

	var customErrAction []CustomErrorActions
	if customErrSnippet, exists, getErr := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "ingress.bluemix.net/custom-error-actions", ingEx.Ingress, "\n"); exists {
		if getErr != nil {
			rm := internal.ResourceManager{
				Client: cnf.kubeClient}
			rm.GenerateKubeEvent(internal.EventError{
				MsgCode:      "A0001",
				Ing:          ingEx.Ingress,
				OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/custom-error-actions", getErr),
			})
			glog.Error(getErr)
		} else {
			customErrAction = handleCustomErrActions(customErrSnippet, ingEx.Ingress.Name, "ingress.bluemix.net/custom-error-actions", "<EOS>")
		}
	}

	if ingEx.Ingress.Spec.Backend != nil {
		name := getNameForUpstream(ingEx.Ingress, emptyHost, ingEx.Ingress.Spec.Backend.ServiceName)
		upstream := cnf.createUpstream(ingEx, name, ingEx.Ingress.Spec.Backend, ingEx.Ingress.Namespace, spServices[ingEx.Ingress.Spec.Backend.ServiceName], ingEx.Ingress.Spec.Backend.ServiceName)
		//if watson pre-auth service then don't add it to the upstream services
		if wtAuthServices[ingEx.Ingress.Spec.Backend.ServiceName] {
			glog.V(3).Infof("service(%s) has no backend", ingEx.Ingress.Spec.Backend.ServiceName)
		} else {
			upstreams[name] = upstream
		}
	}

	keepAliveRequests := make(map[string]string)
	if keepAliveRequestsExists {
		keepAliveRequests, err = handleKeepAliveRequests(keepAliveRequestsAnnotation)
		if err != nil {
			rm := internal.ResourceManager{
				Client: cnf.kubeClient}
			rm.GenerateKubeEvent(internal.EventError{
				MsgCode:      "A0001",
				Ing:          ingEx.Ingress,
				OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/keepalive-requests", err),
			})
		}
	}
	keepAliveTimeout := make(map[string]string)
	if keepAliveTimeoutExists {
		keepAliveTimeout, err = handleKeepAliveTimeout(keepAliveTimeoutAnnotation)
		if err != nil {
			if err != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/keepalive-timeout", err),
				})
			}
		}
	}

	var servers []Server
	var globalRateLimitZones []RateLimitZone
	rootLocationCreated := false

	for _, rule := range ingEx.Ingress.Spec.Rules {
		isExtSvcInHost := false

		for _, extSvc := range extSvcs {
			if extSvc.host == rule.Host {
				isExtSvcInHost = true
				break
			}
		}

		// TODO: Refactor this
		if (rule.IngressRuleValue.HTTP == nil && !isExtSvcInHost) && (ingEx.Ingress.Namespace != "kube-system" && ingEx.Ingress.Name != "alb-health") {
			continue
		}

		serverName := rule.Host

		if rule.Host == emptyHost {
			glog.Warningf("Host field of ingress rule in %v/%v is empty", ingEx.Ingress.Namespace, ingEx.Ingress.Name)
		}
		if globalRatelimitAnnotationExists {
			globalRateLimitZones, err = handleGlobalRatelimitzones(globalRatelimitAnnotation, ingressPodCount, ingEx.Ingress.Name)
			if err != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/global-rate-limit", err),
				})
			}
		}

		server := Server{
			Name:                     serverName,
			ServerTokens:             ingCfg.ServerTokens,
			HTTP2:                    ingCfg.HTTP2,
			RedirectToHTTPS:          ingCfg.RedirectToHTTPS,
			ProxyProtocol:            ingCfg.ProxyProtocol,
			HSTS:                     ingCfg.HSTS,
			HSTSMaxAge:               ingCfg.HSTSMaxAge,
			HSTSIncludeSubdomains:    ingCfg.HSTSIncludeSubdomains,
			IamGlobalEndpoint:        ingCfg.IamGlobalEndpoint,
			RealIPHeader:             ingCfg.RealIPHeader,
			SetRealIPFrom:            ingCfg.SetRealIPFrom,
			RealIPRecursive:          ingCfg.RealIPRecursive,
			ProxyHideHeaders:         ingCfg.ProxyHideHeaders,
			ProxyPassHeaders:         ingCfg.ProxyPassHeaders,
			ServerSnippets:           ingCfg.ServerSnippets,
			GlobalSerRateLimitZones:  globalRateLimitZones,
			OptionLocation:           false,
			WatsonAuthLocation:       wtAuthURL,
			IamAuthLocation:          iamAuthPresent,
			AppIDEnabled:             false,
			IamCliAuthLocation:       annotationExists,
			IamAllCliAuthLocation:    iamCliAllSvc,
			KeepAliveTimeout:         keepAliveTimeout[""],
			KeepAliveRequests:        keepAliveRequests[""],
			GlobalCustomErrors:       globalCustomErrors,
			ErrorActions:             customErrAction,
			LargeClientHeaderBuffers: ingCfg.LargeClientHeaderBuffers,
			IamLogoutEnabled:         false,
		}

		if pemFile, ok := pems[serverName]; ok {
			server.SSL = true
			server.SSLCertificate = pemFile
			server.SSLCertificateKey = pemFile
		}

		if customPortAnnotationExists {
			customPort, getErr := handleCustomPort(customPortAnnotation, ingEx.Ingress.GetName(), serverName)
			if getErr != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/custom-port", getErr),
				})
			}
			if customPort[serverName] != nil {
				httpCount := 0
				httpsCount := 0
				protocols := customPort[serverName]
				for _, protocol := range protocols {
					if protocol.Protocol == "http" {
						server.HTTPPort = protocol.Port
						httpCount = httpCount + 1
					} else if protocol.Protocol == "https" {
						server.HTTPSPort = protocol.Port
						httpsCount = httpsCount + 1
					}
				}

				if httpCount > 1 {
					glog.Infof("Multiple HTTP protocols specified for host %v, using port %v for HTTP", serverName, server.HTTPPort)
				}

				if httpsCount > 1 {
					glog.Infof("Multiple HTTPS protocols specified for host %v, using port %v for HTTPS", serverName, server.HTTPPort)
				}
			}
		}

		var mutualAuthServices []string
		if mutualAuthAnnotationExists {
			mutualAuth, _, getErr := HandleMutualAuth(mutualAuthAnnotation, ingEx.Ingress.GetName(), serverName)
			if getErr != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. Error %v", "ingress.bluemix.net/mutual-auth", getErr),
				})
			}
			if mutualAuth[serverName] != nil {
				mutualPems := cnf.updateMutualAuthCertificates(ingEx, mutualAuth[serverName][1], serverName)
				if mutualPems[serverName] != "" {
					server.MutualAuthPort = mutualAuth[serverName][0]
					server.SSLClientCertificate = mutualPems[serverName]

					if server.HTTPSPort == server.MutualAuthPort || server.HTTPPort == server.MutualAuthPort {
						glog.Errorf("Port %v cannot be the same for both HTTP/HTTPS and Mutual Auth. Mutual Auth will not be enabled.", server.MutualAuthPort)
					} else {
						glog.Infof("Mutual Auth enabled on port %v for host %v.", server.MutualAuthPort, serverName)
					}
				}
			}
		}

		if largeClientHeaderBuffersAnnotationExists {
			largeClientHeaderBuffers, getErr := handleLargeClientHeaderBuffers(largeClientHeaderBuffersAnnotation, serverName)
			if getErr != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/large-client-header-buffers", getErr),
				})
			}
			if largeClientHeaderBuffers[serverName] != "" {
				server.LargeClientHeaderBuffers = largeClientHeaderBuffers[serverName]
			}
		}

		if defaultServerExists {
			defaultServer, getErr := handleDefaultServer(defaultServerAnnotation)
			if getErr != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/default-server", getErr),
				})
			} else {
				server.IsDefaultServer = defaultServer
				if defaultServer == true {
					IsDefaultServerConfGlobal = false

					mainCfg := &IngressNginxMainConfig{
						IsDefaultServerConf: IsDefaultServerConfGlobal,
						Backlog:             ingCfg.Backlog,
						ReusePort:           ingCfg.ReusePort,
					}
					cnf.nginx.UpdateDefaultConfFile(mainCfg)
				}
			}
		}

		var locations []Location
		rootLocation := false
		var locationRateLimitZones []RateLimitZone
		var locProxyConnectTimeout, locProxyReadTimeout, clientMaxBodySize, proxyBufferSize, proxyBusyBufferSize string
		var proxyBuffers ProxyBuffer
		var locProxyBuffering bool
		var locHostPort bool
		var locationModifier string
		var iamLogout bool

		// AppId
		appIDSecret := ""
		appIDSecretNamespace := ""
		appIDRequestType := ""
		appIDToken := true

		if isExtSvcInHost {
			for _, extSvc := range extSvcs {
				if extSvc.host == rule.Host {
					sslAuthentication := false
					sslTwoWayAuthentication := false
					plainSSLAuthentication := true
					if extSvc.isssl {
						glog.V(3).Infof("ext-svc %v is a ssl-service ", extSvc.svc)
						if proxySslPems[extSvc.svc].sslAuthentication == oneWaySSLAuthentication {
							sslAuthentication = true
							plainSSLAuthentication = false
						} else {
							if proxySslPems[extSvc.svc].sslAuthentication == twoWaySSLAuthentication {
								sslAuthentication = true
								sslTwoWayAuthentication = true
								plainSSLAuthentication = false
							}
						}
					} else {
						glog.V(3).Infof("ext-svc %v is not ssl-service ", extSvc.svc)
					}
					locationRateLimitZones = getRatelimitZonesForService(serviceratelimits, extSvc.svc)
					if connectAnnotationExists {
						if locProxyConnectTimeout, err = handleLocProxyTimeout(connectTimeoutAnnotation, extSvc.svc); locProxyConnectTimeout == "" {
							if err != nil {
								rm := internal.ResourceManager{
									Client: cnf.kubeClient}
								rm.GenerateKubeEvent(internal.EventError{
									MsgCode:      "A0001",
									Ing:          ingEx.Ingress,
									OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-connect-timeout", err),
								})
							}
							locProxyConnectTimeout = ingCfg.ProxyConnectTimeout
						}
					} else {
						locProxyConnectTimeout = ingCfg.ProxyConnectTimeout
					}

					if readAnnotationExists {
						if locProxyReadTimeout, err = handleLocProxyTimeout(readTimeoutAnnotation, extSvc.svc); locProxyReadTimeout == "" {
							if err != nil {
								rm := internal.ResourceManager{
									Client: cnf.kubeClient}
								rm.GenerateKubeEvent(internal.EventError{
									MsgCode:      "A0001",
									Ing:          ingEx.Ingress,
									OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-read-timeout", err),
								})
							}
							locProxyReadTimeout = ingCfg.ProxyReadTimeout
						}
					} else {
						locProxyReadTimeout = ingCfg.ProxyReadTimeout
					}

					if proxyBufferSizeAnnotationExists {
						proxyBufferSize, err = handleLocProxyBufferSize(proxyBufferSizeAnnotation, extSvc.svc)
						if err != nil {
							rm := internal.ResourceManager{
								Client: cnf.kubeClient}
							rm.GenerateKubeEvent(internal.EventError{
								MsgCode:      "A0001",
								Ing:          ingEx.Ingress,
								OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-buffer-size", err),
							})
						}
					}

					if proxyBusyBufferSizeAnnotationExists {
						proxyBusyBufferSize, err = handleLocProxyBufferSize(proxyBusyBufferSizeAnnotation, extSvc.svc)
						if err != nil {
							rm := internal.ResourceManager{
								Client: cnf.kubeClient}
							rm.GenerateKubeEvent(internal.EventError{
								MsgCode:      "A0001",
								Ing:          ingEx.Ingress,
								OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-busy-buffers-size", err),
							})
						}
					}

					if proxyBuffersAnnotationExists {
						proxyBuffers.Size, proxyBuffers.Number, err = handleLocProxyBuffers(proxyBuffersAnnotation, extSvc.svc)
						if err != nil {
							rm := internal.ResourceManager{
								Client: cnf.kubeClient}
							rm.GenerateKubeEvent(internal.EventError{
								MsgCode:      "A0001",
								Ing:          ingEx.Ingress,
								OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-buffers", err),
							})
						}
					}

					if proxyBufferingAnnotationExists {
						locProxyBuffering, err = handleLocProxyBuffering(proxyBufferingAnnotation, extSvc.svc)
						if err != nil {
							rm := internal.ResourceManager{
								Client: cnf.kubeClient}
							rm.GenerateKubeEvent(internal.EventError{
								MsgCode:      "A0001",
								Ing:          ingEx.Ingress,
								OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-buffering", err),
							})
						}
					} else {
						locProxyBuffering = ingCfg.ProxyBuffering
					}

					if clientMaxBodySizeAnnotationExists {
						if clientMaxBodySize, err = handleLocClientMaxBodySize(clientMaxBodySizeAnnotation, extSvc.svc); clientMaxBodySize == "" {
							if err != nil {
								rm := internal.ResourceManager{
									Client: cnf.kubeClient}
								rm.GenerateKubeEvent(internal.EventError{
									MsgCode:      "A0001",
									Ing:          ingEx.Ingress,
									OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/client-max-body-size", err),
								})
							}
							clientMaxBodySize = ingCfg.ClientMaxBodySize
						}
					} else {
						clientMaxBodySize = ingCfg.ClientMaxBodySize
					}

					if locationModifierExists {
						locationModifier, err = handleLocationModifier(locationModifierAnnotation, extSvc.svc)
						if err != nil {
							rm := internal.ResourceManager{
								Client: cnf.kubeClient}
							rm.GenerateKubeEvent(internal.EventError{
								MsgCode:      "A0001",
								Ing:          ingEx.Ingress,
								OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/location-modifier", err),
							})
						}
					}

					extDNSResolver := os.Getenv("EXT_DNS_RESOLVER")
					glog.Infof("extDNSResolver in configurator - %s ", extDNSResolver)

					extloc := createExtSvcLocation(pathOrDefault(extSvc.path),
						&ingCfg,
						extSvc.svc,
						sslAuthentication,
						sslTwoWayAuthentication,
						proxySslPems[extSvc.svc].proxySslTrustedCertificateFile,
						proxySslPems[extSvc.svc].proxySslCertificateFile,
						proxySslPems[extSvc.svc].proxySslCertificateKeyFile,
						proxySslPems[extSvc.svc].proxySslVerifyDepth,
						locationRateLimitZones,
						ingCfg.LocationSnippets[extSvc.svc],
						proxyUpstreamValues[extSvc.svc],
						proxyUpstreamTimeout[extSvc.svc],
						proxyUpstreamTries[extSvc.svc],
						plainSSLAuthentication,
						locProxyConnectTimeout,
						locProxyReadTimeout,
						clientMaxBodySize,
						customLocErrors[extSvc.svc],
						proxyBufferSize,
						proxyBuffers,
						proxyBusyBufferSize,
						extDNSResolver,
						locProxyBuffering,
						locationModifier,
						ingEx.UpstreamSSLData[extSvc.svc].ProxySSLConfig.ProxySSLName,
					)
					locations = append(locations, extloc)
					glog.Infof("external svc identified for this host")
				}
			}
		}
		if rule.HTTP != nil {
			// Retreieve insgress istio ingress upstreams
			istioIngressUpstream = cnf.createIstioIngressUpstream(ingEx, rule.Host)

			for _, path := range rule.HTTP.Paths {
				setOptions := false
				sslAuthentication := false
				sslTwoWayAuthentication := false
				plainSSLAuthentication := true
				upsName := getNameForUpstream(ingEx.Ingress, rule.Host, path.Backend.ServiceName)

				// check whether the upstream for the backend has already been populated in istioIngressUpstream array
				// if yes then populate in upstreams map ,if not then the backend is not istio enabled .
				istioIngressUpstreamFound := false
				for _, elem := range istioIngressUpstream {
					if elem.Name == upsName {
						istioIngressUpstreamFound = true
						upstreams[elem.Name] = elem
						break
					}
				}

				if _, exists := upstreams[upsName]; !exists && !istioIngressUpstreamFound {
					upstream := cnf.createUpstream(ingEx, upsName, &path.Backend, ingEx.Ingress.Namespace, spServices[path.Backend.ServiceName], path.Backend.ServiceName)
					if wtAuthServices[path.Backend.ServiceName] {
						glog.V(3).Infof("service(%s) has no backend in rule.http", path.Backend.ServiceName)
					} else {
						upstreams[upsName] = upstream
					}
				}
				locationRateLimitZones = getRatelimitZonesForService(serviceratelimits, path.Backend.ServiceName)
				if _, ok := ingEx.UpstreamSSLData[path.Backend.ServiceName]; ok {
					glog.V(3).Infof("writing ssl-service %v location", path.Backend.ServiceName)
					ingEx.IsUpsreamSSLs = true
					if proxySslPems[path.Backend.ServiceName].sslAuthentication == oneWaySSLAuthentication {
						sslAuthentication = true
						plainSSLAuthentication = false
					} else {
						if proxySslPems[path.Backend.ServiceName].sslAuthentication == twoWaySSLAuthentication {
							sslAuthentication = true
							sslTwoWayAuthentication = true
							plainSSLAuthentication = false
						}
					}
				} else {
					if proxySslPems[path.Backend.ServiceName].sslAuthentication == "PlainSSLAuthentication" {
						glog.V(3).Infof("writing plain ssl-service %v location", path.Backend.ServiceName)
						ingEx.IsUpsreamSSLs = true
						sslAuthentication = true
					} else {
						glog.V(3).Infof("writing non ssl-service %v location", path.Backend.ServiceName)
						ingEx.IsUpsreamSSLs = false
					}
				}

				if connectAnnotationExists {
					if locProxyConnectTimeout, err = handleLocProxyTimeout(connectTimeoutAnnotation, path.Backend.ServiceName); locProxyConnectTimeout == "" {
						if err != nil {
							rm := internal.ResourceManager{
								Client: cnf.kubeClient}
							rm.GenerateKubeEvent(internal.EventError{
								MsgCode:      "A0001",
								Ing:          ingEx.Ingress,
								OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-connect-timeout", err),
							})
						}
						locProxyConnectTimeout = ingCfg.ProxyConnectTimeout
					}
				} else {
					locProxyConnectTimeout = ingCfg.ProxyConnectTimeout
				}

				if readAnnotationExists {
					if locProxyReadTimeout, err = handleLocProxyTimeout(readTimeoutAnnotation, path.Backend.ServiceName); locProxyReadTimeout == "" {
						if err != nil {
							rm := internal.ResourceManager{
								Client: cnf.kubeClient}
							rm.GenerateKubeEvent(internal.EventError{
								MsgCode:      "A0001",
								Ing:          ingEx.Ingress,
								OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-read-timeout", err),
							})
						}
						locProxyReadTimeout = ingCfg.ProxyReadTimeout
					}
				} else {
					locProxyReadTimeout = ingCfg.ProxyReadTimeout
				}

				if proxyBufferSizeAnnotationExists {
					proxyBufferSize, err = handleLocProxyBufferSize(proxyBufferSizeAnnotation, path.Backend.ServiceName)
					if err != nil {
						rm := internal.ResourceManager{
							Client: cnf.kubeClient}
						rm.GenerateKubeEvent(internal.EventError{
							MsgCode:      "A0001",
							Ing:          ingEx.Ingress,
							OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-buffer-size", err),
						})
					}
				}

				if proxyBusyBufferSizeAnnotationExists {
					proxyBusyBufferSize, err = handleLocProxyBufferSize(proxyBusyBufferSizeAnnotation, path.Backend.ServiceName)
					if err != nil {
						rm := internal.ResourceManager{
							Client: cnf.kubeClient}
						rm.GenerateKubeEvent(internal.EventError{
							MsgCode:      "A0001",
							Ing:          ingEx.Ingress,
							OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-busy-buffers-size", err),
						})
					}
				}

				if proxyBuffersAnnotationExists {
					proxyBuffers.Size, proxyBuffers.Number, err = handleLocProxyBuffers(proxyBuffersAnnotation, path.Backend.ServiceName)
					if err != nil {
						rm := internal.ResourceManager{
							Client: cnf.kubeClient}
						rm.GenerateKubeEvent(internal.EventError{
							MsgCode:      "A0001",
							Ing:          ingEx.Ingress,
							OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-buffers", err),
						})
					}
				}

				if clientMaxBodySizeAnnotationExists {
					if clientMaxBodySize, err = handleLocClientMaxBodySize(clientMaxBodySizeAnnotation, path.Backend.ServiceName); clientMaxBodySize == "" {
						if err != nil {
							rm := internal.ResourceManager{
								Client: cnf.kubeClient}
							rm.GenerateKubeEvent(internal.EventError{
								MsgCode:      "A0001",
								Ing:          ingEx.Ingress,
								OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/client-max-body-size", err),
							})
						}
						clientMaxBodySize = ingCfg.ClientMaxBodySize
					}
				} else {
					clientMaxBodySize = ingCfg.ClientMaxBodySize
				}

				if appIDAuthAnnotationExists {
					appIDSecret, appIDSecretNamespace, appIDRequestType, appIDToken, err = handleAppIDAuth(appIDAuthAnnotation, path.Backend.ServiceName)
					if err != nil {
						rm := internal.ResourceManager{
							Client: cnf.kubeClient}
						rm.GenerateKubeEvent(internal.EventError{
							MsgCode:      "A0001",
							Ing:          ingEx.Ingress,
							OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/appid-auth", err),
						})
					} else {
						server.AppIDEnabled = true
						if appIDRequestType == appIDRequestTypeCheck {
							server.AppIDWebEnabled = true
						}
					}
				}

				if proxyBufferingAnnotationExists {
					locProxyBuffering, err = handleLocProxyBuffering(proxyBufferingAnnotation, path.Backend.ServiceName)
					if err != nil {
						rm := internal.ResourceManager{
							Client: cnf.kubeClient}
						rm.GenerateKubeEvent(internal.EventError{
							MsgCode:      "A0001",
							Ing:          ingEx.Ingress,
							OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-buffering", err),
						})
					}
				} else {
					locProxyBuffering = ingCfg.ProxyBuffering
				}

				if addHostPortAnnotationExists {
					locHostPort, err = handleLocHostPort(addHostPortAnnotation, path.Backend.ServiceName)
					if err != nil {
						rm := internal.ResourceManager{
							Client: cnf.kubeClient}
						rm.GenerateKubeEvent(internal.EventError{
							MsgCode:      "A0001",
							Ing:          ingEx.Ingress,
							OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/add-host-port", err),
						})
					}
				}

				if locationModifierExists {
					locationModifier, err = handleLocationModifier(locationModifierAnnotation, path.Backend.ServiceName)
					if err != nil {
						rm := internal.ResourceManager{
							Client: cnf.kubeClient}
						rm.GenerateKubeEvent(internal.EventError{
							MsgCode:      "A0001",
							Ing:          ingEx.Ingress,
							OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/location-modifier", err),
						})
					}
				}

				//only want to set the options for "/" when WatsonIAM is used.  Options only applies to "/" Path
				if (path.Path == "" || path.Path == "/") && wtPresent {
					setOptions = true
				}

				if iamAuthEnableAll {
					iamAuthService[path.Backend.ServiceName] = true
					iamAuthClientID[path.Backend.ServiceName] = iamAuthClientID[AllIngressServiceName]
					iamAuthClientSecret[path.Backend.ServiceName] = iamAuthClientSecret[AllIngressServiceName]
					iamAuthClientSecretNS[path.Backend.ServiceName] = iamAuthClientSecretNS[AllIngressServiceName]
					iamAuthRedirectURL[path.Backend.ServiceName] = iamAuthRedirectURL[AllIngressServiceName]
				}

				loc := createLocation(pathOrDefault(path.Path),
					upstreams[upsName],
					&ingCfg,
					wsServices[path.Backend.ServiceName],
					rewrites[path.Backend.ServiceName],
					ingEx.IsUpsreamSSLs,
					proxySetHeaders[path.Backend.ServiceName],
					moreSetHeaders[path.Backend.ServiceName],
					moreClearHeaders[path.Backend.ServiceName],
					sslAuthentication,
					sslTwoWayAuthentication,
					proxySslPems[path.Backend.ServiceName].proxySslTrustedCertificateFile,
					proxySslPems[path.Backend.ServiceName].proxySslCertificateFile,
					proxySslPems[path.Backend.ServiceName].proxySslCertificateKeyFile,
					locationRateLimitZones,
					proxySslPems[path.Backend.ServiceName].proxySslVerifyDepth,
					ingCfg.LocationSnippets[path.Backend.ServiceName],
					wtAuthServices[path.Backend.ServiceName],
					wtSecondaryHosts[path.Backend.ServiceName],
					wtSecondaryIngress[path.Backend.ServiceName],
					setOptions,
					wtUpstreamSvcs[path.Backend.ServiceName],
					iamAuthService[path.Backend.ServiceName],
					iamAuthClientID[path.Backend.ServiceName],
					iamAuthClientSecret[path.Backend.ServiceName],
					iamAuthClientSecretNS[path.Backend.ServiceName],
					iamAuthRedirectURL[path.Backend.ServiceName],
					path.Backend.ServiceName,
					proxyUpstreamValues[path.Backend.ServiceName],
					proxyUpstreamTimeout[path.Backend.ServiceName],
					proxyUpstreamTries[path.Backend.ServiceName],
					plainSSLAuthentication,
					locProxyConnectTimeout,
					locProxyReadTimeout,
					clientMaxBodySize,
					keepAliveTimeout[path.Backend.ServiceName],
					keepAliveRequests[path.Backend.ServiceName],
					iamCliAuthService[path.Backend.ServiceName],
					customLocErrors[path.Backend.ServiceName],
					proxyBufferSize,
					proxyBuffers,
					proxyBusyBufferSize,
					locProxyBuffering,
					locHostPort,
					statsdEnabled,
					appIDSecret,
					appIDSecretNamespace,
					appIDRequestType,
					appIDToken,
					locationModifier,
					iamLogout,
					ingEx.UpstreamSSLData[path.Backend.ServiceName].ProxySSLConfig.ProxySSLName,
				)
				var newUpstreamForSSL Upstream
				if _, ok := ingEx.UpstreamSSLData[path.Backend.ServiceName]; ok {
					if ingEx.UpstreamSSLData[path.Backend.ServiceName].ProxySSLConfig.ProxySSLName == "" {
						glog.V(4).Infof("ServiceName =  %v", path.Backend.ServiceName)
						newUpstreamForSSL = prepareSSLUpstreamForLocation(loc, ingEx, path.Backend.ServiceName)
						if newUpstreamForSSL.Name == "" {
							continue
						}
						if _, exists := upstreams[newUpstreamForSSL.Name]; !exists {
							upstreams[newUpstreamForSSL.Name] = newUpstreamForSSL
						}
						loc.Upstream = newUpstreamForSSL
					}
				}

				locations = append(locations, loc)

				if loc.Path == "/" {
					rootLocation = true
					rootLocationCreated = true
				}
			}
		}

		if !rootLocation && ingEx.Ingress.Spec.Backend != nil {
			sslAuthentication := false
			sslTwoWayAuthentication := false
			plainSSLAuthentication := true
			locationRateLimitZones = getRatelimitZonesForService(serviceratelimits, ingEx.Ingress.Spec.Backend.ServiceName)
			upsName := getNameForUpstream(ingEx.Ingress, emptyHost, ingEx.Ingress.Spec.Backend.ServiceName)
			if _, ok := ingEx.UpstreamSSLData[ingEx.Ingress.Spec.Backend.ServiceName]; ok {
				glog.V(3).Infof("writing ssl-service %v location", ingEx.Ingress.Spec.Backend.ServiceName)
				ingEx.IsUpsreamSSLs = true
				if proxySslPems[ingEx.Ingress.Spec.Backend.ServiceName].sslAuthentication == oneWaySSLAuthentication {
					sslAuthentication = true
					plainSSLAuthentication = false
				} else {
					if proxySslPems[ingEx.Ingress.Spec.Backend.ServiceName].sslAuthentication == twoWaySSLAuthentication {
						sslAuthentication = true
						sslTwoWayAuthentication = true
						plainSSLAuthentication = false
					}
				}
			} else {
				if proxySslPems[ingEx.Ingress.Spec.Backend.ServiceName].sslAuthentication == "PlainSSLAuthentication" {
					glog.V(3).Infof("writing plain ssl-service %v location", ingEx.Ingress.Spec.Backend.ServiceName)
					ingEx.IsUpsreamSSLs = true
					sslAuthentication = true
				} else {
					glog.V(3).Infof("writing non ssl-service %v location", ingEx.Ingress.Spec.Backend.ServiceName)
					ingEx.IsUpsreamSSLs = false
				}
			}

			if connectAnnotationExists {
				if locProxyConnectTimeout, err = handleLocProxyTimeout(connectTimeoutAnnotation, ingEx.Ingress.Spec.Backend.ServiceName); locProxyConnectTimeout == "" {
					if err != nil {
						rm := internal.ResourceManager{
							Client: cnf.kubeClient}
						rm.GenerateKubeEvent(internal.EventError{
							MsgCode:      "A0001",
							Ing:          ingEx.Ingress,
							OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-connect-timeout", err),
						})
					}
					locProxyConnectTimeout = ingCfg.ProxyConnectTimeout
				}
			} else {
				locProxyConnectTimeout = ingCfg.ProxyConnectTimeout
			}
			if readAnnotationExists {
				if locProxyReadTimeout, err = handleLocProxyTimeout(readTimeoutAnnotation, ingEx.Ingress.Spec.Backend.ServiceName); locProxyReadTimeout == "" {
					if err != nil {
						rm := internal.ResourceManager{
							Client: cnf.kubeClient}
						rm.GenerateKubeEvent(internal.EventError{
							MsgCode:      "A0001",
							Ing:          ingEx.Ingress,
							OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-read-timeout", err),
						})
					}
					locProxyReadTimeout = ingCfg.ProxyReadTimeout
				}
			} else {
				locProxyReadTimeout = ingCfg.ProxyReadTimeout
			}

			if proxyBufferSizeAnnotationExists {
				proxyBufferSize, err = handleLocProxyBufferSize(proxyBufferSizeAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
				if err != nil {
					rm := internal.ResourceManager{
						Client: cnf.kubeClient}
					rm.GenerateKubeEvent(internal.EventError{
						MsgCode:      "A0001",
						Ing:          ingEx.Ingress,
						OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-buffer-size", err),
					})
				}
			}

			if proxyBusyBufferSizeAnnotationExists {
				proxyBusyBufferSize, err = handleLocProxyBufferSize(proxyBusyBufferSizeAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
				if err != nil {
					rm := internal.ResourceManager{
						Client: cnf.kubeClient}
					rm.GenerateKubeEvent(internal.EventError{
						MsgCode:      "A0001",
						Ing:          ingEx.Ingress,
						OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-busy-buffers-size", err),
					})
				}
			}

			if proxyBuffersAnnotationExists {
				proxyBuffers.Size, proxyBuffers.Number, err = handleLocProxyBuffers(proxyBuffersAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
				if err != nil {
					rm := internal.ResourceManager{
						Client: cnf.kubeClient}
					rm.GenerateKubeEvent(internal.EventError{
						MsgCode:      "A0001",
						Ing:          ingEx.Ingress,
						OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-buffers", err),
					})
				}
			}
			if clientMaxBodySizeAnnotationExists {
				if clientMaxBodySize, err = handleLocClientMaxBodySize(clientMaxBodySizeAnnotation, ingEx.Ingress.Spec.Backend.ServiceName); clientMaxBodySize == "" {
					if err != nil {
						rm := internal.ResourceManager{
							Client: cnf.kubeClient}
						rm.GenerateKubeEvent(internal.EventError{
							MsgCode:      "A0001",
							Ing:          ingEx.Ingress,
							OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/client-max-body-size", err),
						})
					}
					clientMaxBodySize = ingCfg.ClientMaxBodySize
				}
			} else {
				clientMaxBodySize = ingCfg.ClientMaxBodySize
			}

			if appIDAuthAnnotationExists {
				appIDSecret, appIDSecretNamespace, appIDRequestType, appIDToken, err = handleAppIDAuth(appIDAuthAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
				if err != nil {
					rm := internal.ResourceManager{
						Client: cnf.kubeClient}
					rm.GenerateKubeEvent(internal.EventError{
						MsgCode:      "A0001",
						Ing:          ingEx.Ingress,
						OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/appid-auth", err),
					})
				} else {
					server.AppIDEnabled = true
					if appIDRequestType == appIDRequestTypeCheck {
						server.AppIDWebEnabled = true
					}
				}
			}

			if proxyBufferingAnnotationExists {
				locProxyBuffering, err = handleLocProxyBuffering(proxyBufferingAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
				if err != nil {
					rm := internal.ResourceManager{
						Client: cnf.kubeClient}
					rm.GenerateKubeEvent(internal.EventError{
						MsgCode:      "A0001",
						Ing:          ingEx.Ingress,
						OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-buffering", err),
					})
				}
			} else {
				locProxyBuffering = ingCfg.ProxyBuffering
			}

			if addHostPortAnnotationExists {
				locHostPort, err = handleLocHostPort(addHostPortAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
				if err != nil {
					rm := internal.ResourceManager{
						Client: cnf.kubeClient}
					rm.GenerateKubeEvent(internal.EventError{
						MsgCode:      "A0001",
						Ing:          ingEx.Ingress,
						OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/add-host-port", err),
					})
				}
			}

			if locationModifierExists {
				locationModifier, err = handleLocationModifier(locationModifierAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
				if err != nil {
					rm := internal.ResourceManager{
						Client: cnf.kubeClient}
					rm.GenerateKubeEvent(internal.EventError{
						MsgCode:      "A0001",
						Ing:          ingEx.Ingress,
						OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/location-modifier", err),
					})
				}
			}

			if iamAuthEnableAll {
				iamAuthService[ingEx.Ingress.Spec.Backend.ServiceName] = true
				iamAuthClientID[ingEx.Ingress.Spec.Backend.ServiceName] = iamAuthClientID[AllIngressServiceName]
				iamAuthClientSecret[ingEx.Ingress.Spec.Backend.ServiceName] = iamAuthClientSecret[AllIngressServiceName]
				iamAuthClientSecretNS[ingEx.Ingress.Spec.Backend.ServiceName] = iamAuthClientSecretNS[AllIngressServiceName]
				iamAuthRedirectURL[ingEx.Ingress.Spec.Backend.ServiceName] = iamAuthRedirectURL[AllIngressServiceName]
			}

			loc := createLocation(pathOrDefault("/"),
				upstreams[upsName],
				&ingCfg,
				wsServices[ingEx.Ingress.Spec.Backend.ServiceName],
				rewrites[ingEx.Ingress.Spec.Backend.ServiceName],
				ingEx.IsUpsreamSSLs,
				proxySetHeaders[ingEx.Ingress.Spec.Backend.ServiceName],
				moreSetHeaders[ingEx.Ingress.Spec.Backend.ServiceName],
				moreClearHeaders[ingEx.Ingress.Spec.Backend.ServiceName],
				sslAuthentication,
				sslTwoWayAuthentication,
				proxySslPems[ingEx.Ingress.Spec.Backend.ServiceName].proxySslTrustedCertificateFile,
				proxySslPems[ingEx.Ingress.Spec.Backend.ServiceName].proxySslCertificateFile,
				proxySslPems[ingEx.Ingress.Spec.Backend.ServiceName].proxySslCertificateKeyFile,
				locationRateLimitZones,
				proxySslPems[ingEx.Ingress.Spec.Backend.ServiceName].proxySslVerifyDepth,
				ingCfg.LocationSnippets[ingEx.Ingress.Spec.Backend.ServiceName],
				wtAuthServices[ingEx.Ingress.Spec.Backend.ServiceName],
				wtSecondaryHosts[ingEx.Ingress.Spec.Backend.ServiceName],
				wtSecondaryIngress[ingEx.Ingress.Spec.Backend.ServiceName],
				wtPresent,
				wtUpstreamSvcs[ingEx.Ingress.Spec.Backend.ServiceName],
				iamAuthService[ingEx.Ingress.Spec.Backend.ServiceName],
				iamAuthClientID[ingEx.Ingress.Spec.Backend.ServiceName],
				iamAuthClientSecret[ingEx.Ingress.Spec.Backend.ServiceName],
				iamAuthClientSecretNS[ingEx.Ingress.Spec.Backend.ServiceName],
				iamAuthRedirectURL[ingEx.Ingress.Spec.Backend.ServiceName],
				ingEx.Ingress.Spec.Backend.ServiceName,
				proxyUpstreamValues[ingEx.Ingress.Spec.Backend.ServiceName],
				proxyUpstreamTimeout[ingEx.Ingress.Spec.Backend.ServiceName],
				proxyUpstreamTries[ingEx.Ingress.Spec.Backend.ServiceName],
				plainSSLAuthentication,
				locProxyConnectTimeout,
				locProxyReadTimeout,
				clientMaxBodySize,
				keepAliveTimeout[ingEx.Ingress.Spec.Backend.ServiceName],
				keepAliveRequests[ingEx.Ingress.Spec.Backend.ServiceName],
				iamCliAuthService[ingEx.Ingress.Spec.Backend.ServiceName],
				customLocErrors[ingEx.Ingress.Spec.Backend.ServiceName],
				proxyBufferSize,
				proxyBuffers,
				proxyBusyBufferSize,
				locProxyBuffering,
				locHostPort,
				statsdEnabled,
				appIDSecret,
				appIDSecretNamespace,
				appIDRequestType,
				appIDToken,
				locationModifier,
				iamLogout,
				ingEx.UpstreamSSLData[ingEx.Ingress.Spec.Backend.ServiceName].ProxySSLConfig.ProxySSLName,
			)
			var newUpstreamForSSL Upstream
			if _, ok := ingEx.UpstreamSSLData[ingEx.Ingress.Spec.Backend.ServiceName]; ok {
				if ingEx.UpstreamSSLData[ingEx.Ingress.Spec.Backend.ServiceName].ProxySSLConfig.ProxySSLName == "" {
					newUpstreamForSSL = prepareSSLUpstreamForLocation(loc, ingEx, ingEx.Ingress.Spec.Backend.ServiceName)
					if newUpstreamForSSL.Name == "" {
						continue
					}
					if _, exists := upstreams[newUpstreamForSSL.Name]; !exists {
						upstreams[newUpstreamForSSL.Name] = newUpstreamForSSL
					}
					loc.Upstream = newUpstreamForSSL
				}
			}
			locations = append(locations, loc)
		}

		//in this case the default "/" has not been created yet but watsonIAM is present then add options
		if !rootLocationCreated && wtPresent {
			server.OptionLocation = true
		}

		server.Locations = locations

		// copy over locations
		var tempLocations []Location
		tempLocations = append(tempLocations, locations...)

		if len(mutualAuthServices) > 0 {
			for _, maSvc := range mutualAuthServices {
				for _, loc := range tempLocations {
					if loc.SvcName == maSvc {
						server.MutualAuthPaths = append(server.MutualAuthPaths, loc.Path)
					}
				}
			}

			// get paths not in MutualAuth paths by subtracting it from a set of all
			for _, svc := range mutualAuthServices {
				for j, loc := range tempLocations {
					if svc == loc.SvcName {
						tempLocations = append(tempLocations[:j], tempLocations[j+1:]...)
						break
					}
				}
			}

			nonMutualAuthPaths := []string{}
			for _, loc := range tempLocations {
				nonMutualAuthPaths = append(nonMutualAuthPaths, loc.Path)
			}
			server.NonMutualAuthPaths = nonMutualAuthPaths
		} else {
			//Add all paths to keep default behavior
			for _, loc := range locations {
				server.MutualAuthPaths = append(server.MutualAuthPaths, loc.Path)
				server.NonMutualAuthPaths = append(server.NonMutualAuthPaths, loc.Path)
			}
		}

		servers = append(servers, server)
	}
	if globalRatelimitAnnotationExists {
		globalRateLimitZones, err = handleGlobalRatelimitzones(globalRatelimitAnnotation, ingressPodCount, ingEx.Ingress.Name)
		if err != nil {
			rm := internal.ResourceManager{
				Client: cnf.kubeClient}
			rm.GenerateKubeEvent(internal.EventError{
				MsgCode:      "A0001",
				Ing:          ingEx.Ingress,
				OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/global-rate-limit", err),
			})
		}
	}

	if len(ingEx.Ingress.Spec.Rules) == 0 && ingEx.Ingress.Spec.Backend != nil {
		server := Server{
			Name:                     emptyHost,
			ServerTokens:             ingCfg.ServerTokens,
			HTTP2:                    ingCfg.HTTP2,
			RedirectToHTTPS:          ingCfg.RedirectToHTTPS,
			ProxyProtocol:            ingCfg.ProxyProtocol,
			HSTS:                     ingCfg.HSTS,
			HSTSMaxAge:               ingCfg.HSTSMaxAge,
			HSTSIncludeSubdomains:    ingCfg.HSTSIncludeSubdomains,
			IamGlobalEndpoint:        ingCfg.IamGlobalEndpoint,
			RealIPHeader:             ingCfg.RealIPHeader,
			SetRealIPFrom:            ingCfg.SetRealIPFrom,
			RealIPRecursive:          ingCfg.RealIPRecursive,
			ProxyHideHeaders:         ingCfg.ProxyHideHeaders,
			ProxyPassHeaders:         ingCfg.ProxyPassHeaders,
			ServerSnippets:           ingCfg.ServerSnippets,
			GlobalSerRateLimitZones:  globalRateLimitZones,
			OptionLocation:           false,
			WatsonAuthLocation:       wtAuthURL,
			IamAuthLocation:          iamAuthPresent,
			AppIDEnabled:             false,
			KeepAliveTimeout:         keepAliveTimeout[""],
			KeepAliveRequests:        keepAliveRequests[""],
			LargeClientHeaderBuffers: ingCfg.LargeClientHeaderBuffers,
		}

		if pemFile, ok := pems[emptyHost]; ok {
			server.SSL = true
			server.SSLCertificate = pemFile
			server.SSLCertificateKey = pemFile
		}

		var locations []Location
		var locationRateLimitZones []RateLimitZone
		var locProxyConnectTimeout, locProxyReadTimeout, clientMaxBodySize, proxyBufferSize, proxyBusyBufferSize, locationModifier string
		var proxyBuffers ProxyBuffer
		var locProxyBuffering, iamLogout bool
		var locHostPort bool

		// AppId
		appIDSecret := ""
		appIDSecretNamespace := ""
		appIDRequestType := ""
		appIDToken := true

		locationRateLimitZones = getRatelimitZonesForService(serviceratelimits, ingEx.Ingress.Spec.Backend.ServiceName)
		upsName := getNameForUpstream(ingEx.Ingress, emptyHost, ingEx.Ingress.Spec.Backend.ServiceName)

		if connectAnnotationExists {
			if locProxyConnectTimeout, err = handleLocProxyTimeout(connectTimeoutAnnotation, ingEx.Ingress.Spec.Backend.ServiceName); locProxyConnectTimeout == "" {
				if err != nil {
					rm := internal.ResourceManager{
						Client: cnf.kubeClient}
					rm.GenerateKubeEvent(internal.EventError{
						MsgCode:      "A0001",
						Ing:          ingEx.Ingress,
						OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-connect-timeout", err),
					})
				}
				locProxyConnectTimeout = ingCfg.ProxyConnectTimeout
			}
		} else {
			locProxyConnectTimeout = ingCfg.ProxyConnectTimeout
		}

		if readAnnotationExists {
			if locProxyReadTimeout, err = handleLocProxyTimeout(readTimeoutAnnotation, ingEx.Ingress.Spec.Backend.ServiceName); locProxyReadTimeout == "" {
				if err != nil {
					rm := internal.ResourceManager{
						Client: cnf.kubeClient}
					rm.GenerateKubeEvent(internal.EventError{
						MsgCode:      "A0001",
						Ing:          ingEx.Ingress,
						OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-read-timeout", err),
					})
				}
				locProxyReadTimeout = ingCfg.ProxyReadTimeout
			}
		} else {
			locProxyReadTimeout = ingCfg.ProxyReadTimeout
		}

		if proxyBufferSizeAnnotationExists {
			proxyBufferSize, err = handleLocProxyBufferSize(proxyBufferSizeAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
			if err != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-buffer-size", err),
				})
			}
		}

		if proxyBusyBufferSizeAnnotationExists {
			proxyBusyBufferSize, err = handleLocProxyBufferSize(proxyBusyBufferSizeAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
			if err != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-busy-buffers-size", err),
				})
			}
		}

		if proxyBuffersAnnotationExists {
			proxyBuffers.Size, proxyBuffers.Number, err = handleLocProxyBuffers(proxyBuffersAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
			if err != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-buffers", err),
				})
			}
		}

		if clientMaxBodySizeAnnotationExists {
			if clientMaxBodySize, err = handleLocClientMaxBodySize(clientMaxBodySizeAnnotation, ingEx.Ingress.Spec.Backend.ServiceName); clientMaxBodySize == "" {
				if err != nil {
					rm := internal.ResourceManager{
						Client: cnf.kubeClient}
					rm.GenerateKubeEvent(internal.EventError{
						MsgCode:      "A0001",
						Ing:          ingEx.Ingress,
						OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/client-max-body-size", err),
					})
				}
				clientMaxBodySize = ingCfg.ClientMaxBodySize
			}
		} else {
			clientMaxBodySize = ingCfg.ClientMaxBodySize
		}

		if appIDAuthAnnotationExists {
			appIDSecret, appIDSecretNamespace, appIDRequestType, appIDToken, err = handleAppIDAuth(appIDAuthAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
			if err != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/appid-auth", err),
				})
			} else {
				server.AppIDEnabled = true
				if appIDRequestType == appIDRequestTypeCheck {
					server.AppIDWebEnabled = true
				}
			}
		}

		if proxyBufferingAnnotationExists {
			locProxyBuffering, err = handleLocProxyBuffering(proxyBufferingAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
			if err != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/proxy-buffering", err),
				})
			}
		} else {
			locProxyBuffering = ingCfg.ProxyBuffering
		}

		if addHostPortAnnotationExists {
			locHostPort, err = handleLocHostPort(addHostPortAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
			if err != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/add-host-port", err),
				})
			}
		}

		if locationModifierExists {
			locationModifier, err = handleLocationModifier(locationModifierAnnotation, ingEx.Ingress.Spec.Backend.ServiceName)
			if err != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/location-modifier", err),
				})
			}
		}

		if iamAuthEnableAll {
			iamAuthService[ingEx.Ingress.Spec.Backend.ServiceName] = true
			iamAuthClientID[ingEx.Ingress.Spec.Backend.ServiceName] = iamAuthClientID[AllIngressServiceName]
			iamAuthClientSecret[ingEx.Ingress.Spec.Backend.ServiceName] = iamAuthClientSecret[AllIngressServiceName]
			iamAuthClientSecretNS[ingEx.Ingress.Spec.Backend.ServiceName] = iamAuthClientSecretNS[AllIngressServiceName]
			iamAuthRedirectURL[ingEx.Ingress.Spec.Backend.ServiceName] = iamAuthRedirectURL[AllIngressServiceName]
		}

		loc := createLocation(pathOrDefault("/"),
			upstreams[upsName],
			&ingCfg,
			wsServices[ingEx.Ingress.Spec.Backend.ServiceName],
			rewrites[ingEx.Ingress.Spec.Backend.ServiceName],
			false,
			proxySetHeaders[ingEx.Ingress.Spec.Backend.ServiceName],
			moreSetHeaders[ingEx.Ingress.Spec.Backend.ServiceName],
			moreClearHeaders[ingEx.Ingress.Spec.Backend.ServiceName],
			false,
			false,
			proxySslPems[ingEx.Ingress.Spec.Backend.ServiceName].proxySslTrustedCertificateFile,
			proxySslPems[ingEx.Ingress.Spec.Backend.ServiceName].proxySslCertificateFile,
			proxySslPems[ingEx.Ingress.Spec.Backend.ServiceName].proxySslCertificateKeyFile,
			locationRateLimitZones,
			proxySslPems[ingEx.Ingress.Spec.Backend.ServiceName].proxySslVerifyDepth,
			ingCfg.LocationSnippets[ingEx.Ingress.Spec.Backend.ServiceName],
			wtAuthServices[ingEx.Ingress.Spec.Backend.ServiceName],
			wtSecondaryHosts[ingEx.Ingress.Spec.Backend.ServiceName],
			wtSecondaryIngress[ingEx.Ingress.Spec.Backend.ServiceName],
			wtPresent,
			wtUpstreamSvcs[ingEx.Ingress.Spec.Backend.ServiceName],
			iamAuthService[ingEx.Ingress.Spec.Backend.ServiceName],
			iamAuthClientID[ingEx.Ingress.Spec.Backend.ServiceName],
			iamAuthClientSecret[ingEx.Ingress.Spec.Backend.ServiceName],
			iamAuthClientSecretNS[ingEx.Ingress.Spec.Backend.ServiceName],
			iamAuthRedirectURL[ingEx.Ingress.Spec.Backend.ServiceName],
			ingEx.Ingress.Spec.Backend.ServiceName,
			proxyUpstreamValues[ingEx.Ingress.Spec.Backend.ServiceName],
			proxyUpstreamTimeout[ingEx.Ingress.Spec.Backend.ServiceName],
			proxyUpstreamTries[ingEx.Ingress.Spec.Backend.ServiceName],
			false,
			locProxyConnectTimeout,
			locProxyReadTimeout,
			clientMaxBodySize,
			keepAliveTimeout[ingEx.Ingress.Spec.Backend.ServiceName],
			keepAliveRequests[ingEx.Ingress.Spec.Backend.ServiceName],
			iamCliAuthService[ingEx.Ingress.Spec.Backend.ServiceName],
			customLocErrors[ingEx.Ingress.Spec.Backend.ServiceName],
			proxyBufferSize,
			proxyBuffers,
			proxyBusyBufferSize,
			locProxyBuffering,
			locHostPort,
			statsdEnabled,
			appIDSecret,
			appIDSecretNamespace,
			appIDRequestType,
			appIDToken,
			locationModifier,
			iamLogout,
			"",
		)

		locations = append(locations, loc)
		//rootLocationCreated = true

		server.Locations = locations
		servers = append(servers, server)
	}

	return IngressNginxConfig{Upstreams: upstreamMapToSlice(upstreams), Servers: servers, GlobalRatelimitzones: globalRateLimitZones, ServiceRatelimitzones: serviceratelimits}
}

func prepareSSLUpstreamForLocation(loc Location, ingEx *IngressEx, svcName string) Upstream {
	originalUpstream := loc.Upstream

	var newCommonName string
	realCn := ingEx.SSLCommonNames[svcName]
	if strings.Contains(realCn, "*") {
		glog.V(4).Infof("common name contains *.")
		revSlashPath := strings.Replace(loc.Path, "/", "", -1)
		newCommonName = strings.Replace(realCn, "*", revSlashPath, -1)
	} else {
		newCommonName = ingEx.SSLCommonNames[svcName]
		glog.V(4).Infof("common name does not contain *")
	}

	newUpstream := Upstream{
		Name:            newCommonName,
		UpstreamServers: originalUpstream.UpstreamServers,
		StickyCookie:    originalUpstream.StickyCookie,
		KeepAlive:       originalUpstream.KeepAlive,
	}
	return newUpstream
}

//EventLogf ...
func (cnf *Configurator) EventLogf(ingEx *IngressEx, msgCode string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	glog.Infof("[event] " + msg)
	rm := internal.ResourceManager{
		Client: cnf.kubeClient}
	rm.GenerateKubeEvent(internal.EventError{
		MsgCode:      msgCode,
		Ing:          ingEx.Ingress,
		OverwriteMsg: msg,
	})
}

func (cnf *Configurator) updateProxyCertificates(ingEx *IngressEx) map[string]ProxyPems {
	return updateProxyCertificatesImpl(ingEx, cnf, cnf, cnf.nginx)
}

type updateProxyCertificatesDeps interface {
	GetCertificateData([]byte) (map[string]string, error)
	EventLogf(*IngressEx, string, string, ...interface{})
}

type updateProxyCertificatesNginxDeps interface {
	AddOrUpdateTrustedCertAndKey(string, string, string, string) (string, string, string)
}

func updateProxyCertificatesImpl(ingEx *IngressEx, cnfData *Configurator, cnfFuncs updateProxyCertificatesDeps, nginxFuncs updateProxyCertificatesNginxDeps) map[string]ProxyPems {
	pems := make(map[string]ProxyPems)
	ingEx.SSLCommonNames = make(map[string]string)
	var proxySSLVerifyDepth int
	for _, svcName := range ingEx.PlainSSL {
		pems[svcName] = ProxyPems{
			"", "PlainSSLAuthentication", "", "", "", 0,
		}
	}
	glog.V(4).Infof("sslServices in configurator is  %v \n", ingEx.UpstreamSSLData)
	for svcName, secretData := range ingEx.UpstreamSSLData {
		glog.V(4).Infof("svcName is %v\n", svcName)

		if secretData.Secrets.Secret == nil {
			glog.Warningf("Service %s has empty Secret.", svcName)
			break
		}

		if secretData.ProxySSLConfig.ProxySSLVerifyDepth != 0 {
			proxySSLVerifyDepth = secretData.ProxySSLConfig.ProxySSLVerifyDepth
		} else {
			proxySSLVerifyDepth = cnfData.config.ProxySslVerifyDepth
		}

		trustedCert, ok := secretData.Secrets.Secret.Data["trusted.crt"]
		name := ingEx.Ingress.Namespace + "_" + ingEx.Ingress.Name + "_" + secretData.Secrets.SecretName + "_"

		if !ok {
			glog.Warningf("Secret %v has no trusted certificate. It is mandatory for proxy ssl connection", secretData.Secrets.SecretName)
			pems[svcName] = ProxyPems{
				"", "TrustCertificateMissing", "", "", "", 0,
			}
			break
		} else {

			var keyFileName, certFileName, trustedCertFileName string

			cert, certOk := secretData.Secrets.Secret.Data["client.crt"]
			key, keyOk := secretData.Secrets.Secret.Data["client.key"]
			certData, err := cnfFuncs.GetCertificateData(trustedCert)
			if err != nil {
				cnfFuncs.EventLogf(ingEx, "A0001", "Failed to apply annotation \"ingress.bluemix.net/ssl-services\", failed to parse ssl-secret \"%s\"", secretData.Secrets.SecretName)
				continue
			}
			if certData["CommonName"] == "" {
				cnfFuncs.EventLogf(ingEx, "A0001", "Failed to apply annotation \"ingress.bluemix.net/ssl-services\", \"Common Name\" from ssl-secret \"%s\" cannot be empty", secretData.Secrets.SecretName)
				continue
			}
			ingEx.SSLCommonNames[svcName] = certData["CommonName"]
			if certOk && keyOk {
				keyFileName, certFileName, trustedCertFileName = nginxFuncs.AddOrUpdateTrustedCertAndKey(name, string(cert), string(key), string(trustedCert))
				glog.V(3).Infof("certificates are generated")
				pems[svcName] = ProxyPems{
					certData["CommonName"],
					twoWaySSLAuthentication,
					trustedCertFileName,
					certFileName,
					keyFileName,
					proxySSLVerifyDepth,
				}
			} else {
				keyFileName, certFileName, trustedCertFileName = nginxFuncs.AddOrUpdateTrustedCertAndKey(name, "", "", string(trustedCert))
				pems[svcName] = ProxyPems{
					certData["CommonName"],
					oneWaySSLAuthentication,
					trustedCertFileName,
					certFileName,
					keyFileName,
					proxySSLVerifyDepth,
				}
				if !certOk {
					glog.Errorf("Secret %v has no cert", secretData.Secrets.SecretName)
				}
				if !keyOk {
					glog.Errorf("Secret %v has no private key", secretData.Secrets.SecretName)
				}
			}
		}
	}
	return pems
}

// GetCertificateData ...
func (cnf *Configurator) GetCertificateData(secret []byte) (map[string]string, error) {
	certData := make(map[string]string)
	block, _ := pem.Decode(secret)
	if block == nil {
		glog.Errorf("failed to parse certificate")
		return nil, fmt.Errorf("failed to decode secret")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		glog.Errorf("failed to parse certificate: %v", err.Error())
		return nil, fmt.Errorf("failed to parse certificate: %v", err.Error())

	}
	certData["CommonName"] = cert.Subject.CommonName

	return certData, nil
}

func (cnf *Configurator) createConfig(ingEx *IngressEx) Config {
	ingCfg := *cnf.config

	if serverTokens, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "ingress.bluemix.net/server-tokens", ingEx.Ingress); exists {
		if err != nil {
			glog.Error(err)
		} else {
			ingCfg.ServerTokens = serverTokens
		}
	}
	if serverSnippets, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "ingress.bluemix.net/server-snippets", ingEx.Ingress, "\n"); exists {

		if err != nil {
			glog.Error(err)
		} else {
			ingCfg.ServerSnippets = serverSnippets
		}
	}
	if locationSnippets, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "ingress.bluemix.net/location-snippets", ingEx.Ingress, "\n"); exists {
		if err != nil {
			glog.Error(err)
		} else {
			ingCfg.LocationSnippets = ParseLocationSnippetLine(locationSnippets, ingEx.Ingress.Name, "ingress.bluemix.net/location-snippets", "<EOS>")
			ingCfg.AllLocationSnippet = ingCfg.LocationSnippets[AllIngressServiceName]
		}
	}
	if proxyHideHeaders, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "ingress.bluemix.net/proxy-hide-headers", ingEx.Ingress, ","); exists {
		if err != nil {
			glog.Error(err)
		} else {
			ingCfg.ProxyHideHeaders = proxyHideHeaders
		}
	}
	if proxyPassHeaders, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "ingress.bluemix.net/proxy-pass-headers", ingEx.Ingress, ","); exists {
		if err != nil {
			glog.Error(err)
		} else {
			ingCfg.ProxyPassHeaders = proxyPassHeaders
		}
	}
	if HTTP2, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "ingress.bluemix.net/http2", ingEx.Ingress); exists {
		if err != nil {
			glog.Error(err)
		} else {
			ingCfg.HTTP2 = HTTP2
		}
	}
	if redirectToHTTPS, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "ingress.bluemix.net/redirect-to-https", ingEx.Ingress); exists {
		if err != nil {
			glog.Error(err)
		} else {
			ingCfg.RedirectToHTTPS = redirectToHTTPS
		}
	}

	hstsAnnotation, hstsAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/hsts", ingEx)
	if hstsAnnotationExists {
		enabled, maxAge, includeSubdomains, err := handleHSTS(hstsAnnotation)
		if err == nil {
			ingCfg.HSTS = enabled
			ingCfg.HSTSMaxAge = maxAge
			ingCfg.HSTSIncludeSubdomains = includeSubdomains

			glog.V(3).Infof("HSTS enabled on %s", ingEx.Ingress)
		} else {
			rm := internal.ResourceManager{
				Client: cnf.kubeClient}
			rm.GenerateKubeEvent(internal.EventError{
				MsgCode:      "A0001",
				Ing:          ingEx.Ingress,
				OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/hsts", err),
			})
		}
	}

	iamEndpointAnnotation, iamEndpointAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/iam-global-endpoint", ingEx)
	if iamEndpointAnnotationExists {
		endpoint, err := handleIAMEndpoint(iamEndpointAnnotation)
		if err == nil {
			ingCfg.IamGlobalEndpoint = endpoint

			glog.V(3).Infof("IAMGlobalEndpoint configured to %s", endpoint)
		} else {
			rm := internal.ResourceManager{
				Client: cnf.kubeClient}
			rm.GenerateKubeEvent(internal.EventError{
				MsgCode:      "A0001",
				Ing:          ingEx.Ingress,
				OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/iam-global-endpoint", err),
			})
		}
	}

	if proxyMaxTempFileSize, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/proxy-max-temp-file-size"]; exists {
		ingCfg.ProxyMaxTempFileSize = proxyMaxTempFileSize
	}
	if ratelimitMemory, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/rate-limit-memory"]; exists {
		ingCfg.RatelimitMemory = ratelimitMemory
	}
	if ratelimitValue, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/rate-limit-value"]; exists {
		ingCfg.RatelimitValue = ratelimitValue
	}
	if ratelimitBurst, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/rate-limit-burst"]; exists {
		ingCfg.RatelimitBurst = ratelimitBurst
	}
	upActivitytrackerEnv := strings.ToUpper(os.Getenv("ACTIVITY_TRACKER_ENABLED"))
	glog.V(4).Infof("up_activitytracker_env= %v\n", upActivitytrackerEnv)
	if upActivitytrackerEnv != valueTrue {
		ingCfg.ActivityTracker = false
	} else {
		ingCfg.ActivityTracker = true
	}
	glog.V(4).Infof("ActivityTracker config is set to %v\n", ingCfg.ActivityTracker)

	ingCfg.IsIstioPresent = false
	ingCfg.IstioIP = "127.0.0.1"
	portString, isPortPresent := os.LookupEnv("ISTIO_PORT")
	if isPortPresent {
		port, err := strconv.ParseInt(portString, 10, 64)
		if err != nil {
			glog.Error(err)
		} else {
			ingCfg.IstioPort = port
			ingCfg.IsIstioPresent = true
			glog.Infof("Getting istio port %d", ingCfg.IstioPort)
		}
	}
	ipString, isIPPresent := os.LookupEnv("ISTIO_IP")
	if isIPPresent {
		ingCfg.IstioIP = ipString
		glog.Infof("Getting istio ip %s", ingCfg.IstioIP)
	}

	glog.V(4).Infof("ingCfg= %+v ", ingCfg)
	return ingCfg
}

func getSessionPersistenceServices(ingEx *IngressEx) map[string]string {
	spServices := make(map[string]string)
	if services, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/sticky-cookie-services"]; exists {
		for _, svc := range strings.Split(services, ";") {
			if serviceName, sticky, err := parseStickyService(svc); err != nil {
				glog.Errorf("In %v nginx.com/sticky-cookie-services contains invalid declaration: %v, ignoring", ingEx.Ingress.Name, err)
			} else {
				spServices[serviceName] = sticky
			}
		}
	}

	return spServices
}

// ParseSingleStream ...
// ingress.bluemix.net/tcp-ports: "ingressPort=80 serviceName=tea-svc servicePort=8080;ingressPort=81 serviceName=coffee-svc servicePort=8081"
func ParseSingleStream(stream string) (config IngressNginxStreamConfig, err error) {
	stream = strings.TrimSpace(stream)
	streamParts := strings.Split(stream, " ")
	if len(streamParts) < 2 || len(streamParts) > 3 {
		return config, fmt.Errorf("invalid single stream format: %s", stream)
	}

	for _, streamPart := range streamParts {
		parts := strings.Split(streamPart, "=")
		if len(parts) != 2 {
			return config, fmt.Errorf("invalid stream format: %s", streamPart)
		}
		if parts[0] == "ingressPort" {
			config.IngressPort = parts[1]
		}
		if parts[0] == "serviceName" {
			config.ServiceName = parts[1]
		}
		if parts[0] == "servicePort" {
			config.ServicePort = parts[1]
		}
	}
	if config.ServicePort == "" {
		config.ServicePort = config.IngressPort
	}
	if config.IngressPort == "" || config.ServiceName == "" || config.ServicePort == "" {
		return config, fmt.Errorf("invalid annotation %s", stream)
	}
	return config, nil
}

// RemoveFileIfExist ...
func RemoveFileIfExist(filename string) {
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		err := os.Remove(filename)
		if err != nil {
			glog.Warningf("failed to delete file %s, error: %s", filename, err)
		}
	}
}

// ParseStreamConfigs ...
func ParseStreamConfigs(streams string) (configs []IngressNginxStreamConfig, err error) {
	for _, stream := range strings.Split(streams, ";") {
		config, err := ParseSingleStream(stream)
		if err != nil {
			return nil, fmt.Errorf("invalid stream format: %s", stream)
		}
		configs = append(configs, config)
	}
	return configs, nil
}

func parseStickyService(service string) (serviceName string, stickyCookie string, err error) {
	parts := strings.SplitN(service, " ", 2)

	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid sticky-cookie service format: %s", service)
	}
	svcNameParts := strings.Split(parts[0], "=")
	if len(svcNameParts) != 2 {
		return "", "", fmt.Errorf("invalid sticky-cookie service format: %s", svcNameParts)
	}

	return svcNameParts[1], parts[1], nil
}

func getWebsocketServices(ingEx *IngressEx) map[string]bool {
	wsServices := make(map[string]bool)

	if services, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/websocket-services"]; exists {
		for _, svc := range strings.Split(services, ",") {
			wsServices[svc] = true
		}
	}

	return wsServices
}

func getRewrites(ingEx *IngressEx) map[string]string {
	rewrites := make(map[string]string)

	if services, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/rewrite-path"]; exists {
		for _, svc := range strings.Split(services, ";") {
			if serviceName, rewrite, err := parseRewrites(svc); err != nil {
				glog.Errorf("In %v ingress.bluemix.net/rewrite-path contains invalid declaration: %v, ignoring", ingEx.Ingress.Name, err)
			} else {
				rewrites[serviceName] = rewrite
			}
		}
	}

	return rewrites
}

func parseRewrites(service string) (serviceName string, rewrite string, err error) {
	parts := strings.SplitN(service, " ", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("Invalid rewrite format: %s", service)
	}

	svcNameParts := strings.Split(parts[0], "=")
	if len(svcNameParts) != 2 {
		return "", "", fmt.Errorf("Invalid rewrite format: %s", svcNameParts)
	}

	rwPathParts := strings.Split(parts[1], "=")
	if len(rwPathParts) != 2 {
		return "", "", fmt.Errorf("Invalid rewrite format: %s", rwPathParts)
	}

	return svcNameParts[1], rwPathParts[1], nil
}

// GetAnnotationModel ...
func (cnf *Configurator) GetAnnotationModel(annotationStr string, ingEx *IngressEx) (annotationModel parser.ParsedValidatedAnnotation, annotationExists bool) {
	if annotationStringIng, exists := ingEx.Ingress.Annotations[annotationStr]; exists {
		if annotationEntryModel, err := parser.ParseInputForAnnotation(annotationStr, annotationStringIng); err != nil {
			glog.Errorf("In %v %v contains invalid declaration: %v, ignoring", ingEx.Ingress.Name, annotationStr, err)
			// this will cover event generation for all annotations that use the parser
			rm := internal.ResourceManager{
				Client: cnf.kubeClient}
			rm.GenerateKubeEvent(internal.EventError{
				MsgCode:      "A0001",
				Ing:          ingEx.Ingress,
				OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. Error %v", annotationStr, err),
			})
		} else {
			annotationModel = annotationEntryModel
			annotationExists = true
		}
	} else {
		annotationExists = false
	}
	return annotationModel, annotationExists
}

// ParseAnnotation ...
func (cnf *Configurator) ParseAnnotation(annotationStr string, annotationStringIng string, ingEx *IngressEx) (annotationModel parser.ParsedValidatedAnnotation) {
	if annotationEntryModel, err := parser.ParseInputForAnnotation(annotationStr, annotationStringIng); err != nil {
		glog.Errorf("In %v %v contains invalid declaration: %v, ignoring", ingEx.Ingress.Name, annotationStr, err)
		// this will cover event generation for all annotations that use the parser
		rm := internal.ResourceManager{
			Client: cnf.kubeClient}
		rm.GenerateKubeEvent(internal.EventError{
			MsgCode:      "A0001",
			Ing:          ingEx.Ingress,
			OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. Error %v", annotationStr, err),
		})
	} else {
		annotationModel = annotationEntryModel
	}
	return annotationModel
}

// VerifyUseOfIstioSvc ...
func (cnf *Configurator) VerifyUseOfIstioSvc(ingEx *IngressEx, svc *api.Service) (found bool) {
	if istioIngressAnnotationStr, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/istio-services"]; exists {
		istioIngressAnnotation := cnf.ParseAnnotation("ingress.bluemix.net/istio-services", istioIngressAnnotationStr, ingEx)
		for _, entry := range istioIngressAnnotation.Entries {
			if !entry.Exists("istioServiceName") {
				if svc.Name == "istio-ingress" {
					glog.V(3).Infof("found default istio-ingress")
					return true
				}
			} else {
				if istioSvcName, istioSvcExists := entry.GetAsString("istioServiceName"); istioSvcExists {
					glog.V(3).Infof("istioSvcName %v", istioSvcName)
					if svc.Name == istioSvcName {
						return true
					}
				}
			}
		}
	}
	return
}

// GetSSLServices ...
func (cnf *Configurator) GetSSLServices(ingEx *IngressEx) (sslServices map[string]SSLServicesData) {
	sslServices = map[string]SSLServicesData{}
	ingEx.IsUpsreamSSLs = false
	if services, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/ssl-services"]; exists {
		ingEx.IsUpsreamSSLs = true
		var tempSSLServiceData SSLServicesData
		for _, svc := range strings.Split(services, ";") {
			if serviceName, secretName, proxySSLVerifyDepth, proxySSLName, err := parseSslService(svc); err != nil {
				glog.Errorf("In %v ingress.bluemix.net/ssl-services contains invalid declaration: %v, ignoring", ingEx.Ingress.Name, err)
			} else {
				tempSSLServiceData = SSLServicesData{secretName, proxySSLVerifyDepth, proxySSLName}
				sslServices[serviceName] = tempSSLServiceData
			}
		}
	}
	return sslServices
}

func parseSslService(service string) (serviceName string, secret string, proxySSLVerifyDepth int, proxySSLName string, err error) {
	glog.V(4).Infof("service is  %v\n", service)
	parts := strings.Split(service, " ")
	if len(parts) < 1 || len(parts) > 4 {
		return "", "", 0, "", fmt.Errorf("Invalid ssl-services  format: %s", service)
	}
	svcNameParts := strings.Split(parts[0], "=")
	if len(svcNameParts) != 2 {
		return "", "", 0, "", fmt.Errorf("Invalid ssl-services  format: %s", svcNameParts)
	} else if svcNameParts[0] != "ssl-service" {
		return "", "", 0, "", fmt.Errorf("Format error :Expected 1st key is ssl-service in ssl-services annotation.Found %v", svcNameParts[0])
	} else {
		serviceName = svcNameParts[1]
	}
	if len(parts) == 1 {
		secret = ""
	} else {
		secretParts := strings.Split(parts[1], "=")
		if len(secretParts) != 2 {
			return "", "", 0, "", fmt.Errorf("Invalid secret format: %s", secretParts)
		} else if secretParts[0] != "ssl-secret" {
			return "", "", 0, "", fmt.Errorf("Format error :Expected 2nd key is ssl-secret in the ssl-services annotation.Found %v", secretParts[0])
		} else {
			secret = secretParts[1]
		}
	}
	if len(parts) >= 3 {
		if proxySSLVerifyDepth, proxySSLName, err = parseOptionalSSLServiceParts(parts[2:]); err != nil {
			return "", "", 0, "", err
		}
	}
	return serviceName, secret, proxySSLVerifyDepth, proxySSLName, nil
}

func parseOptionalSSLServiceParts(optionalParts []string) (proxySSLVerifyDepth int, proxySSLName string, err error) {
	proxySSLVerifyDepth = 0
	proxySSLName = ""
	for _, parameter := range optionalParts {
		parameterParts := strings.Split(parameter, "=")
		if len(parameterParts) != 2 {
			return 0, "", fmt.Errorf("Invalid optional parameter format in the ingress.bluemix.net/ssl-services annotation: %s", parameter)
		} else if parameterParts[0] == "proxy-ssl-verify-depth" {
			if proxySSLVerifyDepth, err = strconv.Atoi(parameterParts[1]); err != nil {
				return 0, "", fmt.Errorf("Format error : Cannot convert proxy-ssl-verify-depth to integer. We use the default value instead")
			}
			if proxySSLVerifyDepth <= 0 || proxySSLVerifyDepth > 10 {
				return 0, "", fmt.Errorf("Format error : proxy-ssl-verify-depth must be greater than 0 and must be equal or less than 10")
			}
		} else if parameterParts[0] == "proxy-ssl-name" {
			proxySSLName = parameterParts[1]
		} else {
			return 0, "", fmt.Errorf("Format error :Invalid optional parameter in the ingress.bluemix.net/ssl-services annotation. Found %v", parameterParts[0])
		}
	}
	return
}

// get add/remove headers in requests being sent to the upstream server and to responses being sent to the client
func getHeaders(ingEx *IngressEx, headerAnnotation string) map[string][]string {
	headers := make(map[string][]string)
	if headerSnippets, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, headerAnnotation, ingEx.Ingress, "\n"); exists {
		if err != nil {
			glog.Error(err)
		} else {
			headers = parseHeaders(headerSnippets, ingEx.Ingress.Name, headerAnnotation)
		}
	}

	return headers
}

func parseHeaders(headerSnippet []string, ingressName string, annotation string) map[string][]string {
	headers := make(map[string][]string)
	bracketIndex := GetIndexesOfValue(headerSnippet, "}", " ")
	startIndex := 0
	for _, endIndex := range bracketIndex {
		var serviceName string
		if strings.Contains(headerSnippet[startIndex], "serviceName") {
			serviceName = strings.Split(strings.Split(headerSnippet[startIndex], "=")[1], " ")[0]
		} else {
			glog.Errorf("In %v %v invalid serviceName format: ignoring", ingressName, annotation)
			break
		}

		for i := startIndex + 1; i < endIndex; i++ {
			if !strings.Contains(headerSnippet[i], ";") {
				glog.Errorf("In %v %v contains invalid header description format: %v ignoring", ingressName, annotation, headerSnippet[i])
				break
			}
			headers[serviceName] = append(headers[serviceName], strings.TrimLeft(headerSnippet[i], " "))
		}
		startIndex = endIndex + 1
	}

	return headers
}

// ParseLocationSnippetLine ...
func ParseLocationSnippetLine(snippet []string, ingressName string, annotation string, deliminator string) map[string][]string {
	headers := make(map[string][]string)
	bracketIndex := GetIndexesOfValue(snippet, deliminator, " ")
	//if bracketIndex has values that means there is an EOS deliminator
	if len(bracketIndex) != 0 {
		startIndex := 0
		for _, endIndex := range bracketIndex {
			var serviceName string
			if strings.Contains(snippet[startIndex], "serviceName") {
				serviceName = strings.Split(strings.Split(snippet[startIndex], "=")[1], " ")[0]
			} else {
				//want to generate for all
				serviceName = AllIngressServiceName
				startIndex = startIndex - 1
			}

			for i := startIndex + 1; i < endIndex; i++ {
				headers[serviceName] = append(headers[serviceName], snippet[i])
			}
			startIndex = endIndex + 1
		}
	} else {
		//no EOS deliminator so every location needs this section
		headers[AllIngressServiceName] = snippet
	}

	glog.Infof("in %v, the location snippets return the following map %v", ingressName, headers)
	return headers
}

func createLocation(path string,
	upstream Upstream,
	cfg *Config,
	websocket bool,
	rewrite string,
	ssl bool,
	proxySetHeaders []string,
	moreSetHeaders []string,
	moreClearHeaders []string,
	sslAuthentication bool,
	sslTwoWayAuthentication bool,
	proxySslTrustedCertificateFile string,
	proxySslCertificateFile string,
	proxySslCertificateKeyFile string,
	locationratelimitZones []RateLimitZone,
	proxySslVerifyDepth int,
	locationSnippet []string,
	watsonAuth bool,
	wtSecondaryHost string,
	wtSecondarySvc string,
	watsonOptions bool,
	wtBackend bool,
	iamAuth bool,
	iamAuthClientID string,
	iamAuthClientSecret string,
	iamAuthClientSecretNS string,
	iamAuthRedirect string,
	svcName string,
	proxyUpstreamValues string,
	proxyUpstreamTimeout string,
	proxyUpstreamTries int,
	plainSSLAuthentication bool,
	proxyConnectTimeout string,
	proxyReadTimeout string,
	clientMaxBodySize string,
	keepAliveTimeout string,
	keepAliveRequests string,
	iamAuthCli bool,
	customErrors []IngressNginxCustomError,
	proxyBufferSize string,
	proxyBuffers ProxyBuffer,
	proxyBusyBufferSize string,
	locProxyBuffering bool,
	locHostPort bool,
	statsdConfigEnabled bool,
	appIDSecret string,
	appIDSecretNamespace string,
	appIDRequestType string,
	appIDToken bool,
	locModifier string,
	iamLogout bool,
	proxySSLName string,
) Location {

	mapPath := ""
	if path != "/" && wtBackend {
		pathValue := strings.Split(path, "/")
		mapPath = pathValue[1]
	}
	loc := Location{
		Path:                       path,
		MapPath:                    mapPath,
		Upstream:                   upstream,
		ProxyConnectTimeout:        proxyConnectTimeout,
		ProxyReadTimeout:           proxyReadTimeout,
		ClientMaxBodySize:          clientMaxBodySize,
		Websocket:                  websocket,
		Rewrite:                    rewrite,
		SSL:                        ssl,
		ProxyBuffering:             locProxyBuffering,
		AddHostPort:                locHostPort,
		ProxyMaxTempFileSize:       cfg.ProxyMaxTempFileSize,
		LocationSnippets:           locationSnippet,
		AllLocationSnippet:         cfg.AllLocationSnippet,
		RatelimitMemory:            cfg.RatelimitMemory,
		RatelimitValue:             cfg.RatelimitValue,
		RatelimitBurst:             cfg.RatelimitBurst,
		ActivityTracker:            cfg.ActivityTracker,
		ProxySetHeaders:            proxySetHeaders,
		MoreSetHeaders:             moreSetHeaders,
		MoreClearHeaders:           moreClearHeaders,
		SSLAuthentication:          sslAuthentication,
		SSLTwoWayAuthentication:    sslTwoWayAuthentication,
		ProxySslTrustedCertificate: proxySslTrustedCertificateFile,
		ProxySslCertificate:        proxySslCertificateFile,
		ProxySslCertificateKey:     proxySslCertificateKeyFile,
		LocationRateLimitZones:     locationratelimitZones,
		ProxySslVerifyDepth:        proxySslVerifyDepth,
		WatsonAuthURL:              watsonAuth,
		WatsonSecondaryHost:        wtSecondaryHost,
		WatsonSecondarySvc:         wtSecondarySvc,
		WatsonUpstream:             wtBackend,
		Options:                    watsonOptions,
		IamAuthURL:                 iamAuth,
		ClientID:                   iamAuthClientID,
		ClientSecret:               iamAuthClientSecret,
		ClientSecretNS:             iamAuthClientSecretNS,
		ClientRedirectURL:          iamAuthRedirect,
		SvcName:                    svcName,
		ProxyNextUpstreamValues:    proxyUpstreamValues,
		ProxyNextUpstreamTimeout:   proxyUpstreamTimeout,
		ProxyNextUpstreamTries:     proxyUpstreamTries,
		PlainSSLAuthentication:     plainSSLAuthentication,
		KeepAliveTimeout:           keepAliveTimeout,
		KeepAliveRequests:          keepAliveRequests,
		IamCLIAuthURL:              iamAuthCli,
		CustomErrors:               customErrors,
		ProxyBufferSize:            proxyBufferSize,
		ProxyBuffers:               proxyBuffers,
		ProxyBusyBufferSize:        proxyBusyBufferSize,
		IstioEnabled:               cfg.IsIstioPresent,
		IstioPort:                  cfg.IstioPort,
		IstioIP:                    cfg.IstioIP,
		StatsdConfigEnabled:        statsdConfigEnabled,
		AppIDSecret:                appIDSecret,
		AppIDNameSpace:             appIDSecretNamespace,
		AppIDRequestType:           appIDRequestType,
		AppIDToken:                 appIDToken,
		LocationModifier:           locModifier,
		IamLogoutEnabled:           iamLogout,
		ProxySSLName:               proxySSLName,
	}

	return loc
}

func (cnf *Configurator) createUpstream(ingEx *IngressEx, name string, backend *networking.IngressBackend, namespace string, stickyCookie string, serviceName string) Upstream {
	ups := NewUpstreamWithDefaultServer(name, stickyCookie)

	endps, exists := ingEx.Endpoints[backend.ServiceName+backend.ServicePort.String()]
	if exists {
		var upsServers []UpstreamServer

		maxFailsAnnotation, maxFailsAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/upstream-max-fails", ingEx)
		failTimeoutAnnotation, failTimeoutAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/upstream-fail-timeout", ingEx)
		upstreamKeepAliveTimeoutAnnotation, upstreamKeepAliveTimeoutExists := cnf.GetAnnotationModel("ingress.bluemix.net/upstream-keepalive-timeout", ingEx)

		var maxFails string
		var failTimeout string
		var getErr error

		if maxFailsAnnotationExists {
			maxFails, getErr = handleUpstreamMaxFails(maxFailsAnnotation, serviceName)
			if getErr != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/upstream-max-fails", getErr),
				})
			}
		}

		if failTimeoutAnnotationExists {
			failTimeout, getErr = handleUpstreamFailTimeout(failTimeoutAnnotation, serviceName)
			if getErr != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/upstream-fail-timeout", getErr),
				})
			}
		}

		for _, endp := range endps {
			addressport := strings.Split(endp, ":")
			upsServers = append(upsServers, UpstreamServer{addressport[0], addressport[1], maxFails, failTimeout})
		}
		if len(upsServers) > 0 {
			ups.UpstreamServers = upsServers
		}
		upstreamKeepAliveAnnotation, upstreamKeepAliveExists := cnf.GetAnnotationModel("ingress.bluemix.net/upstream-keepalive", ingEx)
		if upstreamKeepAliveExists {
			upstreamKeepAlive, err := handleUpstreamKeepAlive(upstreamKeepAliveAnnotation)
			if err != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/upstream-keepalive", err),
				})
			}

			if upstreamKeepAlive, exists := upstreamKeepAlive[serviceName]; exists {
				ups.KeepAlive = upstreamKeepAlive
			}
		}
		upstreamLBAnnotation, upstreamLBAnnotationExists := cnf.GetAnnotationModel("ingress.bluemix.net/upstream-lb-type", ingEx)
		if upstreamLBAnnotationExists {
			upstreamLBType, err := handleUpstreamLBType(upstreamLBAnnotation, serviceName)
			if err != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/upstream-lb-type", err),
				})
			}

			if upstreamLBType, exists := upstreamLBType[serviceName]; exists {
				ups.LBType = upstreamLBType
			}
		}
		if upstreamKeepAliveTimeoutExists {
			upstreamKeepAliveTimeout, err := handleKeepAliveTimeout(upstreamKeepAliveTimeoutAnnotation)
			if err != nil {
				rm := internal.ResourceManager{
					Client: cnf.kubeClient}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/upstream-keepalive-timeout", err),
				})
			}

			if upstreamKeepAliveTimeout, exists := upstreamKeepAliveTimeout[serviceName]; exists {
				ups.KeepAliveTimeout = upstreamKeepAliveTimeout
			}
			if upstreamKeepAliveTimeoutAll, allExists := upstreamKeepAliveTimeout[""]; allExists {
				ups.KeepAliveTimeout = upstreamKeepAliveTimeoutAll
			}
		}
	}

	return ups
}

func pathOrDefault(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func getNameForUpstream(ing *networking.Ingress, host string, service string) string {
	return fmt.Sprintf("%v-%v-%v-%v", ing.Namespace, ing.Name, host, service)
}

func upstreamMapToSlice(upstreams map[string]Upstream) []Upstream {
	result := make([]Upstream, 0, len(upstreams))

	for _, ups := range upstreams {
		result = append(result, ups)
	}

	return result
}

// DeleteIngress deletes NGINX configuration for an Ingress resource
func (cnf *Configurator) DeleteIngress(name string) {
	cnf.lock.Lock()
	defer cnf.lock.Unlock()

	cnf.nginx.DeleteIngress(name)
	if err := cnf.nginx.Reload(); err != nil {
		glog.Errorf("Error when removing ingress %q: %q", name, err)
	}
}

// AddOrUpdateTLSSecret creates or updates a file with the content of the TLS secret
func (cnf *Configurator) AddOrUpdateTLSSecret(secret *api.Secret, ings []networking.Ingress, sslings []networking.Ingress, mutualAuthings []networking.Ingress, reload bool) error {
	cnf.addOrUpdateTLSSecret(secret, ings, sslings, mutualAuthings)

	if !reload {
		return nil
	}

	if err := cnf.nginx.Reload(); err != nil {
		return fmt.Errorf("Error when reloading NGINX when updating Secret: %v", err)
	}
	return nil
}

func (cnf *Configurator) addOrUpdateTLSSecret(secret *api.Secret, ings []networking.Ingress, sslings []networking.Ingress, mutualAuthings []networking.Ingress) {
	secretName := secret.Name
	ingLists := [][]networking.Ingress{ings, mutualAuthings}
	for _, ingList := range ingLists {
		for _, ing := range ingList {
			name := ing.Namespace + "-" + secretName + ".pem"
			glog.V(4).Infof("Secret formed name : %v for ingress %v \n", name, ing)
			data := generateCertAndKeyFileContent(secret)
			cnf.nginx.AddOrUpdatePemFile(name, data)
		}
	}
	for _, ing := range sslings {
		filetypes := []string{"trusted.crt", "client.crt", "client.key"}
		for _, filetype := range filetypes {
			name := ing.Namespace + "_" + ing.Name + "_" + secretName + "_" + filetype
			glog.V(4).Infof("Secret formed name : %v for ingress %v \n", name, ing)
			data := generateSSLCertAndKeyFileContent(secret, filetype)
			cnf.nginx.AddOrUpdatePemFile(name, data)
		}
	}
}

func generateCertAndKeyFileContent(secret *api.Secret) []byte {
	var res bytes.Buffer

	res.Write(secret.Data[api.TLSPrivateKeyKey])
	res.WriteString("\n")
	res.Write(secret.Data[api.TLSCertKey])
	res.WriteString("\n")
	res.Write(secret.Data["ca.crt"])

	return res.Bytes()
}

func generateSSLCertAndKeyFileContent(secret *api.Secret, filetype string) []byte {
	var res bytes.Buffer
	res.Write(secret.Data[filetype])

	return res.Bytes()
}

// DeleteSecret deletes secret
func (cnf *Configurator) DeleteSecret(secretName string, ings []networking.Ingress, sslings []networking.Ingress, mutualAuthings []networking.Ingress) error {
	cnf.lock.Lock()
	defer cnf.lock.Unlock()
	ingLists := [][]networking.Ingress{ings, mutualAuthings}
	for _, ingList := range ingLists {
		for _, ing := range ingList {
			name := cnf.nginx.nginxCertsPath + "/" + ing.Namespace + "-" + secretName
			glog.V(3).Infof("Secret formed name : %v for ingress %v \n", name, ing)
			cnf.nginx.DeletePemFile(name + ".pem")
			//name = ing.Namespace + "-" + ing.Name
			//cnf.nginx.DeleteIngress(name)
		}
	}

	for _, ing := range sslings {
		paths := []string{cnf.nginx.nginxCertsPath, ""}
		for _, path := range paths {
			name := path + "/" + ing.Namespace + "_" + ing.Name + "_" + secretName
			glog.V(3).Infof("Secret formed name : %v for ingress %v \n", name, ing)
			cnf.nginx.DeletePemFile(name + "_trusted.crt")
			cnf.nginx.DeletePemFile(name + "_client.crt")
			cnf.nginx.DeletePemFile(name + "_client.key")
		}
	}

	return nil
}

// UpdateEndpoints updates endpoints in NGINX configuration for an Ingress resource
func (cnf *Configurator) UpdateEndpoints(name string, ingEx *IngressEx) {
	cnf.AddOrUpdateIngress(name, ingEx)
}

// UpdateConfig updates NGINX Configuration parameters
func (cnf *Configurator) UpdateConfig(config *Config) {
	cnf.lock.Lock()
	defer cnf.lock.Unlock()

	var snortEnabled = false

	ingressRole := os.Getenv("ingress_controller_role")
	if ingressRole == FrontendRole {
		snortEnabled = true
		glog.Infof("Snort Enabled: Number of snort instances: %d ", len(SnortUpstreamServers.UpstreamServers))
	}

	cnf.config = config
	mainCfg := &IngressNginxMainConfig{
		HTTPSnippets:              config.MainHTTPSnippets,
		ServerNamesHashBucketSize: config.MainServerNamesHashBucketSize,
		ServerNamesHashMaxSize:    config.MainServerNamesHashMaxSize,
		VtsStatusZoneSize:         config.VtsStatusZoneSize,
		LogFormat:                 config.MainLogFormat,
		LogFormatEscapeJSON:       config.MainLogFormatEscapeJSON,
		SSLProtocols:              config.MainServerSSLProtocols,
		SSLCiphers:                config.MainServerSSLCiphers,
		SSLDHParam:                config.MainServerSSLDHParam,
		SSLPreferServerCiphers:    config.MainServerSSLPreferServerCiphers,
		ActivityTracker:           config.ActivityTracker,
		SnortEnabled:              snortEnabled,
		SnortUpstream:             SnortUpstreamServers,
		InKeepAlive:               config.InKeepAlive,
		AccessLogEnabled:          config.AccessLogEnabled,
		AccessLogBuffer:           config.AccessLogBuffer,
		AccessLogFlush:            config.AccessLogFlush,
		InKeepaliveRequests:       config.InKeepaliveRequests,
		Backlog:                   config.Backlog,
		ReusePort:                 config.ReusePort,
		IsDefaultServerConf:       IsDefaultServerConfGlobal,
	}

	cnf.nginx.UpdateMainConfigFile(mainCfg)
	cnf.nginx.UpdateDefaultConfFile(mainCfg)
}

func getExtSvcs(ingEx *IngressEx) []externalsvc {
	var extsvcs []externalsvc

	if services, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/proxy-external-service"]; exists {
		for _, service := range strings.Split(services, ";") {
			isssl := false
			if hostval, pathval, extSvcval, err := parseExtSvcs(service); err != nil {
				glog.Errorf("In %v ingress.bluemix.net/proxy-external-service contains invalid declaration: %v, ignoring", ingEx.Ingress.Name, err)
			} else {
				if _, ok := ingEx.UpstreamSSLData[extSvcval]; ok {
					isssl = true
				}
				extloc := externalsvc{path: pathval, host: hostval, svc: extSvcval, isssl: isssl}
				extsvcs = append(extsvcs, extloc)
			}
		}
	}
	return extsvcs
}

func parseExtSvcs(service string) (host string, path string, extSvc string, err error) {
	parts := strings.SplitN(service, " ", 3)

	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid external service format: %s", service)
	}

	pathParts := strings.Split(parts[0], "=")
	if len(pathParts) != 2 {
		return "", "", "", fmt.Errorf("invalid external service format: %s", pathParts)
	}

	extSvcParts := strings.Split(parts[1], "=")
	if len(extSvcParts) != 2 {
		return "", "", "", fmt.Errorf("invalid external service format: %s", extSvcParts)
	}

	hostParts := strings.Split(parts[2], "=")
	if len(hostParts) != 2 {
		return "", "", "", fmt.Errorf("invalid external service format: %s", hostParts)
	}

	return hostParts[1], pathParts[1], extSvcParts[1], nil
}

func createExtSvcLocation(path string,
	cfg *Config,
	extSvc string,
	sslAuthentication bool,
	sslTwoWayAuthentication bool,
	proxySslTrustedCertificateFile string,
	proxySslCertificateFile string,
	proxySslCertificateKeyFile string,
	proxySslVerifyDepth int,
	locationRateLimitZones []RateLimitZone,
	locationSnippet []string,
	proxyUpstreamValues string,
	proxyUpstreamTimeout string,
	proxyUpstreamTries int,
	plainSSLAuthentication bool,
	proxyConnectTimeout string,
	proxyReadTimeout string,
	clientMaxBodySize string,
	customErrors []IngressNginxCustomError,
	proxyBufferSize string,
	proxyBuffers ProxyBuffer,
	proxyBusyBufferSize string,
	extDNSResolver string,
	locProxyBuffering bool,
	locModifier string,
	proxySSLName string,
) Location {
	loc := Location{
		Path:                       path,
		ProxyConnectTimeout:        proxyConnectTimeout,
		ProxyReadTimeout:           proxyReadTimeout,
		ClientMaxBodySize:          clientMaxBodySize,
		ProxyBuffering:             locProxyBuffering,
		ProxyMaxTempFileSize:       cfg.ProxyMaxTempFileSize,
		LocationSnippets:           locationSnippet,
		AllLocationSnippet:         cfg.AllLocationSnippet,
		RatelimitMemory:            cfg.RatelimitMemory,
		RatelimitValue:             cfg.RatelimitValue,
		RatelimitBurst:             cfg.RatelimitBurst,
		ActivityTracker:            cfg.ActivityTracker,
		ExternalSvc:                extSvc,
		ExternalLocation:           true,
		ExtDNSResolver:             extDNSResolver,
		SSLAuthentication:          sslAuthentication,
		SSLTwoWayAuthentication:    sslTwoWayAuthentication,
		ProxySslTrustedCertificate: proxySslTrustedCertificateFile,
		ProxySslCertificate:        proxySslCertificateFile,
		ProxySslCertificateKey:     proxySslCertificateKeyFile,
		LocationRateLimitZones:     locationRateLimitZones,
		ProxySslVerifyDepth:        proxySslVerifyDepth,
		ProxyNextUpstreamValues:    proxyUpstreamValues,
		ProxyNextUpstreamTimeout:   proxyUpstreamTimeout,
		ProxyNextUpstreamTries:     proxyUpstreamTries,
		PlainSSLAuthentication:     plainSSLAuthentication,
		CustomErrors:               customErrors,
		ProxyBufferSize:            proxyBufferSize,
		ProxyBuffers:               proxyBuffers,
		ProxyBusyBufferSize:        proxyBusyBufferSize,
		LocationModifier:           locModifier,
		ProxySSLName:               proxySSLName,
	}
	return loc
}

func getWatsonAuthURL(ingEx *IngressEx) string {
	authURL := ""

	if authURLString, exists := ingEx.Ingress.Annotations["watson.ingress.bluemix.net/watson-auth-url"]; exists {
		annotationModel, err := parser.ParseInputForAnnotation("watson.ingress.bluemix.net/watson-auth-url", authURLString)
		if err != nil {
			glog.Errorf("In watson.ingress.bluemix.net/watson-auth-url (%v) contains invalid declaration.  err = %v, ", authURLString, err)
			return authURL
		}

		for _, entry := range annotationModel.Entries {
			urlValue, authURLExists := entry.GetAsString("authURL")
			if authURLExists {
				authURL = urlValue
			}
		}
	}

	return authURL
}

func getWatsonAuth(ingEx *IngressEx, cnf *Configurator) (map[string]bool, map[string]string, map[string]string, map[string]bool, bool) {
	annotationPresent := false
	var upstreamSvc, authServices map[string]bool
	var backendIngressHost, backendIngressSvc map[string]string

	watsonPreAuthAnnotation, watsonPreAuthAnnotationExists := cnf.GetAnnotationModel("watson.ingress.bluemix.net/watson-pre-auth", ingEx)
	if watsonPreAuthAnnotationExists {
		authFrontend, backendIngressHostValue, backendIngressSvcValue, err := handleWatsonPreAuth(watsonPreAuthAnnotation)
		if err != nil {
			rm := internal.ResourceManager{
				Client: cnf.kubeClient}
			rm.GenerateKubeEvent(internal.EventError{
				MsgCode:      "A0001",
				Ing:          ingEx.Ingress,
				OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "watson.ingress.bluemix.net/watson-pre-auth", err),
			})
		} else {
			authServices = authFrontend
			backendIngressHost = backendIngressHostValue
			backendIngressSvc = backendIngressSvcValue
		}
	}

	watsonPostAuthAnnotation, watsonPostAuthAnnotationExists := cnf.GetAnnotationModel("watson.ingress.bluemix.net/watson-post-auth", ingEx)
	if watsonPostAuthAnnotationExists {
		upstream, err := handleWatsonPostAuth(watsonPostAuthAnnotation)
		if err != nil {
			rm := internal.ResourceManager{
				Client: cnf.kubeClient}
			rm.GenerateKubeEvent(internal.EventError{
				MsgCode:      "A0001",
				Ing:          ingEx.Ingress,
				OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "watson.ingress.bluemix.net/watson-post-auth", err),
			})
		} else {
			annotationPresent = true
			upstreamSvc = upstream
		}
	}

	return authServices, backendIngressHost, backendIngressSvc, upstreamSvc, annotationPresent
}

func getUIIAM(ingEx *IngressEx) (map[string]bool, map[string]string, map[string]string, map[string]string, map[string]string, bool, bool) {
	//map indicating if the svc will use clearharbor/generic iam
	var authServices map[string]bool
	//map indicating the svc's clientID
	var authClientID map[string]string
	//map indicating the svc's clientSecret
	var authClientSecret map[string]string
	//map indicating the svc's clientSecretNamespace
	var authClientSecretNS map[string]string
	//map indicating the svc's redirectURL
	var authRedirectURL map[string]string
	authIAMPresent := false
	enableAllLocations := false

	if iamAnnotationsString, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/iam-ui-auth"]; exists {
		parsedServices, parsedClientID, parsedClientSecret, parsedClientSecretNS, parsedRedirectURL, enableAll, err := parseIamUIService(iamAnnotationsString)
		if err != nil {
			glog.Errorf("error in parseIamUIService parsing and validation")
			return authServices, authClientID, authClientSecret, authClientSecretNS, authRedirectURL, authIAMPresent, enableAllLocations
		}
		authIAMPresent = true
		authServices = parsedServices
		authClientID = parsedClientID
		authClientSecret = parsedClientSecret
		authClientSecretNS = parsedClientSecretNS
		authRedirectURL = parsedRedirectURL
		enableAllLocations = enableAll
	}
	return authServices, authClientID, authClientSecret, authClientSecretNS, authRedirectURL, authIAMPresent, enableAllLocations
}

func parseIamUIService(iamAnnotationsString string) (services map[string]bool, clientID map[string]string, clientSecret map[string]string, clientSecretNameSpace map[string]string, RedirectURL map[string]string, enableMulti bool, err error) {
	//map indicating if the svc will use clearharbor/generic iam
	authServices := make(map[string]bool)
	//map indicating the svc's clientID
	authClientID := make(map[string]string)
	//map indicating the svc's clientSecret
	authClientSecret := make(map[string]string)
	//map indicating the svc's clientSecretNamespace
	authClientSecretNS := make(map[string]string)
	//map indicating the svc's redirectURL
	authRedirectURL := make(map[string]string)

	enableAll := false

	annotationModel, err := parser.ParseInputForAnnotation("ingress.bluemix.net/iam-ui-auth", iamAnnotationsString)
	if err != nil {
		glog.Errorf("In ingress.bluemix.net/iam-ui-auth (%v) contains invalid declaration.  err = %v, ", iamAnnotationsString, err)
		return authServices, authClientID, authClientSecret, authClientSecretNS, authRedirectURL, enableAll, err
	}
	for _, entry := range annotationModel.Entries {
		entryName := "none"
		if entry.Exists("serviceName") {
			svcName, svcExists := entry.GetAsString("serviceName")
			if svcExists {
				authServices[svcName] = true
				entryName = svcName

			}
		} else {
			enableAll = true
			entryName = AllIngressServiceName
		}

		authClientIDValue, authClientIDExists := entry.GetAsString("clientId")
		if authClientIDExists {
			authClientID[entryName] = authClientIDValue
		}
		authClientSecretValue, authClientSecretExists := entry.GetAsString("clientSecret")
		if authClientSecretExists {
			authClientSecret[entryName] = authClientSecretValue
		}
		authClientSecretNSValue, authClientSecretNSExists := entry.GetAsString("clientSecretNamespace")
		if authClientSecretNSExists {
			authClientSecretNS[entryName] = authClientSecretNSValue
		}
		authRedirectURLValue, authRedirectURLExists := entry.GetAsString("redirectURL")
		if authRedirectURLExists {
			authRedirectURL[entryName] = authRedirectURLValue
		}
	}

	return authServices, authClientID, authClientSecret, authClientSecretNS, authRedirectURL, enableAll, nil
}

func getProxyNextUpstream(ingEx *IngressEx) (map[string]string, map[string]string, map[string]int) {
	var err error
	var proxyUpstreamValues map[string]string
	var proxyUpstreamTimeout map[string]string
	var proxyUpstreamTries map[string]int

	if proxyUpstreamString, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/proxy-next-upstream-config"]; exists {
		proxyUpstreamValues, proxyUpstreamTimeout, proxyUpstreamTries, err = parseProxyNextUpstream(proxyUpstreamString)
		if err != nil {
			glog.Errorf("error in parseProxyNextUpstream parsing and validation")
		}
	}
	glog.V(4).Infof("getProxyNextUpstream: proxyUpstreamValues=%v, proxyUpstreamTimeout=%v, proxyUpstreamTries=%v",
		proxyUpstreamValues, proxyUpstreamTimeout, proxyUpstreamTries)
	return proxyUpstreamValues, proxyUpstreamTimeout, proxyUpstreamTries
}

func parseProxyNextUpstream(annotationStringFromIng string) (map[string]string, map[string]string, map[string]int, error) {

	proxyUpstreamValues := make(map[string]string)
	proxyUpstreamTimeout := make(map[string]string)
	proxyUpstreamTries := make(map[string]int)

	annotationModel, err := parser.ParseInputForAnnotation("ingress.bluemix.net/proxy-next-upstream-config", annotationStringFromIng)
	if err != nil {
		glog.Errorf("In ingress.bluemix.net/proxy-next-upstream-config (%v) contains invalid declaration.  err = %v, ", annotationStringFromIng, err)
		return proxyUpstreamValues, proxyUpstreamTimeout, proxyUpstreamTries, err
	}

	for _, entry := range annotationModel.Entries {

		values := "timeout"
		svcName, svcExists := entry.GetAsString("serviceName")
		if svcExists {
			//create the value structure
			if entry.Exists("error") {
				errValue, errExists := entry.GetAsBool("error")
				if errExists {
					if errValue {
						values = values + " error"
					}
				}
			}
			if entry.Exists("invalid_header") {
				invalidHdrValue, invalidHdrExists := entry.GetAsBool("invalid_header")
				if invalidHdrExists {
					if invalidHdrValue {
						values = values + " invalid_header"
					}
				}
			}
			if entry.Exists("non_idempotent") {
				nonIdempotentValue, nonIdempotentExists := entry.GetAsBool("non_idempotent")
				if nonIdempotentExists {
					if nonIdempotentValue {
						values = values + " non_idempotent"
					}
				}
			}
			if entry.Exists("off") {
				offValue, offExists := entry.GetAsBool("off")
				if offExists {
					if offValue {
						values = values + " off"
					}
				}
			}
			if entry.Exists("http_500") {
				http500Value, http500Exists := entry.GetAsBool("http_500")
				if http500Exists {
					if http500Value {
						values = values + " http_500"
					}
				}
			}
			if entry.Exists("http_502") {
				http502Value, http502Exists := entry.GetAsBool("http_502")
				if http502Exists {
					if http502Value {
						values = values + " http_502"
					}
				}
			}
			if entry.Exists("http_503") {
				http503Value, http503Exists := entry.GetAsBool("http_503")
				if http503Exists {
					if http503Value {
						values = values + " http_503"
					}
				}
			}
			if entry.Exists("http_504") {
				http504Value, http504Exists := entry.GetAsBool("http_504")
				if http504Exists {
					if http504Value {
						values = values + " http_504"
					}
				}
			}
			if entry.Exists("http_403") {
				http403Value, http403Exists := entry.GetAsBool("http_403")
				if http403Exists {
					if http403Value {
						values = values + " http_403"
					}
				}
			}
			if entry.Exists("http_404") {
				http404Value, http404Exists := entry.GetAsBool("http_404")
				if http404Exists {
					if http404Value {
						values = values + " http_404"
					}
				}
			}
			if entry.Exists("http_429") {
				http429Value, http429Exists := entry.GetAsBool("http_429")
				if http429Exists {
					if http429Value {
						values = values + " http_429"
					}
				}
			}
			if entry.Exists("timeout") {
				upstreamTimeoutValue, upstreamTimeoutExists := entry.GetAsValueUnitString("timeout")
				if upstreamTimeoutExists {
					proxyUpstreamTimeout[svcName] = upstreamTimeoutValue
				}
			}
			if entry.Exists("retries") {
				upstreamTriesValue, upstreamTriesExists := entry.GetAsInt("retries")
				if upstreamTriesExists {
					proxyUpstreamTries[svcName] = upstreamTriesValue
				}

			}
			proxyUpstreamValues[svcName] = strings.TrimSpace(values)
		}
	}

	glog.V(4).Infof("parseProxyNextUpstream: proxyUpstreamValues=%v, proxyUpstreamTimeout=%v, proxyUpstreamTries=%v",
		proxyUpstreamValues, proxyUpstreamTimeout, proxyUpstreamTries)
	return proxyUpstreamValues, proxyUpstreamTimeout, proxyUpstreamTries, nil
}

func getCLIIAM(ingEx *IngressEx) (map[string]bool, bool, bool) {
	//map indicating if the svc will use validate tokens using iam
	var authServices map[string]bool
	enableAllLoc := false
	iamExists := false

	if iamAnnotationsString, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/iam-cli-auth"]; exists {
		parsedServices, enableAll, err := parseIamCLIService(iamAnnotationsString)
		if err != nil {
			glog.Errorf("error in parseIamCLIService parsing and validation")
			return authServices, enableAllLoc, iamExists
		}
		authServices = parsedServices
		iamExists = true
		enableAllLoc = enableAll
	}
	return authServices, enableAllLoc, iamExists
}

func getCarrierLocationEnable(ingEx *IngressEx) bool {

	if statsdAnnotationsString, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/carrier-statsd-config"]; exists {
		glog.Infof("statsdAnnotationsString:%s", statsdAnnotationsString)
		enabled, err := ParseStatsdService(statsdAnnotationsString)
		if err != nil {
			glog.Errorf("error in ParseStatsdService parsing and validation")
			return false
		}
		return enabled
	}
	return false
}

// ParseStatsdService ...
func ParseStatsdService(statsdAnnotationsString string) (enableAllLoc bool, err error) {
	//map indicating if the svc will use clearharbor/generic iam
	var enableAll bool

	annotationModel, err := parser.ParseInputForAnnotation("ingress.bluemix.net/carrier-statsd-config", statsdAnnotationsString)
	if err != nil {
		glog.Errorf("In ingress.bluemix.net/carrier-statsd-config (%v) contains invalid declaration.  err = %v, ", statsdAnnotationsString, err)
		return enableAll, err
	}

	for _, entry := range annotationModel.Entries {
		isEnabled, enabledExists := entry.GetAsBool("enabled")
		if enabledExists {
			if isEnabled {
				enableAll = true
			}
		} else {
			//an error has occurred because the enabled flag is required
			//The ParseInputForAnnotations should have failed with an error
			//and should not have come to this else statement
			return enableAll, fmt.Errorf("invalid ingress.bluemix.net/carrier-statsd-config format: %s", statsdAnnotationsString)
		}
	}

	return enableAll, nil
}

func parseIamCLIService(iamAnnotationsString string) (services map[string]bool, enableAllLoc bool, err error) {
	//map indicating if the svc will use clearharbor/generic iam
	authServices := make(map[string]bool)
	enableAll := false

	annotationModel, err := parser.ParseInputForAnnotation("ingress.bluemix.net/iam-cli-auth", iamAnnotationsString)
	if err != nil {
		glog.Errorf("In ingress.bluemix.net/iam-ui-auth (%v) contains invalid declaration.  err = %v, ", iamAnnotationsString, err)
		return authServices, enableAll, err
	}

	for _, entry := range annotationModel.Entries {
		isEnabled, enabledExists := entry.GetAsBool("enabled")
		if enabledExists {
			if isEnabled {
				if entry.Exists("serviceName") {
					svcName, svcExists := entry.GetAsString("serviceName")
					if svcExists {
						authServices[svcName] = true
					}
				} else {
					//no serviceName but the enabled flag was set so all locations
					//need to do token validation with IAM
					enableAll = true
				}
			}
		} else {
			//an error has occurred because the enabled flag is required
			//The ParseInputForAnnotations should have failed with an error
			//and should not have come to this else statement
			return authServices, enableAll, fmt.Errorf("invalid iam-cli-auth format: %s", iamAnnotationsString)
		}
	}

	return authServices, enableAll, nil
}

func (cnf *Configurator) createIstioIngressUpstream(ingEx *IngressEx, host string) []Upstream {

	// TODO: Refactor lots of duplicated code

	var upstreamArray []Upstream

	if len(ingEx.IstioIngressUpstreams) > 0 {

		for _, elem := range ingEx.IstioIngressUpstreams {

			var upstreamInstance Upstream
			var upsServers []UpstreamServer

			upstreamInstance.Name = getNameForUpstream(ingEx.Ingress, host, elem.BackendSvc)

			for _, endp := range elem.Endpoints {
				addressPortSplitArray := strings.Split(endp, ":")
				upsServers = append(upsServers, UpstreamServer{addressPortSplitArray[0], addressPortSplitArray[1], "1", "10s"})
			}

			upstreamInstance.UpstreamServers = upsServers

			upstreamKeepAliveAnnotation, upstreamKeepAliveExists := cnf.GetAnnotationModel("ingress.bluemix.net/upstream-keepalive", ingEx)

			if upstreamKeepAliveExists {
				upstreamKeepAlive, err := handleUpstreamKeepAlive(upstreamKeepAliveAnnotation)
				if err != nil {
					rm := internal.ResourceManager{
						Client: cnf.kubeClient}
					rm.GenerateKubeEvent(internal.EventError{
						MsgCode:      "A0001",
						Ing:          ingEx.Ingress,
						OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. %v", "ingress.bluemix.net/upstream-keepalive", err),
					})
				}

				if upstreamKeepAlive, exists := upstreamKeepAlive[elem.BackendSvc]; exists {
					upstreamInstance.KeepAlive = upstreamKeepAlive
				}
			}
			upstreamInstance.KeepAlive = 64
			upstreamArray = append(upstreamArray, upstreamInstance)
		}

	}

	return upstreamArray

}
