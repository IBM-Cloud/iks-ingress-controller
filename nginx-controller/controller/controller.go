/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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

package controller

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"

	"github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/internal"
	"github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/nginx"
	"github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser"

	api "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	networking "k8s.io/api/networking/v1beta1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	ingressClassKey     = "kubernetes.io/ingress.class"
	ingressTypeKey      = "ingress.bluemix.net/ALB-ID"
	nginxIngressClass   = "nginx"
	ingressSvcNameSpace = "kube-system"
	namespaceDelimiter  = "-k8ns-"
	defaultNameSpace    = "default"
	tlsSecretError      = "TLSCertError"
	sslSecretError      = "SSLCertError"
	maSecretError       = "MACertError"
	allError            = "AllCertError"
	iksIngressClass     = "iks-nginx"
)

// LoadBalancerController watches Kubernetes API and
// reconfigures NGINX via NginxController when needed
type LoadBalancerController struct {
	client                    kubernetes.Interface
	ingController             cache.Controller
	svcController             cache.Controller
	endpController            cache.Controller
	cfgmController            cache.Controller
	podController             cache.Controller
	secretController          cache.Controller
	ingLister                 StoreToIngressLister
	svcLister                 StoreToServiceLister
	endpLister                StoreToEndpointLister
	cfgmLister                StoreToConfigMapLister
	podLister                 StoreToPodLister
	secretLister              StoreToSecretLister
	ingQueue                  *taskQueue
	endpQueue                 *taskQueue
	cfgmQueue                 *taskQueue
	secretQueue               *taskQueue
	stopCh                    chan struct{}
	cnf                       *nginx.Configurator
	watchNginxConfigMaps      bool
	currentNginxConfigMapData map[string]string
	updatedNginxConfigMapData map[string]string
	listOfResources           []internal.IngressResource // this list is used to reset status for ingress resources
	inShutdownMode            bool                       // flag to indicate lbc controller in shut down mode
	statusSyncQueue           *taskQueue
}

var keyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc

// NewLoadBalancerController creates a controller
func NewLoadBalancerController(kubeClient kubernetes.Interface, resyncPeriod time.Duration, namespace string, cnf *nginx.Configurator, nginxConfigMaps string) (*LoadBalancerController, error) {
	lbc := LoadBalancerController{
		client: kubeClient,
		stopCh: make(chan struct{}),
		cnf:    cnf,
	}

	lbc.ingQueue = newTaskQueue(lbc.syncIng)
	lbc.endpQueue = newTaskQueue(lbc.syncEndp)

	ingHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addIng, _ := toIngress(obj)

			// don't sync ingress resources if in shutdown mode
			if lbc.inShutdownMode {
				glog.V(4).Infof("Ignoring Ingress %v. ALB in shutdown mode", addIng.Name)
				return
			}
			if !isNginxIngress(addIng) {
				glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", addIng.Name, ingressClassKey)
				//rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
				//rm.RemoveStatusAddress(addIng)
				return
			}
			if !isALBIDMatching(addIng) {
				glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", addIng.Name, ingressTypeKey)
				//rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
				//rm.RemoveStatusAddress(addIng)
				return
			}
			glog.V(3).Infof("Adding Ingress: %v", addIng.Name)
			lbc.ingQueue.enqueue(obj)

			rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
			rm.UpdateIngressStatus(addIng)
		},
		DeleteFunc: func(obj interface{}) {
			remIng, isIng := toIngress(obj)
			glog.V(3).Infof("Removing Ingress: %v", remIng.Name)

			if !isIng {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					glog.V(4).Infof("Error received unexpected object: %v", obj)
					return
				}
				remIng, ok = deletedState.Obj.(*networking.Ingress)
				if !ok {
					glog.V(4).Infof("Error DeletedFinalStateUnknown contained non-Ingress object: %v", deletedState.Obj)
					return
				}
			}
			if !isNginxIngress(remIng) {
				glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", remIng.Name, ingressClassKey)
				//rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
				//rm.RemoveStatusAddress(remIng)
				return
			}
			if !isALBIDMatching(remIng) {
				glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", remIng.Name, ingressTypeKey)
				//rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
				//rm.RemoveStatusAddress(remIng)
				return
			}

			ingEx := &nginx.IngressEx{
				Ingress: remIng,
			}
			lbc.resetFirstErrorFlags(remIng, allError)
			lbc.preparePemFileNames(ingEx)
			lbc.ingQueue.enqueue(obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			oldIng, _ := toIngress(old)
			curIng, _ := toIngress(cur)
			// don't sync ingress resources if in shutdown mode
			if lbc.inShutdownMode {
				glog.V(4).Infof("Ignoring Ingress %v. ALB in shutdown mode", curIng.Name)
				return
			}
			if !isNginxIngress(curIng) {
				glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", curIng.Name, ingressClassKey)
				//rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
				//rm.RemoveStatusAddress(curIng)
				return
			}
			if !isALBIDMatching(curIng) {
				glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", curIng.Name, ingressTypeKey)
				//rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
				//rm.RemoveStatusAddress(curIng)
				return
			}

			if lbc.inShutdownMode {
				return
			}
			if !reflect.DeepEqual(old, cur) {
				glog.V(3).Infof("Ingress %v changed, syncing", curIng.Name)
				ingEx := &nginx.IngressEx{
					Ingress: oldIng,
				}
				glog.V(4).Infof("cur Ingress %v ", cur)
				glog.V(4).Infof("old Ingress %v ", old)
				lbc.preparePemFileNames(ingEx)
				lbc.ingQueue.enqueue(cur)

				rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
				rm.UpdateIngressStatus(curIng)
			}
		},
	}

	if internal.IsNetworkingIngressAvailable {
		lbc.ingLister.Store, lbc.ingController = cache.NewInformer(
			cache.NewListWatchFromClient(lbc.client.NetworkingV1beta1().RESTClient(), "ingresses", namespace, fields.Everything()),
			&networking.Ingress{}, resyncPeriod, ingHandlers)
	} else {
		lbc.ingLister.Store, lbc.ingController = cache.NewInformer(
			cache.NewListWatchFromClient(lbc.client.ExtensionsV1beta1().RESTClient(), "ingresses", namespace, fields.Everything()),
			&extensions.Ingress{}, resyncPeriod, ingHandlers)
	}

	svcHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addSvc := obj.(*api.Service)
			glog.V(4).Infof("Adding service: %v", addSvc.Name)
			lbc.enqueueIngressForService(addSvc)
		},
		DeleteFunc: func(obj interface{}) {
			remSvc, isSvc := obj.(*api.Service)
			if !isSvc {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					glog.V(3).Infof("Error received unexpected object: %v", obj)
					return
				}
				remSvc, ok = deletedState.Obj.(*api.Service)
				if !ok {
					glog.V(3).Infof("Error DeletedFinalStateUnknown contained non-Service object: %v", deletedState.Obj)
					return
				}
			}
			glog.V(3).Infof("Removing service: %v", remSvc.Name)
			lbc.enqueueIngressForService(remSvc)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				glog.V(3).Infof("Service %v changed, syncing",
					cur.(*api.Service).Name)
				lbc.enqueueIngressForService(cur.(*api.Service))
			}
		},
	}
	lbc.svcLister.Store, lbc.svcController = cache.NewInformer(
		cache.NewListWatchFromClient(lbc.client.CoreV1().RESTClient(), "services", namespace, fields.Everything()),
		&api.Service{}, resyncPeriod, svcHandlers)

	endpHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addEndp := obj.(*api.Endpoints)
			glog.V(4).Infof("Adding endpoints: %v", addEndp.Name)
			lbc.endpQueue.enqueue(obj)
		},
		DeleteFunc: func(obj interface{}) {
			remEndp, isEndp := obj.(*api.Endpoints)
			if !isEndp {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					glog.V(3).Infof("Error received unexpected object: %v", obj)
					return
				}
				remEndp, ok = deletedState.Obj.(*api.Endpoints)
				if !ok {
					glog.V(3).Infof("Error DeletedFinalStateUnknown contained non-Endpoints object: %v", deletedState.Obj)
					return
				}
			}
			glog.V(3).Infof("Removing endpoints: %v", remEndp.Name)
			lbc.endpQueue.enqueue(obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			if len(cur.(*api.Endpoints).Subsets) != 0 {
				if !reflect.DeepEqual(old, cur) {
					glog.V(3).Infof("Endpoints %v changed, syncing",
						cur.(*api.Endpoints).Name)
					lbc.endpQueue.enqueue(cur)
				}
			}
		},
	}
	lbc.endpLister.Store, lbc.endpController = cache.NewInformer(
		cache.NewListWatchFromClient(lbc.client.CoreV1().RESTClient(), "endpoints", namespace, fields.Everything()),
		&api.Endpoints{}, resyncPeriod, endpHandlers)

	if nginxConfigMaps != "" {
		nginxConfigMapsNS, nginxConfigMapsName, err := parseNamespaceAndEntityname(nginxConfigMaps)
		if err != nil {
			glog.Warning(err)
		} else {
			lbc.watchNginxConfigMaps = true
			lbc.cfgmQueue = newTaskQueue(lbc.syncCfgm)

			cfgmHandlers := cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					cfgm := obj.(*api.ConfigMap)
					if cfgm.Name == nginxConfigMapsName {
						glog.V(3).Infof("Adding ConfigMap: %v", cfgm.Name)
						// Update admin ingress resources
						lbc.updateIngressResources(cfgm.Data, "AddFunc")
						lbc.updateLoadBalancerServicePorts(cfgm.Data, false)
						lbc.cfgmQueue.enqueue(obj)
					}
				},
				DeleteFunc: func(obj interface{}) {
					cfgm, isCfgm := obj.(*api.ConfigMap)
					if !isCfgm {
						deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
						if !ok {
							glog.V(3).Infof("Error received unexpected object: %v", obj)
							return
						}
						cfgm, ok = deletedState.Obj.(*api.ConfigMap)
						if !ok {
							glog.V(3).Infof("Error DeletedFinalStateUnknown contained non-ConfigMap object: %v", deletedState.Obj)
							return
						}
					}
					if cfgm.Name == nginxConfigMapsName {
						glog.V(3).Infof("Removing ConfigMap: %v", cfgm.Name)
						// Update admin ingress resources
						lbc.updateIngressResources(cfgm.Data, "DeleteFunc")
						lbc.updateLoadBalancerServicePorts(cfgm.Data, true)
						lbc.cfgmQueue.enqueue(obj)
					}
				},
				UpdateFunc: func(old, cur interface{}) {
					if !reflect.DeepEqual(old, cur) {
						cfgm := cur.(*api.ConfigMap)
						if cfgm.Name == nginxConfigMapsName {
							glog.V(3).Infof("ConfigMap %v changed, syncing",
								cur.(*api.ConfigMap).Name)
							// Update admin ingress resources
							lbc.updateIngressResources(cfgm.Data, "UpdateFunc")
							lbc.updateLoadBalancerServicePorts(cfgm.Data, false)
							lbc.cfgmQueue.enqueue(cur)
						}
					}
				},
			}
			lbc.cfgmLister.Store, lbc.cfgmController = cache.NewInformer(
				cache.NewListWatchFromClient(lbc.client.CoreV1().RESTClient(), "configmaps", nginxConfigMapsNS, fields.Everything()),
				&api.ConfigMap{}, resyncPeriod, cfgmHandlers)
		}
	}

	podHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if lbc.handleIngressPodScaleChanges() {
				lbc.rewriteRateLimitedIngresses()
			}
		},
		DeleteFunc: func(obj interface{}) {
			if lbc.handleIngressPodScaleChanges() {
				lbc.rewriteRateLimitedIngresses()
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				if lbc.handleIngressPodScaleChanges() {
					lbc.rewriteRateLimitedIngresses()
				}
			}
		},
	}
	lbc.podLister.Store, lbc.podController = cache.NewInformer(
		cache.NewListWatchFromClient(lbc.client.CoreV1().RESTClient(), "pods", namespace, fields.Everything()),
		&api.Pod{}, resyncPeriod, podHandlers)

	lbc.secretQueue = newTaskQueue(lbc.syncSecret)
	secretHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addSecret := obj.(*api.Secret)
			glog.V(4).Infof("Adding secret: %v", addSecret.Name)
			lbc.secretQueue.enqueue(obj)
		},
		DeleteFunc: func(obj interface{}) {
			remSecret, isSecret := obj.(*api.Secret)
			if !isSecret {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					glog.V(3).Infof("Error received unexpected object: %v", obj)
					return
				}
				remSecret, ok = deletedState.Obj.(*api.Secret)
				if !ok {
					glog.V(3).Infof("Error DeletedFinalStateUnknown contained non-Secret object: %v", deletedState.Obj)
					return
				}
			}
			glog.V(3).Infof("Removing Secret: %v", remSecret.Name)
			lbc.secretQueue.enqueue(obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				glog.V(3).Infof("Secret %v changed, syncing",
					cur.(*api.Secret).Name)
				lbc.secretQueue.enqueue(cur)
			}
		},
	}

	lbc.secretLister.Store, lbc.secretController = cache.NewInformer(
		cache.NewListWatchFromClient(lbc.client.CoreV1().RESTClient(), "secrets", namespace, fields.Everything()),
		&api.Secret{}, resyncPeriod, secretHandlers)

	return &lbc, nil
}

func (lbc *LoadBalancerController) preparePemFileNames(ingEx *nginx.IngressEx) {
	sslServices := lbc.cnf.GetSSLServices(ingEx)
	paths := []string{lbc.cnf.GetNginxCertsPath(), ""}
	for _, path := range paths {
		for _, sslData := range sslServices {
			name := path + "/" + ingEx.Ingress.Namespace + "_" + ingEx.Ingress.Name + "_" + sslData.SecretName + "_"
			trustedCertPath := name + "trusted.crt"
			clientCertPath := name + "client.crt"
			clientKeyPath := name + "client.key"
			files := []string{trustedCertPath, clientCertPath, clientKeyPath}
			lbc.cleanupPem(files)
		}
	}
}

func (lbc *LoadBalancerController) cleanupPem(files []string) {
	for _, file := range files {
		glog.V(4).Infof("pem file is %v", file)
		err := os.Remove(file)
		if err != nil {
			glog.Errorf("pem file %v is not deleted and err is %v \n", file, err)
		} else {
			glog.V(3).Infof("pem file %v is deleted", file)
		}
	}
}

// Run starts the loadbalancer controller
func (lbc *LoadBalancerController) Run() {
	go lbc.ingController.Run(lbc.stopCh)
	go lbc.svcController.Run(lbc.stopCh)
	go lbc.endpController.Run(lbc.stopCh)
	go lbc.podController.Run(lbc.stopCh)
	go lbc.ingQueue.run(time.Second, lbc.stopCh)
	go lbc.endpQueue.run(time.Second, lbc.stopCh)
	if lbc.watchNginxConfigMaps {
		go lbc.cfgmController.Run(lbc.stopCh)
		go lbc.cfgmQueue.run(time.Second, lbc.stopCh)
	}
	go lbc.secretController.Run(lbc.stopCh)
	go lbc.secretQueue.run(time.Second, lbc.stopCh)
	go lbc.checkReadiness()
	lbc.handleIngressPodScaleChanges()
	<-lbc.stopCh
}

// Stop shutdowns the load balancer controller
func (lbc *LoadBalancerController) Stop() {
	// set shutdown mode, so that no sync operations happen
	lbc.inShutdownMode = true

	lbc.ingQueue.shutdown()
	lbc.endpQueue.shutdown()
	lbc.cfgmQueue.shutdown()
	lbc.secretQueue.shutdown()

	// resync all ingress resources and empty the status list
	rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
	rm.ResetIngressStatus()

	close(lbc.stopCh)
}

func (lbc *LoadBalancerController) syncEndp(key string) {
	glog.V(4).Infof("Syncing endpoints %v", key)

	obj, endpExists, err := lbc.endpLister.Store.GetByKey(key)
	if err != nil {
		lbc.endpQueue.requeue(key, err)
		return
	}

	if endpExists {
		ings := lbc.getIngressForEndpoints(obj)

		for _, ing := range ings {
			if !isNginxIngress(&ing) {
				glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressClassKey)
				//rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
				//rm.RemoveStatusAddress(&ing)
				continue
			}
			if !isALBIDMatching(&ing) {
				glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressTypeKey)
				//rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
				//rm.RemoveStatusAddress(&ing)
				continue
			}
			ingEx, err := lbc.createIngress(&ing)
			if err != nil {
				glog.Warningf("Error updating endpoints for %v/%v: %v, skipping", ing.Namespace, ing.Name, err)
				continue
			}
			glog.V(3).Infof("Updating Endpoints for %v/%v", ing.Name, ing.Namespace)
			name := ing.Namespace + "-" + ing.Name
			lbc.cnf.UpdateEndpoints(name, ingEx)
		}
	}
}

func (lbc *LoadBalancerController) syncCfgm(key string) {
	glog.V(3).Infof("Syncing configmap %v", key)

	obj, cfgmExists, err := lbc.cfgmLister.Store.GetByKey(key)
	if err != nil {
		lbc.cfgmQueue.requeue(key, err)
		return
	}
	cfg := nginx.NewDefaultConfig()

	if cfgmExists {
		cfgm := obj.(*api.ConfigMap)

		if serverTokens, exists, err := nginx.GetMapKeyAsBool(cfgm.Data, "server-tokens", cfgm); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.ServerTokens = serverTokens
			}
		}
		if proxyConnectTimeout, exists := cfgm.Data["proxy-connect-timeout"]; exists {
			cfg.ProxyConnectTimeout = proxyConnectTimeout
		}
		if ratelimitMemory, exists := cfgm.Data["rate-limit-memory"]; exists {
			cfg.RatelimitMemory = ratelimitMemory
		}
		if ratelimitValue, exists := cfgm.Data["rate-limit-value"]; exists {
			cfg.RatelimitValue = ratelimitValue
		}
		if ratelimitBurst, exists := cfgm.Data["rate-limit-burst"]; exists {
			cfg.RatelimitBurst = ratelimitBurst
		}

		if inKeepAlive, exists := cfgm.Data["keep-alive"]; exists {
			cfg.InKeepAlive = inKeepAlive
		}

		if inKeepaliveReq, exists := cfgm.Data["keep-alive-requests"]; exists {
			cfg.InKeepaliveRequests = inKeepaliveReq
		}

		if inBacklog, exists := cfgm.Data["backlog"]; exists {
			inBacklogInt, err := strconv.Atoi(inBacklog)
			if err != nil {
				glog.Error(err)
			} else if inBacklogInt <= 32768 {
				cfg.Backlog = inBacklog
			}
		}

		if reusePort, exists, err := nginx.GetMapKeyAsBool(cfgm.Data, "reuse-port", cfgm); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.ReusePort = reusePort
			}
		}

		if proxyReadTimeout, exists := cfgm.Data["proxy-read-timeout"]; exists {
			cfg.ProxyReadTimeout = proxyReadTimeout
		}
		if proxyHideHeaders, exists, err := nginx.GetMapKeyAsStringSlice(cfgm.Data, "proxy-hide-headers", cfgm, ","); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.ProxyHideHeaders = proxyHideHeaders
			}
		}
		if proxyPassHeaders, exists, err := nginx.GetMapKeyAsStringSlice(cfgm.Data, "proxy-pass-headers", cfgm, ","); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.ProxyPassHeaders = proxyPassHeaders
			}
		}
		if clientMaxBodySize, exists := cfgm.Data["client-max-body-size"]; exists {
			cfg.ClientMaxBodySize = clientMaxBodySize
		}
		if serverNamesHashBucketSize, exists := cfgm.Data["server-names-hash-bucket-size"]; exists {
			cfg.MainServerNamesHashBucketSize = serverNamesHashBucketSize
		}
		if serverNamesHashMaxSize, exists := cfgm.Data["server-names-hash-max-size"]; exists {
			cfg.MainServerNamesHashMaxSize = serverNamesHashMaxSize
		}
		if HTTP2, exists, err := nginx.GetMapKeyAsBool(cfgm.Data, "http2", cfgm); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.HTTP2 = HTTP2
			}
		}
		if redirectToHTTPS, exists, err := nginx.GetMapKeyAsBool(cfgm.Data, "redirect-to-https", cfgm); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.RedirectToHTTPS = redirectToHTTPS
			}
		}

		if proxyProtocol, exists, err := nginx.GetMapKeyAsBool(cfgm.Data, "proxy-protocol", cfgm); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.ProxyProtocol = proxyProtocol
			}
		}

		// ngx_http_realip_module
		if realIPHeader, exists := cfgm.Data["real-ip-header"]; exists {
			cfg.RealIPHeader = realIPHeader
		}
		if setRealIPFrom, exists, err := nginx.GetMapKeyAsStringSlice(cfgm.Data, "set-real-ip-from", cfgm, ","); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.SetRealIPFrom = setRealIPFrom
			}
		}
		if realIPRecursive, exists, err := nginx.GetMapKeyAsBool(cfgm.Data, "real-ip-recursive", cfgm); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.RealIPRecursive = realIPRecursive
			}
		}

		// SSL block
		if sslProtocols, exists := cfgm.Data["ssl-protocols"]; exists {
			cfg.MainServerSSLProtocols = sslProtocols
		}
		if sslPreferServerCiphers, exists, err := nginx.GetMapKeyAsBool(cfgm.Data, "ssl-prefer-server-ciphers", cfgm); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.MainServerSSLPreferServerCiphers = sslPreferServerCiphers
			}
		}
		if sslCiphers, exists := cfgm.Data["ssl-ciphers"]; exists {
			cfg.MainServerSSLCiphers = strings.Trim(sslCiphers, "\n")
		}
		if sslDHParamFile, exists := cfgm.Data["ssl-dhparam-file"]; exists {
			sslDHParamFile = strings.Trim(sslDHParamFile, "\n")
			fileName, err := lbc.cnf.AddOrUpdateDHParam(sslDHParamFile)
			if err != nil {
				glog.Errorf("Configmap %s/%s: Could not update dhparams: %v", cfgm.GetNamespace(), cfgm.GetName(), err)
			} else {
				cfg.MainServerSSLDHParam = fileName
			}
		}

		if logFormat, exists := cfgm.Data["log-format"]; exists {
			cfg.MainLogFormat = logFormat
			cfg.MainLogFormatEscapeJSON = "escape=json"
			if logFormatEscapeJSON, exists, err := nginx.GetMapKeyAsBool(cfgm.Data, "log-format-escape-json", cfgm); exists {
				if err != nil {
					glog.Error(err)
				} else {
					if logFormatEscapeJSON == false {
						cfg.MainLogFormatEscapeJSON = ""
					}
				}
			}
		}
		if vtsStatusZoneSize, exists := cfgm.Data["vts-status-zone-size"]; exists {
			cfg.VtsStatusZoneSize = vtsStatusZoneSize
		}
		if proxyBuffering, exists, err := nginx.GetMapKeyAsBool(cfgm.Data, "proxy-buffering", cfgm); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.ProxyBuffering = proxyBuffering
			}
		}

		if proxyMaxTempFileSize, exists := cfgm.Data["proxy-max-temp-file-size"]; exists {
			cfg.ProxyMaxTempFileSize = proxyMaxTempFileSize
		}

		if mainHTTPSnippets, exists, err := nginx.GetMapKeyAsStringSlice(cfgm.Data, "http-snippets", cfgm, "\n"); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.MainHTTPSnippets = mainHTTPSnippets
			}
		}
		if locationSnippets, exists, err := nginx.GetMapKeyAsStringSlice(cfgm.Data, "location-snippets", cfgm, "\n"); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.LocationSnippets = nginx.ParseLocationSnippetLine(locationSnippets, cfgm.Name, "ingress.bluemix.net/location-snippets", "<EOS>")
				cfg.AllLocationSnippet = cfg.LocationSnippets[nginx.AllIngressServiceName]
			}
		}
		if serverSnippets, exists, err := nginx.GetMapKeyAsStringSlice(cfgm.Data, "server-snippets", cfgm, "\n"); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfg.ServerSnippets = serverSnippets
			}
		}

		if externalDNSResolver, exists := cfgm.Data["external-dns-resolver"]; exists {
			os.Setenv("EXT_DNS_RESOLVER", externalDNSResolver)
			glog.V(3).Infof("externalDNSResolver from configmap data - %s ", externalDNSResolver)
		}

		if activityTrackerEnabled, exists, err := nginx.GetMapKeyAsBool(cfgm.Data, "activity-tracker-enabled", cfgm); exists {
			if err != nil {
				glog.Error(err)
			} else {

				activityTrackerEnabledENV, err := strconv.ParseBool(os.Getenv("ACTIVITY_TRACKER_ENABLED"))

				if err != nil {
					glog.Error(err)
				} else {
					if activityTrackerEnabledENV == activityTrackerEnabled {
						glog.V(4).Infof("No change in activity tracker toggle")
					} else {
						if activityTrackerEnabled {
							os.Setenv("ACTIVITY_TRACKER_ENABLED", "true")
						} else {
							os.Setenv("ACTIVITY_TRACKER_ENABLED", "false")
						}
						glog.V(4).Infof("Activity tracker toggled to %v", activityTrackerEnabled)
					}
				}
			}
		}

		if customerLogsEnabled, exists, err := nginx.GetMapKeyAsBool(cfgm.Data, "customer-logs-enabled", cfgm); exists {
			if err != nil {
				glog.Error(err)
			} else {

				customerLogsEnabledENV, err := strconv.ParseBool(os.Getenv("CUSTOMER_LOGS_ENABLED"))
				glog.V(4).Infof("customerLogsEnabledENV - %v", customerLogsEnabledENV)

				if err != nil {
					glog.Error(err)
				} else {
					if customerLogsEnabledENV == customerLogsEnabled {
						glog.V(4).Infof("No change in customerLogs toggle")
					} else {
						if customerLogsEnabled {
							os.Setenv("CUSTOMER_LOGS_ENABLED", "true")
						} else {
							os.Setenv("CUSTOMER_LOGS_ENABLED", "false")
						}
						glog.V(4).Infof("customer logs toggle changed")
					}
				}
			}
		}

		if customerLogsfileWatchFrequency, exists := cfgm.Data["customer-logs-filewatch-frequency"]; exists {
			os.Setenv("CUSTOMER_LOGS_FILEWATCHER_FREQUENCY", customerLogsfileWatchFrequency)
			glog.V(4).Infof("CustomerLogsfileWatchFrequency is updated to %v ", customerLogsfileWatchFrequency)
		}
		// Access Log
		if accessLogEnabled, exists, err := nginx.GetMapKeyAsBool(cfgm.Data, "access-log-buffering", cfgm); exists {

			if err != nil {
				glog.Error(err)
			} else {
				cfg.AccessLogEnabled = accessLogEnabled
				glog.V(4).Infof("AccessLogEnabled is updated from configmap data to %v", accessLogEnabled)
			}

			if accessLogEnabled == true {
				if accessLogBuffer, exists := cfgm.Data["buffer-size"]; exists {
					cfg.AccessLogBuffer = accessLogBuffer
					glog.V(4).Infof("accessLogBuffer is read from configmap data to %v", accessLogBuffer)
				}
				if accessLogFlush, exists := cfgm.Data["flush-interval"]; exists {
					cfg.AccessLogFlush = accessLogFlush
					glog.V(4).Infof("accessLogFlush is read from configmap data to %v", accessLogFlush)
				}
			}
		}
	}
	lbc.cnf.UpdateConfig(cfg)

	//todo this shouldn't cause reloads for every ingress yaml.  Check community code.
	ings, _ := lbc.ingLister.List()
	for _, ing := range ings.Items {
		if !isNginxIngress(&ing) {
			glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressClassKey)
			continue
		}
		if !isALBIDMatching(&ing) {
			glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressTypeKey)
			continue
		}
		lbc.ingQueue.enqueue(&ing)
	}
}

func (lbc *LoadBalancerController) syncIng(key string) {
	glog.V(3).Infof("Syncing %v", key)

	obj, ingExists, err := lbc.ingLister.Store.GetByKey(key)
	if err != nil {
		lbc.ingQueue.requeue(key, err)
		return
	}
	glog.V(4).Info("syncIng obj", obj)

	// default/some-ingress -> default-some-ingress
	name := strings.Replace(key, "/", "-", -1)

	if !ingExists {
		glog.V(2).Infof("Deleting Ingress: %v\n", key)
		lbc.cnf.DeleteIngress(name)
	} else {
		ing, _ := toIngress(obj)
		if !isNginxIngress(ing) {
			glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressClassKey)
			//rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
			//rm.RemoveStatusAddress(ing)
			return
		}
		if !isALBIDMatching(ing) {
			glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressTypeKey)
			//rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
			//rm.RemoveStatusAddress(ing)
			return
		}
		glog.V(2).Infof("Adding or Updating Ingress: %v\n", key)
		ingEx, err := lbc.createIngress(ing)
		if err != nil {
			lbc.ingQueue.requeueAfter(key, err, 5*time.Second)
			return
		}
		lbc.resetFirstErrorFlags(ingEx.Ingress, allError)
		lbc.cnf.AddOrUpdateIngress(name, ingEx)
	}
}

func (lbc *LoadBalancerController) syncSecret(key string) {
	glog.V(4).Infof("Syncing secret %v", key)

	obj, secretExists, err := lbc.secretLister.Store.GetByKey(key)
	if err != nil {
		lbc.secretQueue.requeue(key, err)
		return
	}

	namespace, name, err := parseNamespaceAndEntityname(key)
	if err != nil {
		glog.Warningf("Secret key %v is invalid: %v", key, err)
		return
	}

	if namespace == os.Getenv("SECURED_NAMESPACE") {
		namespace = defaultNameSpace
	}

	glog.V(4).Infof("Secret namespace & name =  %v,%v", namespace, name)
	ings, sslings, mutualAuthings, err := lbc.findIngressesForSecret(namespace, name)
	if err != nil {
		glog.Warningf("Failed to find Ingress resources for Secret %v: %v", key, err)
		lbc.secretQueue.requeueAfter(key, err, 5*time.Second)
	}

	glog.V(4).Infof("Found %v Ingress resources with default Secret %v", len(ings), key)
	glog.V(4).Infof("Found %v Ingress resources with ssl Secret %v", len(sslings), key)
	glog.V(4).Infof("Found %v Ingress resources with mutual Secret %v", len(mutualAuthings), key)

	if !secretExists {
		glog.V(2).Infof("Deleting Secret: %v\n", key)
		lbc.cnf.DeleteSecret(name, ings, sslings, mutualAuthings)
	} else {
		glog.V(4).Infof("Adding or Updating Secret: %v\n", key)

		secret := obj.(*api.Secret)
		if len(ings) > 0 || len(sslings) > 0 || len(mutualAuthings) > 0 {
			if err := lbc.cnf.AddOrUpdateTLSSecret(secret, ings, sslings, mutualAuthings, true); err != nil {
				glog.Errorf("Error when updating Secret %v: %v", key, err)
				lbc.ingsQueue(ings)
				lbc.ingsQueue(sslings)
				lbc.ingsQueue(mutualAuthings)
			} else {
				glog.V(3).Infof("Secret: %v is updated successfully\n", name)
				lbc.ingsQueue(ings)
				lbc.ingsQueue(sslings)
				lbc.ingsQueue(mutualAuthings)
			}
		}
	}
}

func (lbc *LoadBalancerController) ingsQueue(ings []networking.Ingress) {
	for _, ing := range ings {
		if !isNginxIngress(&ing) {
			glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressClassKey)
			continue
		}
		if !isALBIDMatching(&ing) {
			glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressTypeKey)
			continue
		}
		lbc.ingQueue.enqueue(&ing)
	}
}

func (lbc *LoadBalancerController) findIngressesForSecret(secretNamespace string, secret string) ([]networking.Ingress, []networking.Ingress, []networking.Ingress, error) {
	var res, sslres, mutualAuthres []networking.Ingress
	ings, err := lbc.ingLister.List()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't get the list of Ingress resources: %v", err)
	}
	for _, ing := range ings.Items {
		if _, secretExistsInIngNamespace, err := lbc.secretLister.Store.GetByKey(ing.Namespace + "/" + secret); ing.Namespace == secretNamespace ||
			(err == nil && secretNamespace == "default" && !secretExistsInIngNamespace) {
			if !isNginxIngress(&ing) {
				glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressClassKey)
				continue
			}
			for _, tls := range ing.Spec.TLS {
				if tls.SecretName == secret {
					res = append(res, ing)
				}
				if services, exists := ing.Annotations["ingress.bluemix.net/ssl-services"]; exists {
					if strings.Contains(services, secret) {
						glog.V(3).Infof("secret %v found in ssl annotation \n", secret)
						sslres = append(sslres, ing)
					}
				}
				if services, exists := ing.Annotations["ingress.bluemix.net/mutual-auth"]; exists {
					if strings.Contains(services, secret) {
						glog.V(3).Infof("secret %v found in mutual-auth annotation \n", secret)
						mutualAuthres = append(mutualAuthres, ing)
					}
				}
			}
		} else if err != nil {
			glog.Errorf("Error checking if secret exists %v: %v", ing.Namespace+"/"+secret, err)
		}
	}

	return res, sslres, mutualAuthres, nil
}

func (lbc *LoadBalancerController) enqueueIngressForService(svc *api.Service) {
	ings := lbc.getIngressesForService(svc)
	for _, ing := range ings {
		if !isNginxIngress(&ing) {
			glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressClassKey)
			continue
		}
		if !isALBIDMatching(&ing) {
			glog.V(4).Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressTypeKey)
			continue
		}
		lbc.ingQueue.enqueue(&ing)
	}
}

func (lbc *LoadBalancerController) getIngressesForService(svc *api.Service) []networking.Ingress {
	ings, err := lbc.ingLister.GetServiceIngress(svc)
	if err != nil {
		glog.V(4).Infof("ignoring service %v: %v", svc.Name, err)
		return nil
	}
	return ings
}

func (lbc *LoadBalancerController) getIstioIngressesForService(svc *api.Service) (istioIngs []networking.Ingress) {
	ings, err := lbc.ingLister.List()
	if err != nil {
		glog.V(3).Infof("error in getting ingress list for istio: %v", err)
		return nil
	}
	for _, ing := range ings.Items {
		ingEx := &nginx.IngressEx{
			Ingress: &ing,
		}
		if lbc.cnf.VerifyUseOfIstioSvc(ingEx, svc) {
			istioIngs = append(istioIngs, ing)
		}
	}
	return istioIngs
}

func (lbc *LoadBalancerController) getIngressForEndpoints(obj interface{}) []networking.Ingress {
	var ings []networking.Ingress
	endp := obj.(*api.Endpoints)
	svcKey := endp.GetNamespace() + "/" + endp.GetName()
	svcObj, svcExists, err := lbc.svcLister.Store.GetByKey(svcKey)
	if err != nil {
		glog.V(3).Infof("error getting service %v from the cache: %v\n", svcKey, err)
	} else {
		if svcExists {
			ings = append(ings, lbc.getIngressesForService(svcObj.(*api.Service))...)
			ings = append(ings, lbc.getIstioIngressesForService(svcObj.(*api.Service))...)
		}
	}
	return ings
}

func (lbc *LoadBalancerController) createIngress(ing *networking.Ingress) (*nginx.IngressEx, error) {
	ingEx := &nginx.IngressEx{
		Ingress: ing,
	}

	resourceExists := false
	for _, resource := range lbc.listOfResources {
		glog.V(4).Infof("checking if ingress in list %v", resource)
		if resource.Name == ing.Name && resource.Namespace == ing.Namespace {
			resourceExists = true
		}
	}

	// add ingress resource to list if does not exists
	if !resourceExists {
		lbc.listOfResources = append(lbc.listOfResources, internal.IngressResource{Name: ing.Name, Namespace: ing.Namespace})
		glog.V(4).Infof("adding ingress to list of resources %+v", lbc.listOfResources)
	}

	resourceAcrossNamespace := false
	// check configmap data for resource name that can span across namespaces
	if lbc.currentNginxConfigMapData["ingress-resources"] != "" {
		// get the list of resources provided by user
		glog.V(4).Info("createIngress: currentNginxConfigMapData ", lbc.currentNginxConfigMapData["ingress-resources"])
		ingResNames := strings.Split(lbc.currentNginxConfigMapData["ingress-resources"], ";")

		for _, ingResource := range ingResNames {
			resource := strings.Split(ingResource, "/")
			if len(resource) != 2 {
				glog.Errorf("createIngress: Unable to get list of admin ingress resources: %s .Correct format <namespace>/<resourcename>", ingResource)
			} else {
				if resource[0] == ing.Namespace && resource[1] == ing.Name {
					glog.Info("createIngress: Creating admin ingress resource")
					// enable spanning across namespaces
					resourceAcrossNamespace = true
				}
			}
		}

	}

	ingEx.Secrets = make(map[string]*api.Secret)
	for _, tls := range ing.Spec.TLS {
		secretName := tls.SecretName
		secret, err := lbc.getSecretFromNamespace(ing.Name, ing.Namespace, secretName)
		glog.V(4).Infof("list of resources %v", lbc.listOfResources)
		if err != nil {
			if !lbc.checkIfNotFirstSecretError(ing, tlsSecretError) {
				rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode: "E0001",
					Ing:     ing,
				})
			}
			return nil, fmt.Errorf("error retrieving secret %v for Ingress %v: %v", secretName, ing.Name, err)
		}
		lbc.resetFirstErrorFlags(ing, tlsSecretError)
		ingEx.Secrets[secretName] = secret
	}
	/*SSL Secret*/
	sslServices := lbc.cnf.GetSSLServices(ingEx)
	glog.V(4).Infof("sslServices in controller is  %v \n", sslServices)
	ingEx.UpstreamSSLData = make(map[string]nginx.UpstreamSSLConfig)
	var tmpUpstreamSSLData nginx.UpstreamSSLConfig
	for svcName, sslData := range sslServices {
		if sslData.SecretName != "" {
			secret, err := lbc.getSecretFromNamespace(ing.Name, ing.Namespace, sslData.SecretName)
			if err != nil {
				if !lbc.checkIfNotFirstSecretError(ing, sslSecretError) {
					rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
					rm.GenerateKubeEvent(internal.EventError{
						MsgCode: "E0002",
						Ing:     ing,
					})
				}
				return nil, fmt.Errorf("error retrieving secret %v for Ingress %v: %v", sslData.SecretName, ing.Name, err)
			}
			lbc.resetFirstErrorFlags(ing, sslSecretError)

			tmpUpstreamSSLData = nginx.UpstreamSSLConfig{
				Secrets: nginx.Secrets{
					SecretName: string(sslData.SecretName),
					Secret:     secret,
				},
				ProxySSLConfig: nginx.ProxySSLConfig{
					ProxySSLVerifyDepth: sslData.ProxySSLVerifyDepth,
					ProxySSLName:        sslData.ProxySSLName,
				},
			}
			ingEx.UpstreamSSLData[svcName] = tmpUpstreamSSLData
		} else {
			ingEx.PlainSSL = append(ingEx.PlainSSL, svcName)
		}
	}

	ingEx.Endpoints = make(map[string][]string)
	if ing.Spec.Backend != nil {
		endps, err := lbc.getEndpointsForIngressBackend(ing.Spec.Backend, ing.Namespace, resourceAcrossNamespace)
		if err != nil {
			glog.Warningf("Error retrieving endpoints for the service %v: %v", ing.Spec.Backend.ServiceName, err)
		} else {
			ingEx.Endpoints[ing.Spec.Backend.ServiceName+ing.Spec.Backend.ServicePort.String()] = endps
		}
	}

	for _, rule := range ing.Spec.Rules {
		if rule.IngressRuleValue.HTTP == nil {
			continue
		}

		for _, path := range rule.HTTP.Paths {
			endps, err := lbc.getEndpointsForIngressBackend(&path.Backend, ing.Namespace, resourceAcrossNamespace)
			if err != nil {
				glog.Warningf("Error retrieving endpoints for the service %v: %v", path.Backend.ServiceName, err)
			} else {
				ingEx.Endpoints[path.Backend.ServiceName+path.Backend.ServicePort.String()] = endps
			}
		}

		// Check for Mutual Auth Secret
		mutualAuthAnnotation, mutualAuthAnnotationExists := lbc.cnf.GetAnnotationModel("ingress.bluemix.net/mutual-auth", ingEx)
		if mutualAuthAnnotationExists {
			mutualAuth, _, err := nginx.HandleMutualAuth(mutualAuthAnnotation, ing.Name, rule.Host)
			if err != nil {
				rm := internal.ResourceManager{
					Client: lbc.client}
				rm.GenerateKubeEvent(internal.EventError{
					MsgCode:      "A0001",
					Ing:          ingEx.Ingress,
					OverwriteMsg: fmt.Sprintf("Failed to apply %s annotation. Error %v", "ingress.bluemix.net/mutual-auth", err),
				})
			}
			if len(mutualAuth) == 0 {
				glog.Errorf("No valid items in `ingress.bluemix.net/mutual-auth`, Value %v in Resource %v. Mutual Auth will not be enabled.", mutualAuth, ing.Name)
			} else {
				if mutualAuth[rule.Host] != nil {
					secretName := mutualAuth[rule.Host][1]
					secret, err := lbc.getSecretFromNamespace(ing.Name, ing.Namespace, secretName)
					if err != nil {
						if !lbc.checkIfNotFirstSecretError(ing, maSecretError) {
							rm := internal.ResourceManager{Client: lbc.client, ListOfResources: lbc.listOfResources}
							rm.GenerateKubeEvent(internal.EventError{
								MsgCode: "E0003",
								Ing:     ing,
							})
						}
						glog.Errorf("Error retrieving mutual-auth secret %v for Ingress %v: %v. Mutual Auth will not be enabled.", secretName, ing.Name, err)
						return nil, err
					}
					lbc.resetFirstErrorFlags(ing, maSecretError)
					ingEx.Secrets[secretName] = secret
				}
			}
		}
	}

	if streamAnnotation, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/tcp-ports"]; exists {
		streamConfigs, err := nginx.ParseStreamConfigs(streamAnnotation)
		var fail = false
		if err == nil {
			for _, streamConfig := range streamConfigs {
				var backend networking.IngressBackend
				backend.ServiceName = streamConfig.ServiceName
				var n int
				n, err = strconv.Atoi(streamConfig.ServicePort)
				if err != nil {
					glog.Warningf("Error in getting service port %v", streamConfig.ServicePort)
					fail = true
					break
				}
				backend.ServicePort = intstr.FromInt(n)
				var endps []string
				endps, err = lbc.getEndpointsForIngressBackend(&backend, ing.Namespace, resourceAcrossNamespace)
				if err != nil {
					glog.Warningf("Error retrieving endpoints for the service %v: %v", streamConfig.ServiceName, err)
					fail = true
				} else {
					ingEx.Endpoints[backend.ServiceName+backend.ServicePort.String()] = endps
				}
			}
		}
		if fail == true && err == nil {
			var rule networking.IngressRule
			rule.Host = "dummy-k8-fd-ing"
			for _, streamConfig := range streamConfigs {
				var backend networking.IngressBackend
				backend.ServiceName = streamConfig.ServiceName
				backend.ServicePort = intstr.FromString(streamConfig.ServicePort)
				var path networking.HTTPIngressPath
				path.Backend = backend
				path.Path = streamConfig.ServiceName + "_stream"
				var _http networking.HTTPIngressRuleValue
				if rule.IngressRuleValue.HTTP == nil {
					rule.IngressRuleValue.HTTP = &_http
				}
				rule.IngressRuleValue.HTTP.Paths = append(rule.IngressRuleValue.HTTP.Paths, path)
				ing.Spec.Rules = append(ing.Spec.Rules, rule)
			}
			lbc.ingQueue.enqueue(&ing)
		}
	}

	istioIngressUpstreams := []nginx.IstioIngressUpstream{}

	if istioIngressAnnotation, istioIngressAnnotationExists := lbc.cnf.GetAnnotationModel("ingress.bluemix.net/istio-services", ingEx); istioIngressAnnotationExists {

		glog.V(4).Infof("IstioIngress annotation exists.")
		glog.V(4).Infof("Retrieving all the backend services and their port mentioned by the user in ingress resource for ALB.")

		backendSvcPortMap := make(map[string](intstr.IntOrString))

		for _, rule := range ing.Spec.Rules {
			if rule.IngressRuleValue.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {

				backendSvcPortMap[path.Backend.ServiceName] = path.Backend.ServicePort
			}
		}

		// string array to hold backend svc which are disabled or enabled=false in the annotation .
		var nonIstioBackendSvcArray []string
		// determines whether the annotation contains an "enabled=true" entry or not .
		var enableAllExists = false
		// determines whether the annotation contains an "enabled=false" entry or not .
		var disableAllexists = false

		// determines how many entries are there there in the annotation .
		istioIngressAnnotationEntriesLength := len(istioIngressAnnotation.Entries)

		if istioIngressAnnotationEntriesLength == 1 && !istioIngressAnnotation.Entries[0].Exists("serviceName") {

			var istioSvcNameVar string
			var istioSvcNamespaceVar string
			isEnabled, enabledExists := istioIngressAnnotation.Entries[0].GetAsBool("enable")
			if enabledExists && isEnabled {
				if !istioIngressAnnotation.Entries[0].Exists("istioServiceName") {
					istioSvcNameVar = "istio-ingress"
					glog.V(3).Infof("Istio ingress name not provided by the user, using  default name %v ", istioSvcNameVar)

				} else {
					if istioSvcName, istioSvcExists := istioIngressAnnotation.Entries[0].GetAsString("istioServiceName"); istioSvcExists {
						istioSvcNameVar = istioSvcName
						glog.V(3).Infof("Istio ingress name provided by the user %v ", istioSvcNameVar)

					}
				}
				if !istioIngressAnnotation.Entries[0].Exists("istioServiceNamespace") {
					istioSvcNamespaceVar = "istio-system"
					glog.V(3).Infof("Istio ingress namespace name not provided by the user , using  default name %v ", istioSvcNamespaceVar)

				} else {
					if istioSvcNamespace, istioSvcNamespaceExists := istioIngressAnnotation.Entries[0].GetAsString("istioServiceNamespace"); istioSvcNamespaceExists {
						istioSvcNamespaceVar = istioSvcNamespace
						glog.V(3).Infof("Istio ingress name space provided by the user %v ", istioSvcNamespaceVar)
					}
				}
				glog.V(4).Infof("Enabling  istio for all backend svc.")
				for backendService, port := range backendSvcPortMap {
					glog.V(4).Infof("Retrieving endpoints for svc %v", backendService)
					svcEndpoints, _ := lbc.getEndpointsForIstioSvcBackend(istioSvcNameVar, istioSvcNamespaceVar, port.IntValue())
					glog.V(4).Infof("Endpoints for svc %v - %v ", backendService, svcEndpoints)

					istioIngressUpstreamInstance := nginx.IstioIngressUpstream{
						BackendSvc: backendService,
						Endpoints:  svcEndpoints,
					}
					istioIngressUpstreams = append(istioIngressUpstreams, istioIngressUpstreamInstance)
				}
			}

		} else {

			for _, entry := range istioIngressAnnotation.Entries {
				isEnabled, enabledExists := entry.GetAsBool("enable")

				if enabledExists && isEnabled {

					var svcEndpoints []string
					var svcName string
					var svcExists bool
					var istioSvcNameVar string
					var istioSvcNamespaceVar string
					var istioIngressUpstreamInstance nginx.IstioIngressUpstream

					if entry.Exists("serviceName") {

						if !entry.Exists("istioServiceName") {
							istioSvcNameVar = "istio-ingress"
							glog.V(3).Infof("Istio ingress name not provided by the user , using  default name %v ", istioSvcNameVar)

						} else {
							if istioSvcName, istioSvcExists := entry.GetAsString("istioServiceName"); istioSvcExists {
								istioSvcNameVar = istioSvcName
								glog.V(3).Infof("Istio ingress name provided by the user %v ", istioSvcNameVar)
							}
						}
						if !entry.Exists("istioServiceNamespace") {
							istioSvcNamespaceVar = "istio-system"
							glog.V(3).Infof("Istio ingress namespace name not provided by the user , using  default name %v ", istioSvcNamespaceVar)

						} else {
							if istioSvcNamespace, istioSvcNamespaceExists := entry.GetAsString("istioServiceNamespace"); istioSvcNamespaceExists {
								istioSvcNamespaceVar = istioSvcNamespace
								glog.V(3).Infof("Istio ingress name space provided by the user %v ", istioSvcNamespaceVar)
							}
						}

						svcName, svcExists = entry.GetAsString("serviceName")
						if svcExists {
							targetPort := backendSvcPortMap[svcName]
							glog.V(4).Infof("Retrieving endpoints for svc %v", svcName)
							svcEndpoints, _ = lbc.getEndpointsForIstioSvcBackend(istioSvcNameVar, istioSvcNamespaceVar, targetPort.IntValue())
							glog.V(4).Infof("Endpoints for svc %v - %v ", svcName, svcEndpoints)
						}
					} else {
						glog.V(4).Infof("Enabled=true exists as the only field in the entry.")
						enableAllExists = true
					}

					// Add the svc to the ingress istio upstream only if it is mentioned by the user in annotation entry.
					if svcName != "" {
						istioIngressUpstreamInstance = nginx.IstioIngressUpstream{
							BackendSvc: svcName,
							Endpoints:  svcEndpoints,
						}
						istioIngressUpstreams = append(istioIngressUpstreams, istioIngressUpstreamInstance)
					}

				} else if enabledExists && !isEnabled {

					if entry.Exists("serviceName") {
						svcName, svcExists := entry.GetAsString("serviceName")
						if svcExists {
							glog.V(3).Infof("Enabled=false exists for service %v ", svcName)
							nonIstioBackendSvcArray = append(nonIstioBackendSvcArray, svcName)
						}
					} else {
						glog.V(3).Infof("Enabled=false exists as the only field in the entry.")
						disableAllexists = true
					}
				}
			}

		}

		// enable all the remaining backend svc excluding the ones which are already saved in istioIngressUpstreams , nonIstioBackendSvcArray .
		if enableAllExists && !disableAllexists {
			glog.V(4).Infof("Enabling all the remaining backend svc excluding the ones which are already saved in istioIngressUpstreams , nonIstioBackendSvcArray .")
			for backendService, port := range backendSvcPortMap {

				backendSvcFound := false
				for _, upstream := range istioIngressUpstreams {
					if backendService == upstream.BackendSvc {
						backendSvcFound = true
					}
				}
				// if svc was not found in istioIngressUpstreams check whether it has disabled specifically .
				if !backendSvcFound {
					for _, nonIstioBackendSvc := range nonIstioBackendSvcArray {
						if backendService == nonIstioBackendSvc {
							backendSvcFound = true
						}
					}
				}

				// if svc was not found neither in istioIngressUpstreams nor in nonIstioBackendSvcArray , then we can enable this
				if !backendSvcFound {

					targetPort := port
					glog.V(4).Infof("Retrieving endpoints for svc %v", backendService)
					svcEndpoints, _ := lbc.getEndpointsForIstioSvcBackend("istio-ingress", "istio-system", targetPort.IntValue())
					glog.V(4).Infof("Endpoints for svc %v - %v ", backendService, svcEndpoints)
					istioIngressUpstreamInstance := nginx.IstioIngressUpstream{
						BackendSvc: backendService,
						Endpoints:  svcEndpoints,
					}
					istioIngressUpstreams = append(istioIngressUpstreams, istioIngressUpstreamInstance)
				}
			}
		}

	}
	glog.V(4).Infof("Populating ingress with istioUpstreams %v ", istioIngressUpstreams)
	ingEx.IstioIngressUpstreams = istioIngressUpstreams
	return ingEx, nil
}

func (lbc *LoadBalancerController) getSecretFromNamespace(ingName string, namespace string, secretName string) (secret *api.Secret, err error) {
	securedNamespace := os.Getenv("SECURED_NAMESPACE")
	secretFound := false             // If false by end of function, then log error
	namespacesSearched := []string{} // Maintain namespaces searched for error logging

	// Logic:
	// 1. Check for Secret in the namespace where the Ingress is located
	// 	1.1 If in the default namespace
	//    1.1.1 If Reference Secret, check for secret in CertStore
	//    1.1.2 If not Reference Secret, then use it
	//  1.2 If not in the default namespace then use it
	// 2. Check for Secret in the default Namespace
	// 	2.1 If Reference Secret, check for secret in the CertStore
	// 	2.2 If not Reference Secret, then use it
	// 3. Check for Secret in the CertStore

	secret, err = lbc.client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, meta_v1.GetOptions{})
	glog.V(4).Infof("Checking for secret %v in %v namespace", secretName, namespace)
	namespacesSearched = append(namespacesSearched, namespace)

	if err != nil {
		glog.Infof("Could not find secret %v for Ingress %v in namespace %v: %v", secretName, ingName, namespace, err)

		secret, err = lbc.client.CoreV1().Secrets(defaultNameSpace).Get(context.Background(), secretName, meta_v1.GetOptions{})
		glog.V(4).Infof("Checking for secret %v in %v namespace", secretName, defaultNameSpace)
		namespacesSearched = append(namespacesSearched, defaultNameSpace)

		if err != nil {
			glog.Infof("Could not find secret %v for Ingress %v in namespace %v", secretName, ingName, defaultNameSpace)

			glog.V(4).Infof("Checking for Secret %v in namespace %v", secretName, securedNamespace)
			secret, err = lbc.client.CoreV1().Secrets(securedNamespace).Get(context.Background(), secretName, meta_v1.GetOptions{})
			namespacesSearched = append(namespacesSearched, securedNamespace)
			if err != nil {
				glog.Infof("Secret %v not found in Secure Namespace %v: %v", secretName, securedNamespace, err)
			} else {
				glog.Infof("Secret %v found in Secure Namespace %v", secretName, securedNamespace)
				secretFound = true
			}
		} else {
			glog.Infof("Secret %v found in namespace %v", secretName, defaultNameSpace)
			secretFound = true

			if lbc.referenceSecretExists(secret) {
				glog.Infof("Reference Secret Exists, Checking for secret %v in Secured Namespace %v", secretName, securedNamespace)
				secret, err = lbc.client.CoreV1().Secrets(securedNamespace).Get(context.Background(), secretName, meta_v1.GetOptions{})
				namespacesSearched = append(namespacesSearched, securedNamespace)

				if err != nil {
					glog.Infof("Secret %v not found in Secure Namespace %v: %v", secretName, securedNamespace, err)
					secretFound = false
				} else {
					glog.Infof("Secret %v found in namespace %v", secretName, securedNamespace)
				}
			}
		}
	} else {
		glog.Infof("Secret %v found in namespace %v", secretName, namespace)
		secretFound = true

		if namespace == defaultNameSpace {
			if lbc.referenceSecretExists(secret) {
				glog.Infof("Reference Secret Exists, Checking for secret %v in Secured Namespace %v", secretName, securedNamespace)
				secret, err = lbc.client.CoreV1().Secrets(securedNamespace).Get(context.Background(), secretName, meta_v1.GetOptions{})
				namespacesSearched = append(namespacesSearched, securedNamespace)

				if err != nil {
					glog.Infof("Secret %v not found in Secure Namespace %v: %v", secretName, securedNamespace, err)
					secretFound = false
				} else {
					glog.Infof("Secret %v found in namespace %v", secretName, securedNamespace)
				}
			}
		}
	}

	// Log error if seceret not found within any namespaces
	if !secretFound {
		glog.Errorf("Secret %v not found in Namespaces: %v: %v", secretName, namespacesSearched, err)
	}

	return secret, err
}

func (lbc *LoadBalancerController) referenceSecretExists(secret *api.Secret) bool {
	referenceSecret, _ := secret.Data["referenceSecret"]
	if referenceSecret != nil {
		return true
	}

	return false
}

func (lbc *LoadBalancerController) getEndpointsForIngressBackend(backend *networking.IngressBackend, namespace string, resourceAcrossNamespace bool) ([]string, error) {
	svc, err := lbc.getServiceForIngressBackend(backend, namespace, resourceAcrossNamespace)
	if err != nil {
		glog.V(3).Infof("Error getting service %v: %v", backend.ServiceName, err)
		return nil, err
	}

	endps, err := lbc.endpLister.GetServiceEndpoints(svc)
	if err != nil {
		glog.V(3).Infof("Error getting endpoints for service %s from the cache: %v", svc.Name, err)
		return nil, err
	}

	result, err := lbc.getEndpointsForPort(endps, backend.ServicePort, svc)
	if err != nil {
		glog.V(3).Infof("Error getting endpoints for service %s port %v: %v", svc.Name, backend.ServicePort, err)
		return nil, err
	}
	return result, nil
}

func (lbc *LoadBalancerController) getEndpointsForPort(endps api.Endpoints, ingSvcPort intstr.IntOrString, svc *api.Service) ([]string, error) {
	var targetPort int32
	var err error
	var found bool

	for _, port := range svc.Spec.Ports {
		if (ingSvcPort.Type == intstr.Int && port.Port == int32(ingSvcPort.IntValue())) || (ingSvcPort.Type == intstr.String && port.Name == ingSvcPort.String()) {
			if targetPort, err = lbc.getTargetPort(&port, svc); err != nil {
				return nil, fmt.Errorf("error determining target port for port %v in Ingress: %v", ingSvcPort, err)
			}
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("no port %v in service %s", ingSvcPort, svc.Name)
	}

	for _, subset := range endps.Subsets {
		for _, port := range subset.Ports {
			if port.Port == targetPort {
				var endpoints []string
				for _, address := range subset.Addresses {
					endpoint := fmt.Sprintf("%v:%v", address.IP, port.Port)
					endpoints = append(endpoints, endpoint)
				}
				return endpoints, nil
			}
		}
	}

	return nil, fmt.Errorf("no endpoints for target port %v in service %s", targetPort, svc.Name)
}

func (lbc *LoadBalancerController) getTargetPort(svcPort *api.ServicePort, svc *api.Service) (int32, error) {
	if (svcPort.TargetPort == intstr.IntOrString{}) {
		return svcPort.Port, nil
	}

	if svcPort.TargetPort.Type == intstr.Int {
		return int32(svcPort.TargetPort.IntValue()), nil
	}

	pods, err := lbc.client.CoreV1().Pods(svc.Namespace).List(context.Background(), meta_v1.ListOptions{LabelSelector: labels.Set(svc.Spec.Selector).AsSelector().String()})
	if err != nil {
		return 0, fmt.Errorf("error getting pod information: %v", err)
	}
	if len(pods.Items) == 0 {
		return 0, fmt.Errorf("no pods of service %s", svc.Name)
	}

	pod := &pods.Items[0]

	portNum, err := FindPort(pod, svcPort)
	if err != nil {
		return 0, fmt.Errorf("error finding named port %v in pod %s: %v", svcPort, pod.Name, err)
	}

	return portNum, nil
}

func (lbc *LoadBalancerController) getServiceForIngressBackend(backend *networking.IngressBackend, namespace string, resourceAcrossNamespace bool) (*api.Service, error) {
	svcKey := namespace + "/" + backend.ServiceName

	// using services across namespace enabled (admin ingress resource)
	if resourceAcrossNamespace {
		parseService := strings.Split(backend.ServiceName, namespaceDelimiter)

		if len(parseService) == 2 && parseService[1] != "" {
			svcKey = parseService[1] + "/" + parseService[0]
		}
	}

	glog.V(4).Infof("getServiceForIngressBackend svcKey: %s", svcKey)
	glog.V(4).Info("resourceAcrossNamespace: ", resourceAcrossNamespace)

	svcObj, svcExists, err := lbc.svcLister.Store.GetByKey(svcKey)
	if err != nil {
		return nil, err
	}

	if svcObj != nil {
		if resourceAcrossNamespace {
			parseService := strings.Split(backend.ServiceName, namespaceDelimiter)
			if len(parseService) == 2 && parseService[1] != "" {
				svcObj.(*api.Service).Namespace = parseService[1]
				svcObj.(*api.Service).Name = parseService[0]
			}
		}
	}

	if svcExists {
		return svcObj.(*api.Service), nil
	}

	return nil, fmt.Errorf("service %s doesn't exists", svcKey)
}

func parseNamespaceAndEntityname(value string) (ns string, name string, err error) {
	res := strings.Split(value, "/")
	if len(res) != 2 {
		return "", "", fmt.Errorf("%v must follow the format <namespace>/<name>", value)
	}
	return res[0], res[1], nil
}

func isNginxIngress(ing *networking.Ingress) bool {
	if class, exists := ing.Annotations[ingressClassKey]; exists {
		return class == nginxIngressClass || class == "" || class == iksIngressClass
	}

	return true
}

func isALBIDMatching(ing *networking.Ingress) bool {
	annotationAlbID, exists := ing.Annotations[ingressTypeKey]
	annotationMatch := false
	if !exists {
		return "public" == os.Getenv("ingress_alb_type")
	}
	albArr, err := parseAlbIDAnnotation(annotationAlbID)
	if err != nil {
		glog.Errorf("Failed to apply %s annotation. %v", "ingress.bluemix.net/ALB-ID", err)
	} else {
		for _, AlbID := range albArr {
			if AlbID == os.Getenv("ALB_ID") {
				annotationMatch = true
				break
			}
		}
		if annotationMatch == false {
			glog.V(4).Infof("No ALBID match")
		}
	}
	return annotationMatch
}

func parseAlbIDAnnotation(albID string) (albArray []string, err error) {

	if albID == "" {
		err = fmt.Errorf("Invalid entry: %v ", albID)
	} else {
		//parse albID to get list of albIDs
		albs := strings.Split(albID, ";")
		for _, elem := range albs {
			alb := strings.TrimSpace(elem)
			albArray = append(albArray, alb)
		}
	}
	return albArray, err
}

func (lbc *LoadBalancerController) updateLoadBalancerServicePorts(configMapData map[string]string, delete bool) error {
	// get alb id to determine the lb name
	ingressSvcName := os.Getenv("ALB_ID_LB")
	var portKey string
	// perform this operation only if alb_id is found
	if ingressSvcName != "" {
		var svcObject *api.Service
		var err error

		for i := 1; i <= 5; i++ {
			svcObject, err = lbc.client.CoreV1().Services(ingressSvcNameSpace).Get(context.Background(), ingressSvcName, meta_v1.GetOptions{})
			if err == nil {
				break
			} else {
				glog.Errorf("failed to get service object on attempt %d for alb service: %s. Error: %v", i, ingressSvcName, err)
				time.Sleep(time.Duration(3*i) * time.Second)
			}
		}

		if err != nil {
			glog.Errorf("updateLoadBalancerServicePorts: Failed to get ingress service object %s. Error: %v",
				ingressSvcName, err)
			return err
		}

		newPorts := api.ServiceSpec{}.Ports

		if strings.Contains(ingressSvcName, "public") || strings.Contains(ingressSvcName, "pubids") {
			portKey = "public-ports"
		} else if strings.Contains(ingressSvcName, "private") {
			portKey = "private-ports"
		}

		cnfPorts := configMapData[portKey]
		if cnfPorts != "" && !delete {
			ports := removeDuplicates(strings.Split(cnfPorts, ";"))
			for _, port := range ports {
				portInt, convErr := strconv.ParseInt(port, 10, 32)
				if convErr != nil {
					glog.Errorf("updateLoadBalancerServicePorts: Port %v cannot be converted to an integer. Error: %v", port, convErr)
				} else {
					newSvcPort := api.ServicePort{
						Name:       "port-" + port,
						Port:       int32(portInt),
						Protocol:   "TCP",
						TargetPort: intstr.FromInt(int(portInt)),
					}
					newPorts = append(newPorts, newSvcPort)
				}
			}
			// check to see if the current cm ports match the lb ports and bail if they do match
			svcPorts := svcObject.Spec.Ports
			if matchingPorts(svcPorts, newPorts) {
				glog.Info("updateLoadBalancerServicePorts: Load Balancer ports match Config Map ports. Nothing to do here")
				return nil
			}
		} else {
			// Reset to Defaults
			httpPort := api.ServicePort{
				Name:       "http",
				Port:       80,
				Protocol:   "TCP",
				TargetPort: intstr.FromInt(80),
			}
			newPorts = append(newPorts, httpPort)
			httpsPort := api.ServicePort{
				Name:       "https",
				Port:       443,
				Protocol:   "TCP",
				TargetPort: intstr.FromInt(443),
			}
			newPorts = append(newPorts, httpsPort)
		}
		svcObject.Spec.Ports = newPorts

		for i := 1; i <= 5; i++ {
			_, err = lbc.client.CoreV1().Services(ingressSvcNameSpace).Update(context.Background(), svcObject, meta_v1.UpdateOptions{})
			if err == nil {
				break
			} else {
				glog.Errorf("updateLoadBalancerServicePorts: Failed to update the ingress LB service with desired ports on attempt %d. Error: %v", i, err)
				svcObject, err = lbc.client.CoreV1().Services(ingressSvcNameSpace).Get(context.Background(), ingressSvcName, meta_v1.GetOptions{})
				if err != nil {
					svcObject.Spec.Ports = newPorts
				}
				time.Sleep(time.Duration(3*i) * time.Second)
			}
		}

		if err != nil {
			glog.Errorf("updateLoadBalancerServicePorts: Failed to update the ingress LB service after 5 attempts. Error: %v", err)
			return err
		}

		// post validation to ensure the desired ports have been opened on the load balancer service
		for i := 1; i <= 5; i++ {
			svcObject, err = lbc.client.CoreV1().Services(ingressSvcNameSpace).Get(context.Background(), ingressSvcName, meta_v1.GetOptions{})
			if err == nil {
				break
			} else {
				glog.Errorf("post validation: failed to get service object on attempt %d for alb service: %s", i, ingressSvcName)
				time.Sleep(time.Duration(3*i) * time.Second)
			}
		}

		if err != nil || svcObject.Spec.Ports == nil {
			glog.Errorf("updateLoadBalancerServicePorts: Failed to get ingress service object %s for post validation after 5 attempts. Error: %v",
				ingressSvcName, err)
			return err
		}

		// this loop will ensure all the desired ports have been opened on the lb service
		// if any ports are missing then a message is logged
		for _, desiredPort := range newPorts {
			exists := false
			for _, actualPort := range svcObject.Spec.Ports {
				if actualPort.Port == desiredPort.Port {
					exists = true
					break
				}
			}
			if exists == false {
				glog.Errorf("updateLoadBalancerServicePorts: port %d not found in the post validation", desiredPort.Port)
			}
		}
		glog.V(3).Infof("updateLoadBalancerServicePorts: updated %s lb service ports", ingressSvcName)
	} else {
		glog.V(3).Info("updateLoadBalancerServicePorts: service name not found")
	}
	return nil
}

func (lbc *LoadBalancerController) updateIngressResources(configMapData map[string]string, method string) {

	switch method {
	case "AddFunc":
		glog.V(4).Infof("updateConfigMapData:AddFunc current config map data %s", configMapData)

		lbc.updatedNginxConfigMapData = configMapData
		lbc.currentNginxConfigMapData = configMapData
		syncResources := parseResourceNames(lbc.currentNginxConfigMapData["ingress-resources"])

		// this flow works if adding config map first time or adding configmap after delete
		if len(syncResources) > 0 {
			for _, ingResource := range syncResources {
				lbc.ingQueue.queue.Add(ingResource.Namespace + "/" + ingResource.Name)
			}
		}

	case "UpdateFunc":
		glog.V(4).Infof("updateConfigMapData:UpdateFunc current config map data %s", configMapData)

		lbc.updatedNginxConfigMapData = configMapData
		currentData := lbc.currentNginxConfigMapData["ingress-resources"]
		var diffList []internal.IngressResource
		updatedResourceList := parseResourceNames(lbc.updatedNginxConfigMapData["ingress-resources"])

		for _, resource := range updatedResourceList {
			if !strings.Contains(currentData, resource.Namespace+"/"+resource.Name) {
				diffList = append(diffList, resource)
			} else {
				strings.Replace(currentData, resource.Namespace+"/"+resource.Name, "", -1)
			}
		}

		residualCurrentData := parseResourceNames(currentData)
		for _, residualResource := range residualCurrentData {
			diffList = append(diffList, residualResource)
		}

		// replace current with new updated value
		lbc.currentNginxConfigMapData = configMapData

		// this needs to be done to sync admin resources based on updated configmap data
		// this will not run if there are no changes in configmap data for admin resource
		if len(diffList) > 0 {
			for _, syncResource := range diffList {
				lbc.ingQueue.queue.Add(syncResource.Namespace + "/" + syncResource.Name)
			}
		}

	case "DeleteFunc":
		lbc.updatedNginxConfigMapData = nil
		currentResources := parseResourceNames(lbc.currentNginxConfigMapData["ingress-resources"])
		lbc.currentNginxConfigMapData = nil
		glog.V(4).Infof("updateConfigMapData:DeleteFunc current config map data %s", configMapData)

		// configmap has been deleted, which means we need to disable all admin resources
		if len(currentResources) > 0 {
			for _, syncResource := range currentResources {
				lbc.ingQueue.queue.Add(syncResource.Namespace + "/" + syncResource.Name)
			}
		}
	}
}

// parseResourceNames ... parse list of admin ingress resource from config map
func parseResourceNames(resourceName string) []internal.IngressResource {
	adminResources := []internal.IngressResource{}
	ingResources := strings.Split(resourceName, ";")
	if resourceName != "" && len(ingResources) > 0 {
		for _, resource := range ingResources {
			resourceDetails := strings.Split(resource, "/")
			if len(resourceDetails) == 2 {
				adminResources = append(adminResources, internal.IngressResource{
					Name:      resourceDetails[1],
					Namespace: resourceDetails[0]})
			} else {
				glog.Errorf("parseResourceNames: Error reading value %s from config map. Expected format <namespace>/<resource name>", resourceDetails)
			}
		}
	}

	return adminResources
}

func (lbc *LoadBalancerController) retrievePodScale(nameSpace string, labelSetKey string, LabelSetVal string) int {
	var podLen int
	pods, err := lbc.client.CoreV1().Pods(nameSpace).List(context.Background(), meta_v1.ListOptions{LabelSelector: labels.Set{labelSetKey: LabelSetVal}.AsSelector().String()})
	if err != nil {
		glog.Errorf("Error getting pod information: %v", err)
	}
	for _, pod := range pods.Items {
		if pod.Status.Phase == api.PodRunning {
			if isPodReady(pod.Status) {
				podLen = podLen + 1
			}
		}
	}
	return podLen
}

func (lbc *LoadBalancerController) handleIngressPodScaleChanges() bool {
	namespace := "kube-system"
	var albid = os.Getenv("ALB_ID")
	podScale := lbc.retrievePodScale(namespace, "app", albid)
	if lbc.cnf.GetPodScale() != podScale {
		lbc.cnf.SetPodScale(podScale)
		return true
	}
	return false
}

func (lbc *LoadBalancerController) rewriteRateLimitedIngresses() {
	ings := lbc.getRateLimitedIngresses()
	for _, ing := range ings.Items {
		if !isNginxIngress(&ing) {
			glog.Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressClassKey)
			continue
		}
		if !isALBIDMatching(&ing) {
			glog.Infof("Ignoring Ingress %v based on Annotation %v", ing.Name, ingressTypeKey)
			continue
		}
		ingName, ingNamespace := ing.Name, ing.Namespace
		ingStr := strings.Join([]string{ingNamespace, "/", ingName}, "")
		lbc.syncIng(ingStr)
	}
}

func (lbc *LoadBalancerController) getRateLimitedIngresses() (ing networking.IngressList) {
	ings, _ := lbc.ingLister.List()
	var rateLimitIngs networking.IngressList
	for _, ing := range ings.Items {
		if val, exists := ing.Annotations["ingress.bluemix.net/global-rate-limit"]; exists {
			glog.V(3).Infof("Ingress [%s] has ratelimit set to %s ", ing.Name, val)
			rateLimitIngs.Items = append(rateLimitIngs.Items, ing)
		} else if val, exists := ing.Annotations["ingress.bluemix.net/service-rate-limit"]; exists {
			glog.V(3).Infof("Ingress [%s] has ratelimit set to %s ", ing.Name, val)
			rateLimitIngs.Items = append(rateLimitIngs.Items, ing)
		} else {
			glog.V(4).Infof("Ingress [%s] doesn't have global or service ratelimits set ", ing.Name)
		}
	}
	return rateLimitIngs
}

func isPodReady(status api.PodStatus) bool {
	for i := range status.Conditions {
		if status.Conditions[i].Type == api.PodReady {
			if status.Conditions[i].Status == api.ConditionTrue {
				return true
			}
		}
	}
	return false
}

func (lbc *LoadBalancerController) checkIfNotFirstSecretError(ing *networking.Ingress, scenario string) (notFirstError bool) {
	for index, ingress := range lbc.listOfResources {
		if ingress.Name == ing.ObjectMeta.Name && ingress.Namespace == ing.Namespace {
			switch scenario {
			case tlsSecretError:
				notFirstError = ingress.NotFirstSecretError
				lbc.listOfResources[index].NotFirstSecretError = true
			case sslSecretError:
				notFirstError = ingress.NotFirstSSLSecretError
				lbc.listOfResources[index].NotFirstSSLSecretError = true
			case maSecretError:
				notFirstError = ingress.NotFirstMASecretError
				lbc.listOfResources[index].NotFirstMASecretError = true
			}
			break
		}
	}
	return
}

func (lbc *LoadBalancerController) resetFirstErrorFlags(ing *networking.Ingress, scenario string) {
	for index, ingress := range lbc.listOfResources {
		if ingress.Name == ing.ObjectMeta.Name && ingress.Namespace == ing.ObjectMeta.Namespace {
			switch scenario {
			case tlsSecretError:
				lbc.listOfResources[index].NotFirstSecretError = false
			case sslSecretError:
				lbc.listOfResources[index].NotFirstSSLSecretError = false
			case maSecretError:
				lbc.listOfResources[index].NotFirstMASecretError = false
			case allError:
				lbc.listOfResources[index].NotFirstSecretError = false
				lbc.listOfResources[index].NotFirstSSLSecretError = false
				lbc.listOfResources[index].NotFirstMASecretError = false
			}
			break
		}
	}
}

func (lbc *LoadBalancerController) getEndpointsForIstioSvcBackend(istioSvc string, namespace string, targetPort int) ([]string, error) {

	svcObj, err := lbc.getServiceForIstioIngressBackend(istioSvc, namespace)
	if err != nil {
		glog.V(3).Infof("Error getting service %v: %v", istioSvc, err)
		return nil, err
	}
	endps, err := lbc.endpLister.GetServiceEndpoints(svcObj)
	if err != nil {
		glog.V(3).Infof("Error getting endpoints for service %s from the cache: %v", istioSvc, err)
		return nil, err
	}

	var endpoints []string
	targetPortFound := false
	for _, subset := range endps.Subsets {
		for _, port := range subset.Ports {
			if port.Port == int32(targetPort) {
				targetPortFound = true
				for _, address := range subset.Addresses {
					endpoint := fmt.Sprintf("%v:%v", address.IP, port.Port)
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	}

	if !targetPortFound {
		glog.V(3).Infof("Target port %v for the svc %v is not found.", targetPort, istioSvc)
		glog.V(3).Infof("Assigning endpoint %v:%v", "127.0.0.1", "8181")
		endpoint := fmt.Sprintf("%v:%v", "127.0.0.1", "8181")
		endpoints = append(endpoints, endpoint)
	}

	return endpoints, nil
}

func (lbc *LoadBalancerController) getServiceForIstioIngressBackend(istioSvc string, namespace string) (*api.Service, error) {
	svcKey := namespace + "/" + istioSvc

	svcObj, svcExists, err := lbc.svcLister.Store.GetByKey(svcKey)
	if err != nil {
		return nil, err
	}

	if svcExists {
		return svcObj.(*api.Service), nil
	}

	return nil, fmt.Errorf("service %s doesn't exists", svcKey)
}

func (lbc *LoadBalancerController) getNumIngResourceConfFiles() int {
	confdDirectory := "./etc/nginx/conf.d"
	confdFiles := getFiles(confdDirectory)

	streamconfdDirectory := "./streamconf.d"
	streamconfdFiles := getFiles(streamconfdDirectory)

	// total number of ingress files
	return len(confdFiles) + len(streamconfdFiles)
}

// here we are checking if the number of ingress resource conf files
// equals the number of ingress resources
// before starting the pods
func (lbc *LoadBalancerController) checkReadiness() {
	// the timeout for how long we check for new ingress resources is set by seconds
	// to set it, a user will need to write in the `ibm-cloud-provider-ingress-cm`
	// then in the alb deployment we will create an environment variable that points to it
	ingressResourceCreationRate, ingressResourceTimeout := os.Getenv("INGRESS_RESOURCE_CREATION_RATE"), os.Getenv("INGRESS_RESOURCE_TIMEOUT")

	ingressCheckRate := 15             // default is 15 seconds
	totalIngressResourceTimeout := 300 // default for total timeout is 5 min (300 sec)

	if ingressResourceCreationRate != "" {
		if timeout, err := parser.ParseTimeoutToSeconds(ingressResourceCreationRate); err == nil {
			ingressCheckRate = timeout
		}
	}

	if ingressResourceTimeout != "" {
		if timeout, err := parser.ParseTimeoutToSeconds(ingressResourceTimeout); err == nil {
			totalIngressResourceTimeout = timeout
		}
	}

	prevNumIngs := lbc.getNumIngResourceConfFiles()

	totalTimePassed := 0
	for {
		// once more seconds have passed than the total timeout
		// break out of the loop
		if totalTimePassed >= totalIngressResourceTimeout {
			break
		}

		// the ingressCheckRate specifies how long to wait before
		// checking again if the ingress resource conf file are done being created
		time.Sleep(time.Second * time.Duration(ingressCheckRate))
		totalTimePassed += ingressCheckRate

		currNumIngs := lbc.getNumIngResourceConfFiles()

		// if the number of ingress conf files hasn't changed
		// that means that we _should_ be done writing conf files
		if prevNumIngs == currNumIngs {
			createFile("Completed.\n", "/tmp/", "post-start-check.txt")
			return
		}
		prevNumIngs = currNumIngs
	}

	createFile("Timed out.\n", "/tmp/", "post-start-check.txt")
}
