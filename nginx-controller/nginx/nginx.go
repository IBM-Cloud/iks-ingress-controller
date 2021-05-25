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
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/golang/glog"
)

const (
	dhparamFilename = "dhparam.pem"
	dummyHost       = "dummy-k8-fd-ing"

	nginxConfdPath       = "conf.d"
	nginxStreamConfdPath = "streamconf.d"
	nginxCertsPath       = "ssl"

	ingressControllerRoleKey = "ingress_controller_role"
	backendControllerRole    = "backend"

	streamTmpl          = "stream.tmpl"
	kubeSystemALBHealth = "kube-system-alb-health"

	clientKey  = "client.key"
	clientCrt  = "client.crt"
	trustedCrt = "trusted.crt"

	ingressTmpl         = "ingress.tmpl"
	ingressServerTmpl   = "ingress.server.tmpl"
	ingressFrontendTmpl = "ingress.frontend.tmpl"
	ingressBackendTmpl  = "ingress.backend.tmpl"
	indexHTMLTmpl       = "index.html.tmpl"
	defaultConfTmpl     = "default.conf.tmpl"
	defaultPemTmpl      = "default.pem.tmpl"
	nginxConfTmpl       = "nginx.conf.tmpl"
	utilityLuaTmpl      = "utility.lua.tmpl"

	nginxStartCommand  = "nginx"
	nginxTestCommand   = "nginx -t"
	nginxReloadCommand = "nginx -s reload"
	nginxKillCommand   = "kill -USR1 `cat /var/run/nginx.pid`"

	customerLogsEnabledKey              = "CUSTOMER_LOGS_ENABLED"
	customerLogsFilewatcherFrequencyKey = "CUSTOMER_LOGS_FILEWATCHER_FREQUENCY"
	activityTrackerEnabledKey           = "ACTIVITY_TRACKER_ENABLED"

	nginxConf   = "/etc/nginx/nginx.conf"
	indexHTML   = "/var/www/nginx/default/index.html"
	defaultPath = "/var/www/nginx/default"
	defaultConf = "/etc/nginx/conf.d/default.conf"
	defaultPem  = "/etc/nginx/ssl/default.pem"
	sslPath     = "/etc/nginx/ssl"
	utilityLua  = "/usr/local/lib/lua/5.1/utility.lua"
	lua51Path   = "/usr/local/lib/lua/5.1/"

	customerAccessLogs = "/var/log/nginx/customerlogs/customerlogAccess_"
	customerErrorLogs  = "/var/log/nginx/customerlogs/customerlogError_"
)

var (
	ingressPodName = os.Getenv("ARMADA_POD_NAME")
)

// IngressNginxController Updates NGINX configuration, starts and reloads NGINX
type IngressNginxController struct {
	nginxConfdPath       string
	nginxCertsPath       string
	nginxStreamConfdPath string
	local                bool
}

// IngressNginxConfig describes an NGINX configuration
type IngressNginxConfig struct {
	Upstreams             []Upstream
	Servers               []Server
	GlobalRatelimitzones  []RateLimitZone
	ServiceRatelimitzones []RateLimitZone

	// Snort
	SnortEnabled  bool
	SnortUpstream Upstream
}

// RateLimitZone Struct
type RateLimitZone struct {
	Name     string
	Key      string
	Rate     string
	RateUnit string
	Conn     string
	ConnMem  string
	RateMem  string
	Burst    int
}

// Upstream describes an NGINX upstream
type Upstream struct {
	Name             string
	UpstreamServers  []UpstreamServer
	StickyCookie     string
	KeepAlive        int
	LBType           string
	KeepAliveTimeout string
}

// UpstreamServer describes a server in an NGINX upstream
type UpstreamServer struct {
	Address string
	Port    string

	// Upstream HealthCheck
	MaxFails    string
	FailTimeout string
}

// IngressNginxStreamConfigs ...
type IngressNginxStreamConfigs struct {
	StreamConfigs []IngressNginxStreamConfig
	Ups           []Upstream
}

// IngressNginxStreamConfig ...
type IngressNginxStreamConfig struct {
	IngressPort string
	ServiceName string
	ServicePort string
}

// IngressNginxCustomError ...
type IngressNginxCustomError struct {
	HTTPStatus string
	Action     string
}

// CustomErrorActions ...
type CustomErrorActions struct {
	Name  string
	Value []string
}

// Server describes an NGINX server
type Server struct {
	ServerSnippets           []string
	Name                     string
	ServerTokens             bool
	Locations                []Location
	SSL                      bool
	SSLCertificate           string
	SSLCertificateKey        string
	HTTP2                    bool
	RedirectToHTTPS          bool
	ProxyProtocol            bool
	HSTS                     bool
	HSTSMaxAge               int
	HSTSIncludeSubdomains    bool
	ProxyHideHeaders         []string
	ProxyPassHeaders         []string
	GlobalSerRateLimitZones  []RateLimitZone
	LargeClientHeaderBuffers string

	// Port configurations
	HTTPPort             string
	HTTPSPort            string
	MutualAuthPort       string
	SSLClientCertificate string
	MutualAuthPaths      []string
	NonMutualAuthPaths   []string

	// http://nginx.org/en/docs/http/ngx_http_realip_module.html
	RealIPHeader    string
	SetRealIPFrom   []string
	RealIPRecursive bool

	// Watson configurations
	OptionLocation        bool
	WatsonAuthLocation    string
	IamAuthLocation       bool
	IamCliAuthLocation    bool
	IamAllCliAuthLocation bool
	KeepAliveTimeout      string
	KeepAliveRequests     string
	CustomerLogs          bool
	IamLogoutEnabled      bool

	IamGlobalEndpoint string

	// AppID
	AppIDEnabled    bool
	AppIDWebEnabled bool

	// Used for Healthcheck
	IsDefaultHealthcheck bool

	// Used for setting up a default Server
	IsDefaultServer bool

	ErrorActions       []CustomErrorActions
	GlobalCustomErrors []IngressNginxCustomError
}

// Location describes an NGINX location
type Location struct {
	LocationSnippets     []string
	Path                 string
	Upstream             Upstream
	ProxyConnectTimeout  string
	ProxyReadTimeout     string
	ClientMaxBodySize    string
	Websocket            bool
	Rewrite              string
	SSL                  bool
	ProxyMaxTempFileSize string
	RatelimitMemory      string
	RatelimitValue       string
	RatelimitBurst       string
	ActivityTracker      bool
	CustomerLogs         bool
	ProxySetHeaders      []string
	MoreSetHeaders       []string
	MoreClearHeaders     []string
	LocationModifier     string

	//watson configurations
	MapPath             string
	WatsonAuthURL       bool
	WatsonSecondaryHost string
	WatsonSecondarySvc  string
	WatsonUpstream      bool
	AuthCookie          bool
	Options             bool

	// IAM Oauth Configurations
	IamAuthURL        bool
	ClientID          string
	ClientSecret      string
	ClientSecretNS    string
	SvcName           string
	ClientRedirectURL string

	// IAM CLI Configurations
	IamCLIAuthURL    bool
	IamLogoutEnabled bool

	// AppId Configurations
	AppIDSecret      string
	AppIDNameSpace   string
	AppIDRequestType string
	AppIDToken       bool

	//proxy_next_upstream configuration
	ProxyNextUpstreamValues  string
	ProxyNextUpstreamTimeout string
	ProxyNextUpstreamTries   int

	ExternalLocation           bool
	ExternalSvc                string
	ExtDNSResolver             string
	SSLAuthentication          bool
	SSLTwoWayAuthentication    bool
	ProxySslTrustedCertificate string
	ProxySslCertificate        string
	ProxySslCertificateKey     string
	LocationRateLimitZones     []RateLimitZone
	ProxySslVerifyDepth        int
	PlainSSLAuthentication     bool
	ProxySSLName               string

	KeepAliveTimeout    string
	KeepAliveRequests   string
	AllLocationSnippet  []string
	CustomErrors        []IngressNginxCustomError
	ProxyBuffering      bool
	AddHostPort         bool
	ProxyBuffers        ProxyBuffer
	ProxyBufferSize     string
	ProxyBusyBufferSize string

	IstioEnabled        bool
	IstioPort           int64
	IstioIP             string
	StatsdConfigEnabled bool
}

// IngressNginxMainConfig describe the main NGINX configuration file
type IngressNginxMainConfig struct {
	ServerNamesHashBucketSize string
	ServerNamesHashMaxSize    string
	LogFormat                 string
	LogFormatEscapeJSON       string
	VtsStatusZoneSize         string
	HealthStatus              bool
	HTTPSnippets              []string
	InKeepAlive               string
	InKeepaliveRequests       string
	Backlog                   string
	ReusePort                 bool

	// http://nginx.org/en/docs/http/ngx_http_ssl_module.html
	SSLProtocols           string
	SSLPreferServerCiphers bool
	SSLCiphers             string
	SSLDHParam             string
	ActivityTracker        bool
	CustomerLogs           bool
	PodName                string

	// Used to disable default server in default.conf
	IsDefaultServerConf bool

	// Snort
	SnortEnabled  bool
	SnortUpstream Upstream
	//Access Log buffering
	AccessLogEnabled bool
	AccessLogBuffer  string
	AccessLogFlush   string
}

// ProxyBuffer ...
type ProxyBuffer struct {
	Size   string
	Number int
}

var (
	funcMap = template.FuncMap{
		"buildLocation": buildLocation,
	}
)

// Log Watcher frequency management
var logWatcherLock sync.Mutex
var watchFrequency = "5s"

// GetWatchFrequency ...
func GetWatchFrequency() string {
	return watchFrequency
}

// SetWatchFrequency ...
func SetWatchFrequency(watchFrequencyUpdated string) {
	glog.V(3).Infof("Setting watch frequency")
	logWatcherLock.Lock()
	defer logWatcherLock.Unlock()
	watchFrequency = watchFrequencyUpdated
}

// NewUpstreamWithDefaultServer creates an upstream with the default server.
// proxy_pass to an upstream with the default server returns 502.
// We use it for services that have no endpoints
func NewUpstreamWithDefaultServer(name string, stickyCookie string) Upstream {
	return Upstream{
		Name:             name,
		UpstreamServers:  []UpstreamServer{UpstreamServer{Address: "127.0.0.1", Port: "8181"}},
		StickyCookie:     stickyCookie,
		KeepAlive:        64,
		LBType:           "",
		KeepAliveTimeout: "",
	}
}

// NewNginxController creates a NGINX controller
func NewNginxController(nginxConfPath string, local bool, healthStatus bool) (*IngressNginxController, error) {
	ngxc := IngressNginxController{
		nginxConfdPath:       path.Join(nginxConfPath, nginxConfdPath),
		nginxStreamConfdPath: path.Join(nginxConfPath, nginxStreamConfdPath),
		nginxCertsPath:       path.Join(nginxConfPath, nginxCertsPath),
		local:                local,
	}

	if !local {
		createDir(ngxc.nginxCertsPath)
	}
	cfg := &IngressNginxMainConfig{ServerNamesHashMaxSize: NewDefaultConfig().MainServerNamesHashMaxSize, HealthStatus: healthStatus, IsDefaultServerConf: true}

	ingressControllerRole := os.Getenv(ingressControllerRoleKey)
	ngxc.UpdateMainConfigFile(cfg)
	if ingressControllerRole != backendControllerRole {
		ngxc.UpdateIndexHTMLFile(cfg)
		ngxc.UpdateDefaultConfFile(cfg)
		//ngxc.UpdateDefaultPemFile(cfg)

	}
	ngxc.UpdateLuaUtilityFile(cfg)
	return &ngxc, nil
}

// AddOrUpdateIngressStream ...
func (nginx *IngressNginxController) AddOrUpdateIngressStream(name string, StreamConfigs []IngressNginxStreamConfig, upstreams map[string]Upstream) {
	glog.V(3).Infof("Updating NGINX Stream Configuration")
	filename := nginx.getIngressNginxStreamConfigFileName(name)
	var configs IngressNginxStreamConfigs
	configs.StreamConfigs = StreamConfigs
	configs.Ups = upstreamMapToSlice(upstreams)
	nginx.templateItStream(configs, filename)
}
func (nginx *IngressNginxController) getIngressNginxStreamConfigFileName(name string) string {
	return path.Join(nginx.nginxStreamConfdPath, name+".conf")
}
func (nginx *IngressNginxController) templateItStream(configs IngressNginxStreamConfigs, filename string) {
	glog.Infof("streamconfig: %v", configs)
	tmpl, err := template.New(streamTmpl).ParseFiles(streamTmpl)
	if err != nil {
		glog.Fatal("Failed to parse template file")
	}
	if glog.V(3) {
		tmpl.Execute(os.Stdout, configs)
	}
	if !nginx.local {
		w, err := os.Create(filename)
		if err != nil {
			glog.Fatalf("Failed to open %v: %v", filename, err)
		}
		defer w.Close()
		if err := tmpl.Execute(w, configs); err != nil {
			glog.Fatalf("Error Failed to write template %v", err)
		}
	}
	// print conf to stdout in the else loop

	glog.V(3).Infof("NGINX stream configuration file had been updated")
}

// DeleteIngress deletes the configuration file, which corresponds for the
// specified ingress from NGINX conf directory
func (nginx *IngressNginxController) DeleteIngress(name string) {
	filename := nginx.getIngressNginxConfigFileName(name)
	filenameStream := nginx.getIngressNginxStreamConfigFileName(name)

	if !nginx.local {
		RemoveFileIfExist(filename)
		RemoveFileIfExist(filenameStream)
	}
}

// AddOrUpdateIngress creates or updates a file with
// the specified configuration for the specified ingress
func (nginx *IngressNginxController) AddOrUpdateIngress(name string, config IngressNginxConfig) {
	glog.V(3).Infof("Updating NGINX configuration")
	filename := nginx.getIngressNginxConfigFileName(name)
	glog.Infof("AddOrUpdateIngress filename %s", filename)

	//remove dummy config from Upstreams (created by tcp stream)
	var newUpstreams []Upstream
	for _, upstream := range config.Upstreams {
		if !strings.Contains(upstream.Name, dummyHost) {
			newUpstreams = append(newUpstreams, upstream)
		}
	}
	config.Upstreams = newUpstreams

	//remove dummy config from Servers (created by tcp stream)
	var newServers []Server
	for _, server := range config.Servers {
		if !strings.Contains(server.Name, dummyHost) {
			newServers = append(newServers, server)
		}
	}
	config.Servers = newServers

	// Generates the Default Server for Healthcheck. This is created during deployment.
	if name == kubeSystemALBHealth {
		if len(config.Servers) == 1 {
			config.Servers[0].IsDefaultHealthcheck = true
			config.Servers[0].Locations = []Location{}

			nginx.templateIt(config, filename)
		} else {
			glog.Errorf("Couldn't find any Servers in Config %+v", config)
		}
		return
	}

	//if no http config, do not templateIt
	if len(config.Upstreams) == 0 && len(config.Servers) == 0 {
		return
	}

	nginx.templateIt(config, filename)
}

// AddOrUpdateDHParam creates the servers dhparam.pem file
func (nginx *IngressNginxController) AddOrUpdateDHParam(dhparam string) (string, error) {
	fileName := nginx.nginxCertsPath + "/" + dhparamFilename
	if !nginx.local {
		pem, err := os.Create(fileName)
		if err != nil {
			return fileName, fmt.Errorf("Couldn't create file %v: %v", fileName, err)
		}
		defer pem.Close()

		_, err = pem.WriteString(dhparam)
		if err != nil {
			return fileName, fmt.Errorf("Couldn't write to pem file %v: %v", fileName, err)
		}
	}
	return fileName, nil
}

// AddOrUpdateCertAndKey creates a .pem file wth the cert and the key with the
// specified name
func (nginx *IngressNginxController) AddOrUpdateCertAndKey(name string, cert string, key string, ca string) string {
	pemFileName := nginx.nginxCertsPath + "/" + name + ".pem"

	if !nginx.local {
		pem, err := os.Create(pemFileName)
		if err != nil {
			glog.Fatalf("Couldn't create pem file %v: %v", pemFileName, err)
		}
		defer pem.Close()

		if key != "" {
			_, err = pem.WriteString(key)
			if err != nil {
				glog.Fatalf("Couldn't write 'key' to pem file %v: %v", pemFileName, err)
			}

			_, err = pem.WriteString("\n")
			if err != nil {
				glog.Fatalf("Couldn't write 'newline' to pem file %v: %v", pemFileName, err)
			}
		}

		if cert != "" {
			_, err = pem.WriteString(cert)
			if err != nil {
				glog.Fatalf("Couldn't write 'cert' to pem file %v: %v", pemFileName, err)
			}

			_, err = pem.WriteString("\n")
			if err != nil {
				glog.Fatalf("Couldn't write 'newline' to pem file %v: %v", pemFileName, err)
			}
		}

		if ca != "" {
			_, err = pem.WriteString(ca)
			if err != nil {
				glog.Fatalf("Couldn't write 'ca' to pem file %v: %v", pemFileName, err)
			}

			_, err = pem.WriteString("\n")
			if err != nil {
				glog.Fatalf("Couldn't write 'newline' to pem file %v: %v", pemFileName, err)
			}
		}

	}

	return pemFileName
}

// AddOrUpdateTrustedCertAndKey creates a .crt file wth the trusted cert and client cert and client key with the
// specified name
func (nginx *IngressNginxController) AddOrUpdateTrustedCertAndKey(name string, cert string, key string, trustedCert string) (string, string, string) {
	var keyFileName string
	var certFileName string
	var trustedCertFileName string
	if !nginx.local {
		if key != "" {
			keyFileName = nginx.nginxCertsPath + "/" + name + clientKey
			pem, err := os.Create(keyFileName)
			if err != nil {
				glog.Fatalf("Couldn't create key file %v: %v", keyFileName, err)
			}
			defer pem.Close()
			_, err = pem.WriteString(key)
			if err != nil {
				glog.Fatalf("Couldn't write to key file %v: %v", keyFileName, err)
			}

			_, err = pem.WriteString("\n")
			if err != nil {
				glog.Fatalf("Couldn't write to key file %v: %v", keyFileName, err)
			}
		}
		if cert != "" {
			certFileName = nginx.nginxCertsPath + "/" + name + clientCrt
			pem, err := os.Create(certFileName)
			if err != nil {
				glog.Fatalf("Couldn't create crt file %v: %v", certFileName, err)
			}
			defer pem.Close()
			_, err = pem.WriteString(cert)
			if err != nil {
				glog.Fatalf("Couldn't write to crt file %v: %v", certFileName, err)
			}

			_, err = pem.WriteString("\n")
			if err != nil {
				glog.Fatalf("Couldn't write to crt file %v: %v", certFileName, err)
			}
		}
		if trustedCert != "" {
			trustedCertFileName = nginx.nginxCertsPath + "/" + name + trustedCrt
			pem, err := os.Create(trustedCertFileName)
			if err != nil {
				glog.Fatalf("Couldn't create crt file %v: %v", trustedCertFileName, err)
			}
			defer pem.Close()
			_, err = pem.WriteString(trustedCert)
			if err != nil {
				glog.Fatalf("Couldn't write to crt file %v: %v", trustedCertFileName, err)
			}
		}
	}
	return keyFileName, certFileName, trustedCertFileName
}

// AddOrUpdatePemFile creates a .pem file wth the cert and the key with the
// specified name
func (nginx *IngressNginxController) AddOrUpdatePemFile(pemFileName string, content []byte) string {

	if !nginx.local {
		glog.Infof("Writing pemFileName %v", pemFileName)
		pem, err := ioutil.TempFile(nginx.nginxCertsPath, pemFileName)
		glog.Infof("pem is %v", pem)
		if err != nil {
			glog.Fatalf("Couldn't create a temp file for the pem file %v: %v", pemFileName, err)
		}

		_, err = pem.Write(content)
		if err != nil {
			glog.Fatalf("Couldn't write to the temp pem file %v: %v", pem.Name(), err)
		}

		err = pem.Close()
		if err != nil {
			glog.Fatalf("Couldn't close the temp pem file %v: %v", pem.Name(), err)
		}

		err = os.Rename(pem.Name(), pemFileName)
		if err != nil {
			glog.Fatalf("Fail to rename the temp pem file %v to %v: %v", pem.Name(), pemFileName, err)
		}
	} else {
		glog.Infof("Unable to Write pemFileName %v", pemFileName)
	}

	return pemFileName
}

// DeletePemFile deletes the pem file
func (nginx *IngressNginxController) DeletePemFile(pemFileName string) {
	glog.V(3).Infof("deleting %v", pemFileName)

	if !nginx.local {
		if err := os.Remove(pemFileName); err != nil {
			glog.Warningf("Failed to delete %v: %v", pemFileName, err)
		} else {
			glog.V(3).Infof("Cert file %v is deleted", pemFileName)
		}
	}

}
func (nginx *IngressNginxController) getIngressNginxConfigFileName(name string) string {
	return path.Join(nginx.nginxConfdPath, name+".conf")
}

/*
func (nginx *IngressNginxController) getPemFileName(name string) string {
	return path.Join(nginx.nginxCertsPath, name+".pem")
}
*/

func (nginx *IngressNginxController) templateIt(config IngressNginxConfig, filename string) {
	ingressRole := os.Getenv("ingress_controller_role")

	ingressTemplate := ingressTmpl
	serverTemplate := ingressServerTmpl

	// Snort is disabled by default
	config.SnortEnabled = false
	config.SnortUpstream = SnortUpstreamServers

	if ingressRole == FrontendRole {
		ingressTemplate = ingressFrontendTmpl
	} else if ingressRole == "backend" {
		ingressTemplate = ingressBackendTmpl
		config.SnortEnabled = true
	}

	tmpl, err := template.New(ingressTemplate).Funcs(funcMap).ParseFiles(ingressTemplate, serverTemplate)
	if err != nil {
		glog.Fatalf("Failed to parse template file: %v", err)
	}

	glog.V(4).Infof("Writing NGINX conf to %v", filename)

	if glog.V(3) {
		tmpl.Execute(os.Stdout, config)
	}

	if !nginx.local {
		w, err := os.Create(filename)
		if err != nil {
			glog.Fatalf("Failed to open %v: %v", filename, err)
		}
		defer w.Close()

		if err := tmpl.Execute(w, config); err != nil {
			glog.Fatalf("Error Failed to write template %v", err)
		}
	}
	// print conf to stdout in the else loop

	glog.V(3).Infof("NGINX configuration file had been updated")
}

// shellout returns error and warning error
// 1. nginx -t fails, shellout returns err and warning error
// 2. nginx -s reload fails, shellout returns err and warning error
// 3. conflicting server name, shellout returns nil and warning error

// Reload
// does nginx -t, returns if err!=nil
// does nginx -s reload, returns if err!=nil
// success, then return warning error so that can be logged as event

// Reload reloads NGINX
func (nginx *IngressNginxController) Reload() error {
	var err error
	var warningErrorMsg string
	if !nginx.local {
		if _, err = shellOut(nginxTestCommand); err != nil {
			return fmt.Errorf("Invalid nginx configuration detected, not reloading: %s", err)
		}
		if warningErrorMsg, err = shellOut(nginxReloadCommand); err != nil {
			return fmt.Errorf("Reloading NGINX failed: %s", err)
		}
	} else {
		glog.V(3).Info("Reloading nginx")
	}
	// return warning error that needs to be logged in the event
	var warningError error
	if warningErrorMsg != "" {
		warningError = fmt.Errorf(warningErrorMsg)
	} else {
		warningError = nil
	}
	return warningError
}

// Start starts NGINX
func (nginx *IngressNginxController) Start() {

	if os.Getenv(customerLogsEnabledKey) == "true" {
		SetWatchFrequency(os.Getenv(customerLogsFilewatcherFrequencyKey))
		nginx.watchFile()
	}

	if !nginx.local {
		if _, err := shellOut(nginxStartCommand); err != nil {
			glog.Fatalf("Failed to start nginx: %v", err)
		}
	} else {
		glog.V(3).Info("Starting nginx")
	}
}

func createDir(path string) {
	if err := os.Mkdir(path, os.ModeDir); err != nil {
		glog.Fatalf("Couldn't create directory %v: %v", path, err)
	}
}

func shellOut(cmd string) (warningErrorMsg string, err error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	glog.V(4).Infof("executing %s", cmd)

	command := exec.Command("sh", "-c", cmd)
	command.Stdout = &stdout
	command.Stderr = &stderr

	err = command.Start()
	if err != nil {
		return fmt.Sprintf("failed to execute %v, err: %v", cmd, err), fmt.Errorf("failed to execute %v, err: %v", cmd, err)
	}

	err = command.Wait()

	if err != nil {
		return fmt.Sprintf("Command %v stdout: %q\nstderr: %q\nfinished with error: %v", cmd,
				stdout.String(), stderr.String(), err), fmt.Errorf("Command %v stdout: %q\nstderr: %q\nfinished with error: %v", cmd,
				stdout.String(), stderr.String(), err)
	}
	if strings.Contains(stderr.String(), "conflicting server name") { //Trying to use multiple ingress resource files with the same hostname
		warningErrorMsg = fmt.Sprintf("Command %v \nfinished with warning: %v", cmd, stderr.String())
	}
	return warningErrorMsg, nil
}

// UpdateMainConfigFile update the main NGINX configuration file
func (nginx *IngressNginxController) UpdateMainConfigFile(cfg *IngressNginxMainConfig) {
	nginxUpActivitytrackerEnv := strings.ToUpper(os.Getenv(activityTrackerEnabledKey))
	glog.V(4).Infof("nginx_up_activitytracker_env= %v\n", nginxUpActivitytrackerEnv)
	if (nginxUpActivitytrackerEnv == valueFalse) || (nginxUpActivitytrackerEnv != valueTrue) {
		cfg.ActivityTracker = false
	} else {
		cfg.ActivityTracker = true
	}
	glog.V(4).Infof("nginx ActivityTracker config is set to %v\n", cfg.ActivityTracker)

	//customerLogs
	cfg.PodName = ingressPodName
	nginxUpCustomerLogsEnv := os.Getenv(customerLogsEnabledKey)
	glog.V(4).Infof("nginx_up_customerLogs_env= %v\n", nginxUpCustomerLogsEnv)
	if nginxUpCustomerLogsEnv == "false" || os.Getenv(ingressControllerRoleKey) == FrontendRole {
		cfg.CustomerLogs = false
	} else {
		cfg.CustomerLogs = true
		watchFileFrequency := GetWatchFrequency()
		if os.Getenv(customerLogsFilewatcherFrequencyKey) != watchFileFrequency {
			glog.V(3).Infof("Frequency changed to %s ", os.Getenv(customerLogsFilewatcherFrequencyKey))
			SetWatchFrequency(os.Getenv(customerLogsFilewatcherFrequencyKey))
		}
	}
	glog.V(4).Infof("nginx CustomerLogs config is set to %v\n", cfg.CustomerLogs)

	tmpl, err := template.New(nginxConfTmpl).ParseFiles(nginxConfTmpl)
	if err != nil {
		glog.Fatalf("Failed to parse the main config template file: %v", err)
	}

	filename := nginxConf
	glog.V(4).Infof("Writing NGINX conf to %v", filename)

	if glog.V(3) {
		tmpl.Execute(os.Stdout, cfg)
	}

	if !nginx.local {
		w, err := os.Create(filename)
		if err != nil {
			glog.Fatalf("Failed to open %v: %v", filename, err)
		}
		defer w.Close()

		if err := tmpl.Execute(w, cfg); err != nil {
			glog.Fatalf("Failed to write template %v", err)
		}
	}

	glog.V(3).Infof("The main NGINX configuration file had been updated")

	if err := nginx.Reload(); err != nil {
		glog.Warningf("Error reloading NGINX after NGINX configuration was updated: %v", err)
	}
}

// UpdateIndexHTMLFile update the index html file
func (nginx *IngressNginxController) UpdateIndexHTMLFile(cfg *IngressNginxMainConfig) {
	tmpl, err := template.New(indexHTMLTmpl).ParseFiles(indexHTMLTmpl)
	if err != nil {
		glog.Fatalf("Failed to parse the index html template file: %v", err)
	}

	filename := indexHTML
	glog.V(3).Infof("Writing index html to %v", filename)

	if glog.V(3) {
		tmpl.Execute(os.Stdout, cfg)
	}

	if !nginx.local {
		os.MkdirAll(defaultPath, os.ModePerm)
		w, err := os.Create(filename)
		if err != nil {
			glog.Fatalf("Failed to open %v: %v", filename, err)
		}
		defer w.Close()

		if err := tmpl.Execute(w, cfg); err != nil {
			glog.Fatalf("Failed to write test template %v", err)
		}
	}

	glog.V(3).Infof("The index html file had been updated")
}

// UpdateDefaultConfFile update the default conf file
func (nginx *IngressNginxController) UpdateDefaultConfFile(cfg *IngressNginxMainConfig) {
	tmpl, err := template.New(defaultConfTmpl).ParseFiles(defaultConfTmpl)
	if err != nil {
		glog.Fatalf("Failed to parse the default conf template file: %v", err)
	}

	filename := defaultConf
	glog.V(3).Infof("Writing default conf to %v", filename)

	if glog.V(3) {
		tmpl.Execute(os.Stdout, cfg)
	}

	if !nginx.local {
		w, err := os.Create(filename)
		if err != nil {
			glog.Fatalf("Failed to open %v: %v", filename, err)
		}
		defer w.Close()

		if err := tmpl.Execute(w, cfg); err != nil {
			glog.Fatalf("Failed to write template %v", err)
		}
	}

	glog.V(3).Infof("The default conf file had been updated")
}

// UpdateDefaultPemFile update the index html file
func (nginx *IngressNginxController) UpdateDefaultPemFile(cfg *IngressNginxMainConfig) {
	tmpl, err := template.New(defaultPemTmpl).ParseFiles(defaultPemTmpl)
	if err != nil {
		glog.Fatalf("Failed to parse the default pem template file: %v", err)
	}

	filename := defaultPem
	glog.V(3).Infof("Writing default pem to %v", filename)

	if glog.V(3) {
		tmpl.Execute(os.Stdout, cfg)
	}

	if !nginx.local {
		os.MkdirAll(sslPath, os.ModePerm)
		w, err := os.Create(filename)
		if err != nil {
			glog.Fatalf("Failed to open %v: %v", filename, err)
		}
		defer w.Close()

		if err := tmpl.Execute(w, cfg); err != nil {
			glog.Fatalf("Failed to write template %v", err)
		}
	}

	glog.V(3).Infof("The default pem file has been updated")
}

// UpdateLuaUtilityFile update the lua utility file
func (nginx *IngressNginxController) UpdateLuaUtilityFile(cfg *IngressNginxMainConfig) {
	tmpl, err := template.New(utilityLuaTmpl).ParseFiles(utilityLuaTmpl)
	if err != nil {
		glog.Fatalf("Failed to parse the lua utility template file: %v", err)
	}
	filename := utilityLua
	glog.V(3).Infof("Writing lua utility to %v", filename)
	if glog.V(3) {
		tmpl.Execute(os.Stdout, cfg)
	}
	if !nginx.local {
		os.MkdirAll(lua51Path, os.ModePerm)
		w, err := os.Create(filename)
		if err != nil {
			glog.Fatalf("Failed to open %v: %v", filename, err)
		}
		defer w.Close()
		if err := tmpl.Execute(w, cfg); err != nil {
			glog.Fatalf("Failed to write template %v", err)
		}
	}
	glog.V(3).Infof("The lua utility file had been updated")
}

func (nginx *IngressNginxController) watchFile() {
	glog.V(4).Infof("Started watchFile in nginx.go ")
	go func() {
		for {
			if os.Getenv(customerLogsEnabledKey) == "true" {
				if watchLogFileFrequecy, err := strconv.Atoi(strings.TrimRight(GetWatchFrequency(), "s")); err == nil {
					glog.V(4).Infof("watch log file frequency is %v ", watchLogFileFrequecy)
					time.Sleep(time.Duration(watchLogFileFrequecy) * time.Second)
					if ingressPodName != "" {
						accesslogFileName := customerAccessLogs + ingressPodName + ".log"
						if _, accessLogFileErr := os.Stat(accesslogFileName); accessLogFileErr != nil {
							glog.V(3).Infof("Recreating the log file since deleted the customerAccesslogs file ")
							_, shellAccessLogErr := shellOut(nginxKillCommand)
							if shellAccessLogErr != nil {
								glog.V(3).Infof("nginx kill -USR1 cmd is executed with error")
							}
						}
						errorlogFileName := customerErrorLogs + ingressPodName + ".log"
						if _, errorLogFileErr := os.Stat(errorlogFileName); errorLogFileErr != nil {
							glog.V(3).Infof("Recreating the log file since deleted the customerErrorlogs file ")
							_, shellErrorLogErr := shellOut(nginxKillCommand)
							if shellErrorLogErr != nil {
								glog.V(3).Infof("nginx kill -USR1 cmd is executed with error")
							}
						}
					}
				}
			}
		}
	}()
}
