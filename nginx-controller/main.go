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

package main

import (
	"flag"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"syscall"

	"github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/controller"
	"github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/internal"
	"github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/nginx"
	"github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser"
	"github.com/golang/glog"

	api "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var (
	// Set during build
	version string

	healthStatus = flag.Bool("health-status", false,
		`If present, the default server listening on port 80 with the health check
		location "/nginx-health" gets added to the main nginx configuration.`)

	proxyURL = flag.String("proxy", "",
		`If specified, the controller assumes a kubctl proxy server is running on the
		given url and creates a proxy client. Regenerated NGINX configuration files
    are not written to the disk, instead they are printed to stdout. Also NGINX
    is not getting invoked. This flag is for testing.`)

	watchNamespace = flag.String("watch-namespace", api.NamespaceAll,
		`Namespace to watch for Ingress/Services/Endpoints. By default the controller
		watches acrosss all namespaces`)

	nginxConfigMaps = flag.String("nginx-configmaps", "",
		`Specifies a configmaps resource that can be used to customize NGINX
		configuration. The value must follow the following format: <namespace>/<name>`)
)

const (
	healthCheckURL = "http://localhost/ibmhealthcheck"
)

func main() {
	flag.Parse()

	glog.Infof("Starting NGINX Ingress controller Version %v\n", version)

	if (os.Getenv("ALB_ID") == "") || (strings.Contains(os.Getenv("ALB_ID"), "public")) || (strings.Contains(os.Getenv("ALB_ID"), "pubids")) {
		os.Setenv("ingress_alb_type", "public")
	} else {
		os.Setenv("ingress_alb_type", "non_public")
	}
	glog.V(4).Infof("Ingress alb type %v\n", os.Getenv("ingress_alb_type"))
	glog.Infof("Ingress ALB_ID %v\n", os.Getenv("ALB_ID"))

	if os.Getenv("ACTIVITY_TRACKER_ENABLED") == "" {
		os.Setenv("ACTIVITY_TRACKER_ENABLED", "false")
	}
	glog.V(4).Infof("ACTIVITY_TRACKER_ENABLED %v\n", os.Getenv("ACTIVITY_TRACKER_ENABLED"))

	os.Setenv("EXT_DNS_RESOLVER", "8.8.8.8")
	glog.Infof("EXT_DNS_RESOLVER %v\n", os.Getenv("EXT_DNS_RESOLVER"))

	if os.Getenv("ingress_controller_role") == "" {
		os.Setenv("ingress_controller_role", "default")
	}
	glog.Infof("Ingress controller role %v\n", os.Getenv("ingress_controller_role"))

	if (os.Getenv("ingress_controller_role") != "backend") && (os.Getenv("ingress_controller_role") != "default") {
		os.Setenv("ACTIVITY_TRACKER_ENABLED", "false")
	}

	if os.Getenv("ingress_controller_role") == nginx.FrontendRole {
		os.Setenv("CUSTOMER_LOGS_ENABLED", "false")
	} else {
		os.Setenv("CUSTOMER_LOGS_ENABLED", "true")
		os.Setenv("CUSTOMER_LOGS_FILEWATCHER_FREQUENCY", "5s")
	}

	if os.Getenv("SECURED_NAMESPACE") == "" {
		os.Setenv("SECURED_NAMESPACE", "ibm-cert-store")
	}

	var err error
	var config *rest.Config
	if *proxyURL != "" {
		if config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{},
			&clientcmd.ConfigOverrides{
				ClusterInfo: clientcmdapi.Cluster{
					Server: *proxyURL,
				}}).ClientConfig(); err != nil {
			glog.Fatalf("error creating client configuration: %v", err)
		}
	} else {
		if config, err = rest.InClusterConfig(); err != nil {
			glog.Fatalf("error creating client configuration: %v", err)
		}
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		glog.Fatalf("Failed to create client: %v.", err)
	}

	internal.IsNetworkingIngressAvailable = internal.NetworkingIngressAvailable(kubeClient)
	if !internal.IsNetworkingIngressAvailable {
		glog.Warningf("Using deprecated \"k8s.io/api/extensions/v1beta1\" package because Kubernetes version is < v1.14.0")
	}

	local := *proxyURL != ""

	glog.Infof("The config-map loaded is: %v\n", *nginxConfigMaps)

	ngxc, _ := nginx.NewNginxController("/etc/nginx/", local, *healthStatus)
	parser.Prepare()
	ngxc.Start()
	go startHealthCheck()
	nginxConfig := nginx.NewDefaultConfig()
	cnf := nginx.NewConfigurator(ngxc, nginxConfig, kubeClient)
	lbc, _ := controller.NewLoadBalancerController(kubeClient, 30*time.Second, *watchNamespace, cnf, *nginxConfigMaps)
	go handleTermination(lbc)
	lbc.Run()
}

func startHealthCheck() {
	//run health check every 30 seconds
	ticker := time.NewTicker(time.Second * 30)
	glog.Infof("Starting health check monitoring...")
	count := 0

	//set http.Get timeout to 3 seconds
	timeout := time.Duration(3 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}

	for range ticker.C {
		resp, err := client.Get(healthCheckURL)
		if (err == nil) && (resp.StatusCode == 200) && !isMasterNginxZombie() {
			count = 0
			resp.Body.Close()
		} else {
			count++
			glog.Infof("Health check(%s) fails %d", healthCheckURL, count)
		}
		if count == 3 {
			glog.Infof("Health check has failed %d times, exiting...", count)
			os.Exit(0)
		}
	}
}

func isMasterNginxZombie() bool {
	processIDBytes, err := ioutil.ReadFile("/var/run/nginx.pid")
	if err != nil {
		glog.Infof("Failed to read /var/run/nginx.pid: %s\n", err)
		return false
	}

	processIDString := string(processIDBytes)
	processIDStateFile, err := ioutil.ReadFile("/proc/" + strings.TrimSpace(processIDString) + "/stat")
	if err != nil {
		glog.Infof("Failed to read nginx process ID stat file: %s\n", err)
		return false
	}

	processIDStateString := string(processIDStateFile)
	nginxSTATFields := strings.Split(processIDStateString, " ")
	if len(nginxSTATFields) < 3 {
		glog.Info("Unexpected nginx process stat file format")
		return false
	}
	return strings.Contains(nginxSTATFields[2], "Z")
}

func handleTermination(lbc *controller.LoadBalancerController) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM)

	select {
	case <-signalChan:
		glog.Infof("Received SIGTERM, shutting down")
	}

	exitStatus := 0
	glog.Infof("Shutting down the controller")
	lbc.Stop()

	glog.Infof("Exiting with a status: %v", exitStatus)
	os.Exit(exitStatus)
}
