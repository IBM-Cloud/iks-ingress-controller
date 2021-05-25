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
	"flag"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser"
	"github.com/golang/glog"
	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	flag.Lookup("logtostderr").Value.Set("true")
}

func TestPathOrDefaultReturnDefault(t *testing.T) {
	path := ""
	expected := "/"
	if pathOrDefault(path) != expected {
		t.Errorf("pathOrDefault(%q) should return %q", path, expected)
	}
}

func TestPathOrDefaultReturnActual(t *testing.T) {
	path := "/path/to/resource"
	if pathOrDefault(path) != path {
		t.Errorf("pathOrDefault(%q) should return %q", path, path)
	}
}

func TestParseRewrites(t *testing.T) {
	serviceName := "coffee-svc"
	serviceNamePart := "serviceName=" + serviceName
	rewritePath := "/beans/"
	rewritePathPart := "rewrite=" + rewritePath
	rewriteService := serviceNamePart + " " + rewritePathPart

	serviceNameActual, rewritePathActual, err := parseRewrites(rewriteService)
	if serviceName != serviceNameActual || rewritePath != rewritePathActual || err != nil {
		t.Errorf("parseRewrites(%s) should return %q, %q, nil; got %q, %q, %v", rewriteService, serviceName, rewritePath, serviceNameActual, rewritePathActual, err)
	}
}

func TestParseRewritesInvalidFormat(t *testing.T) {
	rewriteService := "serviceNamecoffee-svc rewrite=/"

	_, _, err := parseRewrites(rewriteService)
	if err == nil {
		t.Errorf("parseRewrites(%s) should return error, got nil", rewriteService)
	}
}
func TestParseStreamConfigs(t *testing.T) {
	annotationStr := "ingressPort=80 serviceName=tea-svc servicePort=8080;ingressPort=81 serviceName=coffee-svc servicePort=8081"
	streams, err := ParseStreamConfigs(annotationStr)
	if err != nil {
		t.Errorf("error:%s", err)
	}
	if streams[0].IngressPort != "80" || streams[0].ServiceName != "tea-svc" || streams[0].ServicePort != "8080" ||
		streams[1].IngressPort != "81" || streams[1].ServiceName != "coffee-svc" || streams[1].ServicePort != "8081" {

		t.Errorf("parseStreamConfigs(%s) test failed", "")
	}
}

func TestParseStickyService(t *testing.T) {
	serviceName := "coffee-svc"
	serviceNamePart := "serviceName=" + serviceName
	stickyCookie := "name=srv_id expires=1h domain=.example.com path=/"
	stickyService := serviceNamePart + " " + stickyCookie

	serviceNameActual, stickyCookieActual, err := parseStickyService(stickyService)
	if serviceName != serviceNameActual || stickyCookie != stickyCookieActual || err != nil {
		t.Errorf("parseStickyService(%s) should return %q, %q, nil; got %q, %q, %v", stickyService, serviceName, stickyCookie, serviceNameActual, stickyCookieActual, err)
	}
}

func TestParseStickyServiceInvalidFormat(t *testing.T) {
	stickyService := "serviceNamecoffee-svc name=srv_id expires=1h domain=.example.com path=/"

	_, _, err := parseStickyService(stickyService)
	if err == nil {
		t.Errorf("parseStickyService(%s) should return error, got nil", stickyService)
	}
}

func TestParsePortsValidFormat(t *testing.T) {
	resourceName := "ok-ingress"
	portAnnotationLabel := "ingress.bluemix.net/custom-port"
	portAnnotation := "protocol=http port=8001"
	serverName := "cafe.ok.com"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(portAnnotationLabel, portAnnotation); err != nil {
		t.Errorf("In contains invalid should return %s but returned %v", portAnnotation, annotationEntryModel)
	} else {
		parsedPorts, _ := handleCustomPort(annotationEntryModel, resourceName, serverName)
		protocols := parsedPorts[serverName]
		for _, protocol := range protocols {
			if protocol.Protocol != "http" {
				t.Errorf("Values in %v were not parsed correctly. (protocol)", portAnnotation)
			}
			if protocol.Port != "8001" {
				t.Errorf("Values in %v were not parsed correctly. (port)", portAnnotation)
			}
		}
	}
}

func TestLargeClientHeaderBuffersValidFormat(t *testing.T) {
	AnnotationLabel := "ingress.bluemix.net/large-client-header-buffers"
	Annotation := "number=2 size=2k"
	serverName := "cafe.ok.com"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation); err != nil {
		t.Errorf("In contains invalid should return %s but returned %v", Annotation, annotationEntryModel)
	} else {

		entries, _ := handleLargeClientHeaderBuffers(annotationEntryModel, serverName)
		buffers := entries[serverName]

		if buffers != "2 2k" {
			t.Errorf("Values in %+v were not parsed correctly.", entries)
		}

	}
}

func TestParseMutualAuthValidFormat(t *testing.T) {
	resourceName := "ok-ingress"
	mutualAuthAnnotationLabel := "ingress.bluemix.net/mutual-auth"
	mutualAuthAnnotation := "port=8001 secretName=secret1"
	serverName := "cafe.ok.com"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(mutualAuthAnnotationLabel, mutualAuthAnnotation); err != nil {
		t.Errorf("In contains invalid should return %s but returned %v", mutualAuthAnnotation, annotationEntryModel)
	} else {
		mutualAuthValue, _, _ := HandleMutualAuth(annotationEntryModel, resourceName, serverName)
		if mutualAuthValue["cafe.ok.com"][0] != "8001" {
			t.Errorf("Values in %v were not parsed correctly (Ports).", mutualAuthAnnotation)
		}
		if mutualAuthValue["cafe.ok.com"][1] != "secret1" {
			t.Errorf("Values in %v were not parsed correctly. (Secret Name)", mutualAuthAnnotation)
		}
	}
}

func TestParseMutualAuthValidFormatwithPaths(t *testing.T) {
	resourceName := "ok-ingress"
	mutualAuthAnnotationLabel := "ingress.bluemix.net/mutual-auth"
	mutualAuthAnnotation := "port=8001 secretName=secret1 serviceName=tea-svc,coffee-svc"
	serverName := "cafe.ok.com"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(mutualAuthAnnotationLabel, mutualAuthAnnotation); err != nil {
		t.Errorf("In contains invalid should return %s but returned %v", mutualAuthAnnotation, annotationEntryModel)
	} else {
		mutualAuthValue, mutualAuthPaths, _ := HandleMutualAuth(annotationEntryModel, resourceName, serverName)
		if mutualAuthValue["cafe.ok.com"][0] != "8001" {
			t.Errorf("Values in %v were not parsed correctly (Ports).", mutualAuthAnnotation)
		}
		if mutualAuthValue["cafe.ok.com"][1] != "secret1" {
			t.Errorf("Values in %v were not parsed correctly. (Secret Name)", mutualAuthAnnotation)
		}
		validMutualAuthPaths := []string{"tea-svc", "coffee-svc"}
		if !reflect.DeepEqual(mutualAuthPaths, validMutualAuthPaths) {
			t.Errorf("Values in %v were not parsed correctly. (Paths), Expected %+v but got %+v", mutualAuthAnnotation, validMutualAuthPaths, mutualAuthPaths)
		}
	}
}

func TestHandleLocProxyTimeout(t *testing.T) {
	annotationLable := "ingress.bluemix.net/proxy-read-timeout"
	annotationStr := "serviceName=bean-svc timeout=10s;serviceName=tea-svc,coffee-svc timeout=20s"
	serviceName := "tea-svc"
	expectedTimeout := "20s"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(annotationLable, annotationStr); err != nil {
		t.Errorf("In contains invalid return %s but returned %v", annotationStr, annotationEntryModel)
	} else {
		locProxyTimeoutValue, _ := handleLocProxyTimeout(annotationEntryModel, serviceName)
		if locProxyTimeoutValue != expectedTimeout {
			t.Errorf("getLocProxyTimeout should return %s but returned %s", expectedTimeout, locProxyTimeoutValue)
		}
	}

}

func TestHandleLocClientMaxBodySize(t *testing.T) {
	annotationLable := "ingress.bluemix.net/client-max-body-size"
	annotationStr := "serviceName=bean-svc size=10m;serviceName=tea-svc,coffee-svc size=20m"
	serviceName := "tea-svc"
	expectedMaxBodySize := "20m"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(annotationLable, annotationStr); err != nil {
		t.Errorf("In contains invalid return %s but returned %v", annotationStr, annotationEntryModel)
	} else {
		clientMaxBodySize, _ := handleLocClientMaxBodySize(annotationEntryModel, serviceName)
		if clientMaxBodySize != expectedMaxBodySize {
			t.Errorf("getLocClientMaxBodySize should return %s but returned %s", expectedMaxBodySize, clientMaxBodySize)
		}
	}

}

func TestParseIndividualIamService(t *testing.T) {
	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	serviceName := "coffee-svc"
	serviceNamePart := "serviceName=" + serviceName
	clientID := "sfsawoierjaofj"
	clientIDPart := "clientId=" + clientID
	clientSecret := "kubeClientSecretRef"
	clientSecretPart := "clientSecret=" + clientSecret
	clientSecretNS := "default"
	clientSecretNSPart := "clientSecretNamespace=" + clientSecretNS
	redirectURL := "http://test.com"
	redirectURLPart := "redirectURL=" + redirectURL

	//"serviceName=frap-svc-k8ns-test clientId=sfsawoierjaofj clientSecret=kubeClientSecretRef redirectURL=http://test.com; serviceName=latte-svc-k8ns-test clientId=2sfsawoierjaofj clientSecret=kubeClientSecretRef2 redirectURL=http://test2.com"
	annotationString := serviceNamePart + " " + clientIDPart + " " + clientSecretPart + " " + clientSecretNSPart + " " + redirectURLPart
	serviceNameActual, clientIDActual, clientSecretActual, clientSecretNSActual, redirectActual, enableAll, err := parseIamUIService(annotationString)
	t.Log("serviceNameActual", serviceNameActual)
	t.Log("clientIdActual", clientIDActual)
	t.Log("clientSecretActual", clientSecretActual)
	t.Log("clientSecretNSActual", clientSecretNSActual)
	t.Log("redirectActual", redirectActual)

	if enableAll || !serviceNameActual[serviceName] || clientIDActual[serviceName] != clientID || clientSecretActual[serviceName] != clientSecret || clientSecretNSActual[serviceName] != clientSecretNS || redirectActual[serviceName] != redirectURL || err != nil {
		t.Errorf("parseGenericIamService(%s) should return %s, %s, %s, %s, %s nil; got %v, %v, %v, %v, %v, %v",
			annotationString, serviceName, clientID, clientSecret, clientSecretNS, redirectURL, serviceNameActual, clientIDActual, clientSecretActual, clientSecretNSActual, redirectActual, err)
	}
}

func TestParseEnableAllIamService(t *testing.T) {
	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	clientID := "sfsawoierjaofj"
	clientIDPart := "clientId=" + clientID
	clientSecret := "kubeClientSecretRef"
	clientSecretPart := "clientSecret=" + clientSecret
	clientSecretNS := "default"
	clientSecretNSPart := "clientSecretNamespace=" + clientSecretNS
	redirectURL := "http://test.com"
	redirectURLPart := "redirectURL=" + redirectURL

	//"serviceName=frap-svc-k8ns-test clientId=sfsawoierjaofj clientSecret=kubeClientSecretRef redirectURL=http://test.com; serviceName=latte-svc-k8ns-test clientId=2sfsawoierjaofj clientSecret=kubeClientSecretRef2 redirectURL=http://test2.com"
	annotationString := clientIDPart + " " + clientSecretPart + " " + clientSecretNSPart + " " + redirectURLPart
	serviceNameActual, clientIDActual, clientSecretActual, clientSecretNSActual, redirectActual, enableAll, err := parseIamUIService(annotationString)
	t.Log("clientIdActual", clientIDActual)
	t.Log("clientSecretActual", clientSecretActual)
	t.Log("clientSecretNSActual", clientSecretNSActual)
	t.Log("redirectActual", redirectActual)

	if !enableAll || len(serviceNameActual) != 0 || clientIDActual[AllIngressServiceName] != clientID || clientSecretActual[AllIngressServiceName] != clientSecret || clientSecretNSActual[AllIngressServiceName] != clientSecretNS || redirectActual[AllIngressServiceName] != redirectURL || err != nil {
		t.Errorf("parseGenericIamService(%s) should return %s, %s, %s, %s, %s nil; got %v, %v, %v, %v, %v, %v",
			annotationString, AllIngressServiceName, clientID, clientSecret, clientSecretNS, redirectURL, serviceNameActual, clientIDActual, clientSecretActual, clientSecretNSActual, redirectActual, err)
	}
}

func TestParseProxyNextUpstream(t *testing.T) {
	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")
	serviceName := "coffee-svc"
	timeout := "40s"
	retries := 5

	serviceName2 := "tea-svc"
	timeout2 := "30s"
	retries2 := 3

	proxyUpstreamString := "serviceName=" + serviceName + " timeout=" + timeout + " retries=5" + " error=true" + ";" + "serviceName=" + serviceName2 + " timeout=" + timeout2 + " retries=3 http_502=true http_403=true"
	t.Log("proxyUpstreamString", proxyUpstreamString)

	proxyUpstreamValues, proxyUpstreamTimeout, proxyUpstreamTries, err := parseProxyNextUpstream(proxyUpstreamString)
	if err != nil {
		t.Error("parseProxyNextUpstream got an err", err)
	}
	t.Logf("proxyUpstreamValues=%+v, proxyUpstreamTimeout=%+v,proxyUpstreamTries=%+v", proxyUpstreamValues, proxyUpstreamTimeout, proxyUpstreamTries)
	t.Logf("serviceName(%s) values =%s, timeout= %s, retries=%d", serviceName, proxyUpstreamValues[serviceName], proxyUpstreamTimeout[serviceName], proxyUpstreamTries[serviceName])
	t.Logf("serviceName(%s) values =%s, timeout= %s, retries=%d", serviceName2, proxyUpstreamValues[serviceName2], proxyUpstreamTimeout[serviceName2], proxyUpstreamTries[serviceName2])

	if proxyUpstreamValues[serviceName] != "timeout error" || proxyUpstreamValues[serviceName2] != "timeout http_502 http_403" ||
		proxyUpstreamTimeout[serviceName] != timeout || proxyUpstreamTimeout[serviceName2] != timeout2 ||
		proxyUpstreamTries[serviceName] != retries || proxyUpstreamTries[serviceName2] != retries2 {
		t.Errorf("parseProxyNextUpstream got an error with one of the parsed values")
	}
}

func TestParseSingleIAMCli(t *testing.T) {
	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")
	serviceName := "coffee-svc"
	serviceName2 := "tea-svc"

	singleIamString := "serviceName=" + serviceName + " enabled=true; enabled=true serviceName=" + serviceName2
	enabledSvcName, enabledAll, err := parseIamCLIService(singleIamString)
	if err != nil {
		t.Error("parseIamCLIService got an err", err)
	}
	t.Logf("enabledSvcName=%v, enabledAll=%v", enabledSvcName, enabledAll)
	if !enabledSvcName[serviceName] || enabledAll || !enabledSvcName[serviceName2] {
		t.Error("parseIamCLIService got an error with one of the parsed values")
	}
}

func TestParseAllIAMCli(t *testing.T) {
	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")
	generalIamString := "enabled=true"
	enabledSvcName, enabledAll, err := parseIamCLIService(generalIamString)
	if err != nil {
		t.Error("parseIamCLIService got an err", err)
	}
	t.Logf("enabledSvcName=%v, enabledAll=%v", enabledSvcName, enabledAll)
	if len(enabledSvcName) != 0 || !enabledAll {
		t.Error("parseIamCLIService got an error with one of the parsed values")
	}
}

func TestParseGlobalCustomErrs(t *testing.T) {
	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")
	errorString := "errorActionName=/test httpError=404,401"
	customLocErrors, globalCustomErrors, err := parseCustomErrors(errorString)
	if err != nil {
		t.Error("parseCustomErrors got an err", err)
	}
	t.Logf("customLocErrors=%v, globalCustomErrors=%v", customLocErrors, globalCustomErrors)
	if len(customLocErrors) != 0 || globalCustomErrors[0].HTTPStatus != "401 404" || globalCustomErrors[0].Action != "/test" {
		t.Errorf("parseIamCLIService got an error with one of the parsed values, len(customLocErrors)= %d  globalCustomErrors[0].HttpStatus = %v,globalCustomErrors[0].Action =%v ",
			len(customLocErrors), globalCustomErrors[0].HTTPStatus, globalCustomErrors[0].Action)
	}
}

func TestParseLocalCustomErrs(t *testing.T) {
	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")
	errorString := "errorActionName=/test httpError=404,401 serviceName=mysvc; serviceName=mysvc errorActionName=/test2 httpError=304, 301"
	customLocErrors, globalCustomErrors, err := parseCustomErrors(errorString)
	if err != nil {
		t.Error("parseCustomErrors got an err", err)
	}
	t.Logf("customLocErrors=%v, globalCustomErrors=%v", customLocErrors, globalCustomErrors)
	if len(globalCustomErrors) != 0 || customLocErrors["mysvc"][0].HTTPStatus != "401 404" || customLocErrors["mysvc"][0].Action != "/test" || customLocErrors["mysvc"][1].HTTPStatus != "301 304" || customLocErrors["mysvc"][1].Action != "/test2" {
		t.Errorf("parseIamCLIService got an error with one of the parsed values")
		t.Errorf("parseIamCLIService got len(globalCustomErrors)=%d customLocErrors[mysvc][0].HttpStatus=%v customLocErrors[mysvc][0].Action=%v customLocErrors[mysvc][1].HttpStatus=%v customLocErrors[mysvc][1].Action=%v",
			len(globalCustomErrors), customLocErrors["mysvc"][0].HTTPStatus, customLocErrors["mysvc"][0].Action, customLocErrors["mysvc"][1].HTTPStatus, customLocErrors["mysvc"][1].Action)
	}
}

func TestParseLocalGlobalCustomErrs(t *testing.T) {
	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")
	errorString := "errorActionName=/test httpError=404,401 serviceName=mysvc; errorActionName=/test2 httpError=304,301 "
	customLocErrors, globalCustomErrors, err := parseCustomErrors(errorString)
	if err != nil {
		t.Error("parseCustomErrors got an err", err)
	}
	t.Logf("customLocErrors=%v, globalCustomErrors=%v", customLocErrors, globalCustomErrors)
	if customLocErrors["mysvc"][0].HTTPStatus != "401 404" || customLocErrors["mysvc"][0].Action != "/test" || globalCustomErrors[0].HTTPStatus != "301 304" || globalCustomErrors[0].Action != "/test2" {
		t.Errorf("parseIamCLIService got an error with one of the parsed values")
		t.Errorf("parseIamCLIService got customLocErrors[mysvc][0].HttpStatus=%v customLocErrors[mysvc][0].Action=%v globalCustomErrors[0].HttpStatus=%v globalCustomErrors[0].Action=%v",
			customLocErrors["mysvc"][0].HTTPStatus, customLocErrors["mysvc"][0].Action, globalCustomErrors[0].HTTPStatus, globalCustomErrors[0].Action)
	}
}

func TestHandleGlobalRatelimitzones(t *testing.T) {
	annotationLable := "ingress.bluemix.net/global-rate-limit"
	annotationStr := "key=location rate=10r/s conn=12"
	expectedRate := "5"
	expectedConn := "6"
	ingressPodCount := 2
	ingressName := "ratelimit_ingress"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(annotationLable, annotationStr); err != nil {
		t.Errorf("In contains invalid return %s but returned %v ", annotationStr, annotationEntryModel)
	} else {
		globalRatelimit, _ := handleGlobalRatelimitzones(annotationEntryModel, ingressPodCount, ingressName)
		if globalRatelimit[0].Conn != expectedConn {
			t.Errorf("getGlobalRatelimitzones should return %s but returned %v", expectedConn, globalRatelimit)
		}
		if globalRatelimit[0].Rate != expectedRate {
			t.Errorf("getGlobalRatelimitzones should return %s but returned %v", expectedRate, globalRatelimit)
		}
	}
}

func TestGetGlobalZoneName(t *testing.T) {
	gKey := "$http_user"
	uniqueGlobalZonenameCount := 1
	ingressName := "ratelimit_ingress"
	expectedGlobalZoneName := "ratelimit_ingress_http_user_1"
	globalZoneName := getGlobalZoneName(gKey, uniqueGlobalZonenameCount, ingressName)
	if globalZoneName != expectedGlobalZoneName {
		t.Errorf("getGlobalZoneName should return %s but returned %s", expectedGlobalZoneName, globalZoneName)
	}
}

func TestHandleLocRateLimitZones(t *testing.T) {
	annotationLable := "ingress.bluemix.net/service-rate-limit"
	annotationStr := "serviceName=coffee-svc key=$http_x_user_id rate=50r/s conn=20;serviceName=tea-svc key=location rate=10r/s conn=10"
	serviceName := "tea-svc"
	expectedRate := "5"
	ingressPodCount := 2
	ingressName := "ratelimit_ingress"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(annotationLable, annotationStr); err != nil {
		t.Errorf("In contains invalid return %s but returned %v", annotationStr, annotationEntryModel)
	} else {
		serviceratelimits, _ := handleLocRateLimitZones(annotationEntryModel, ingressPodCount, ingressName)
		locationRateLimitZones := getRatelimitZonesForService(serviceratelimits, serviceName)
		if locationRateLimitZones[0].Rate != expectedRate {
			t.Errorf("handleLocRateLimitZones should return %s but returned %v", expectedRate, serviceratelimits)
		}
	}
}

func TestGetZoneName(t *testing.T) {
	serviceNames := "tea-svc_coffe-svc"
	keyVal := "$http_user_id"
	ZoneEntryCount := 1
	ingressName := "ratelimit_ingress"
	expecteZoneName := "tea-svc_coffe-svc_http_user_id_1_ratelimit_ingress"
	zoneName := getZoneName(serviceNames, keyVal, ZoneEntryCount, ingressName)
	if zoneName != expecteZoneName {
		t.Errorf("getZoneName should return %s but returned %s", expecteZoneName, zoneName)
	}
}

func TestGetBurst(t *testing.T) {
	rate := 40
	expectedBurst := 8
	burst := getBurst(rate)
	if burst != expectedBurst {
		t.Errorf("getBurst should return %v but returned %v", expectedBurst, burst)
	}
}

func TestGetClusterwideVal(t *testing.T) {
	rate := 40
	ingressPodCount := 2
	expectedVal := "20"
	val := getClusterwideVal(rate, ingressPodCount)
	if val != expectedVal {
		t.Errorf("getClusterwideVal should return %s but returned %s", expectedVal, val)
	}
}

func TestGetMemory(t *testing.T) {
	rate := 40
	serviceCount := 2
	expectedVal := "1m"
	val := getMemory(rate, serviceCount)
	if val != expectedVal {
		t.Errorf("getMemory should return %s but returned %s", expectedVal, val)
	}
}

func TestHandleLocProxyBuffering(t *testing.T) {
	annotationLable := "ingress.bluemix.net/proxy-buffering"
	annotationStr := "serviceName=bean-svc enabled=false;serviceName=tea-svc,coffee-svc enabled=false"
	serviceName := "tea-svc"
	expectedBuffering := false

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(annotationLable, annotationStr); err != nil {
		t.Errorf("In contains invalid return %s but returned %v ", annotationStr, annotationEntryModel)
	} else {
		locProxyBufferingValue, _ := handleLocProxyBuffering(annotationEntryModel, serviceName)
		if locProxyBufferingValue != expectedBuffering {
			t.Errorf("handleLocProxyBuffering should return %v but returned %v", expectedBuffering, locProxyBufferingValue)
		}
	}
}

func TestHandleLocHostPort(t *testing.T) {
	annotationLable := "ingress.bluemix.net/add-host-port"
	annotationStr := "serviceName=bean-svc enabled=false;serviceName=tea-svc,coffee-svc enabled=false"
	serviceName := "tea-svc"
	expectedHostPortValue := false

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(annotationLable, annotationStr); err != nil {
		t.Errorf("In contains invalid return %s but returned %v ", annotationStr, annotationEntryModel)
	} else {
		locHostPortValue, _ := handleLocHostPort(annotationEntryModel, serviceName)
		if locHostPortValue != expectedHostPortValue {
			t.Errorf("handleLocHostPort should return %v but returned %v", expectedHostPortValue, locHostPortValue)
		}
	}
}

func TestHandleLocProxyBufferingAll(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/proxy-buffering"
	annotationStr := "enabled=true"
	serviceName := "tea-svc"
	expectedBuffering := true

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(annotationLabel, annotationStr); err != nil {
		t.Errorf("In contains invalid return %s but returned %v", annotationStr, annotationEntryModel)
	} else {
		locProxyBufferingValue, _ := handleLocProxyBuffering(annotationEntryModel, serviceName)
		if locProxyBufferingValue != expectedBuffering {
			t.Errorf("handleLocProxyBuffering should return %v but returned %v", expectedBuffering, locProxyBufferingValue)
		}
	}
}

func TestHandleLocProxyBufferingKeyless(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/proxy-buffering"
	annotationStr := "true"
	serviceName := "tea-svc"
	expectedBuffering := true

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(annotationLabel, annotationStr); err != nil {
		t.Errorf("In contains invalid return %s but returned %v", annotationStr, annotationEntryModel)
	} else {
		locProxyBufferingValue, _ := handleLocProxyBuffering(annotationEntryModel, serviceName)
		if locProxyBufferingValue != expectedBuffering {
			t.Errorf("handleLocProxyBuffering should return %v but returned %v", expectedBuffering, locProxyBufferingValue)
		}
	}
}

func TestHSTSValidFormat(t *testing.T) {
	AnnotationLabel := "ingress.bluemix.net/hsts"
	Annotation := "enabled=true"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation); err != nil {
		t.Errorf("In contains invalid should return %+v but returned %+v", Annotation, annotationEntryModel)
	} else {

		enabled, maxAge, includeSubdomains, err := handleHSTS(annotationEntryModel)

		if enabled != true {
			t.Errorf("Values in %+v were not parsed correctly.", enabled)
		}

		if maxAge != 31536000 {
			t.Errorf("Values in %+v were not parsed correctly.", maxAge)
		}

		if includeSubdomains != true {
			t.Errorf("Values in %+v were not parsed correctly.", includeSubdomains)
		}

		if err != nil {
			t.Errorf("Error should not be present, but %v was returned.", err)
		}
	}
}

func TestAppIDAuthValidFormat(t *testing.T) {
	AnnotationLabel := "ingress.bluemix.net/appid-auth"
	Annotation := "serviceName=tea-svc bindSecret=my_secret namespace=my_namespace requestType=api"
	serviceName := "tea-svc"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation); err != nil {
		t.Errorf("In contains invalid should return %+v but returned %+v", Annotation, annotationEntryModel)
	} else {

		secret, namespace, requestType, idToken, err := handleAppIDAuth(annotationEntryModel, serviceName)

		if secret != "my_secret" {
			t.Errorf("Values in %+v were not parsed correctly.", secret)
		}

		if namespace != "my_namespace" {
			t.Errorf("Values in %+v were not parsed correctly.", namespace)
		}

		if requestType != "api" {
			t.Errorf("Values in %+v were not parsed correctly.", requestType)
		}

		if idToken != true {
			t.Errorf("Values in %+v were not parsed correctly.", idToken)
		}

		if err != nil {
			t.Errorf("Error should not be present, but %v was returned.", err)
		}
	}
}

func TestHandleLocationModifiers(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/location-modifier"

	cases := []struct {
		annotationStr    string
		serviceName      string
		expectedModifier string
		expectedErr      bool
	}{
		{annotationStr: "modifier='~' serviceName=tea-svc;modifier='^~' serviceName=coffee-svc", serviceName: "coffee-svc", expectedModifier: "^~"},
		{annotationStr: "modifier='=' serviceName=tea-svc;modifier='^~' serviceName=coffee-svc", serviceName: "tea-svc", expectedModifier: "="},
		{annotationStr: "modifier='~*' serviceName=tea-svc;modifier='^~' serviceName=coffee-svc", serviceName: "tea-svc", expectedModifier: "~*"},
		{annotationStr: "modifier='~' serviceName=tea-svc;modifier='^~' serviceName=coffee-svc", serviceName: "tea-svc", expectedModifier: "~"},
		{annotationStr: "modifier='~' serviceName=tea-svc;modifier='^~' serviceName=coffee-svc", serviceName: "random-svc", expectedModifier: ""},
		{annotationStr: "modifier=~* serviceName=tea-svc", serviceName: "tea-svc", expectedModifier: "", expectedErr: true},
		{annotationStr: "modifier='random' serviceName=tea-svc", serviceName: "tea-svc", expectedModifier: "", expectedErr: true},
		{annotationStr: "modifier='='' serviceName=tea-svc", serviceName: "tea-svc", expectedModifier: "", expectedErr: true},
		{annotationStr: "modifier='~ serviceName=tea-svc", serviceName: "tea-svc", expectedModifier: "", expectedErr: true},
		{annotationStr: "modifier='*~' serviceName=tea-svc", serviceName: "tea-svc", expectedModifier: "", expectedErr: true},
		{annotationStr: "modifier='' serviceName=tea-svc", serviceName: "tea-svc", expectedModifier: "", expectedErr: true},
	}

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	for _, tc := range cases {
		if annotationEntryModel, err := parser.ParseInputForAnnotation(annotationLabel, tc.annotationStr); err != nil {
			t.Errorf("In contains invalid return %s but returned %v", tc.annotationStr, annotationEntryModel)
		} else {
			locModifierValue, err := handleLocationModifier(annotationEntryModel, tc.serviceName)
			if tc.expectedErr {
				if err == nil {
					t.Errorf("error should be present")
				}
			} else if err != nil {
				t.Errorf("error should not be present, but %v was returned", err)
			}
			if locModifierValue != tc.expectedModifier {
				t.Errorf("handleLocationModifier should return %s but returned %s", tc.expectedModifier, locModifierValue)
			}
		}
	}
}

func TestUpstreamMaxFailsValidFormat(t *testing.T) {
	AnnotationLabel := "ingress.bluemix.net/upstream-max-fails"
	Annotation := "serviceName=tea-svc max-fails=0"
	serviceName := "tea-svc"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation); err != nil {
		t.Errorf("In contains invalid should return %+v but returned %+v", Annotation, annotationEntryModel)
	} else {

		maxFails, err := handleUpstreamMaxFails(annotationEntryModel, serviceName)

		if maxFails != "0" {
			t.Errorf("Values in %+v were not parsed correctly.", maxFails)
		}

		if err != nil {
			t.Errorf("Error should not be present, but %v was returned.", err)
		}
	}
}

func TestUpstreamFailTimeoutValidFormat(t *testing.T) {
	AnnotationLabel := "ingress.bluemix.net/upstream-fail-timeout"
	Annotation := "serviceName=tea-svc fail-timeout=10s"
	serviceName := "tea-svc"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation); err != nil {
		t.Errorf("In contains invalid should return %+v but returned %+v", Annotation, annotationEntryModel)
	} else {

		failTimeout, err := handleUpstreamFailTimeout(annotationEntryModel, serviceName)

		if failTimeout != "10s" {
			t.Errorf("Values in %+v were not parsed correctly.", failTimeout)
		}

		if err != nil {
			t.Errorf("Error should not be present, but %v was returned.", err)
		}

	}
}

func TestHandleIAMEndpointValidFormat(t *testing.T) {
	AnnotationLabel := "ingress.bluemix.net/iam-global-endpoint"
	Annotation := "endpoint=https://new-endpoint.com"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation); err != nil {
		t.Errorf("In contains invalid should return %+v but returned %+v", Annotation, annotationEntryModel)
	} else {

		endpoint, err := handleIAMEndpoint(annotationEntryModel)

		if endpoint != "https://new-endpoint.com" {
			t.Errorf("Values in %+v were not parsed correctly.", endpoint)
		}

		if err != nil {
			t.Errorf("Error should not be present, but %v was returned.", err)
		}
	}
}

func TestParseWatsonPreAuthServiceValidFormat(t *testing.T) {
	AnnotationLabel := "watson.ingress.bluemix.net/watson-pre-auth"
	Annotation := "serviceName=pre-auth-svc secondaryHost=test.us-south.containers.appdomain.cloud"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")
	os.Setenv("ALB_ID", "public-cr123456789-alb1")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation); err != nil {
		t.Errorf("In contains invalid should return %+v but returned %+v", Annotation, annotationEntryModel)
	} else {
		authFrontend, backendIngressHostValue, backendIngressSvcValue, err := handleWatsonPreAuth(annotationEntryModel)
		if err != nil {
			t.Errorf("Error should not be present, but %v was returned.", err)
		}

		if !authFrontend["pre-auth-svc"] {
			t.Errorf("authFrontend Value in header was not parsed correctly: %+v", authFrontend["pre-auth-svc"])
		}

		if backendIngressHostValue["pre-auth-svc"] != "test.us-south.containers.appdomain.cloud" {
			t.Errorf("backendIngressHostValue Value in header was not parsed correctly: %+v", backendIngressHostValue["pre-auth-svc"])
		}

		if backendIngressSvcValue["pre-auth-svc"] != "private-cr123456789-alb1" {
			t.Errorf("backendIngressSvcValue Value in header was not parsed correctly: %+v", backendIngressSvcValue)
		}
	}
}

func TestParseWatsonPostAuthServiceValidFormat(t *testing.T) {
	AnnotationLabel := "watson.ingress.bluemix.net/watson-post-auth"
	Annotation := "serviceName=post-auth-svc"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation); err != nil {
		t.Errorf("In contains invalid should return %+v but returned %+v", Annotation, annotationEntryModel)
	} else {
		upstream, err := handleWatsonPostAuth(annotationEntryModel)
		if err != nil {
			t.Errorf("Error should not be present, but %v was returned.", err)
		}

		if !upstream["post-auth-svc"] {
			t.Errorf("upstream Value in header was not parsed correctly: %+v", upstream["post-auth-svc"])
		}
	}
}

func TestParseDefaultServerValidFormat(t *testing.T) {
	AnnotationLabel := "ingress.bluemix.net/default-server"
	Annotation := "enabled=true"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation); err != nil {
		t.Errorf("In contains invalid should return %+v but returned %+v", Annotation, annotationEntryModel)
	} else {
		enabled, err := handleDefaultServer(annotationEntryModel)
		if err != nil {
			t.Errorf("Error should not be present, but %v was returned.", err)
		}

		if !enabled {
			t.Errorf("upstream Value in header was not parsed correctly: %+v", enabled)
		}
	}
}

func TestParseUpstreamLBFormat(t *testing.T) {
	AnnotationLabel := "ingress.bluemix.net/upstream-lb-type"
	Annotation := "serviceName=tea-svc lb-type=random"
	serviceName := "tea-svc"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation); err != nil {
		t.Errorf("In contains invalid should return %+v but returned %+v", Annotation, annotationEntryModel)
	} else {

		UpstreamLBType, err := handleUpstreamLBType(annotationEntryModel, serviceName)

		if UpstreamLBType[serviceName] != "random" {
			t.Errorf("Values in %+v were not parsed correctly.", UpstreamLBType)
		}

		if err != nil {
			t.Errorf("Error should not be present, but %v was returned.", err)
		}

	}
}

func TestParseUpstreamKeepaliveTimeoutFormat(t *testing.T) {
	AnnotationLabel := "ingress.bluemix.net/upstream-keepalive-timeout"
	Annotation := "serviceName=tea-svc timeout=20s"
	serviceName := "tea-svc"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation); err != nil {
		t.Errorf("In contains invalid should return %+v but returned %+v", Annotation, annotationEntryModel)
	} else {

		keepAliveTimeout, err := handleKeepAliveTimeout(annotationEntryModel)

		if keepAliveTimeout[serviceName] != "20s" {
			t.Errorf("Values in %+v were not parsed correctly.", keepAliveTimeout)
		}

		if err != nil {
			t.Errorf("Error should not be present, but %v was returned.", err)
		}

	}
}

func TestParseUpstreamKeepaliveTimeoutNoSvcFormat(t *testing.T) {
	AnnotationLabel := "ingress.bluemix.net/upstream-keepalive-timeout"
	Annotation := "timeout=20s"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	if annotationEntryModel, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation); err != nil {
		t.Errorf("In contains invalid should return %+v but returned %+v", Annotation, annotationEntryModel)
	} else {

		keepAliveTimeout, err := handleKeepAliveTimeout(annotationEntryModel)

		if keepAliveTimeout[""] != "20s" {
			t.Errorf("Values in %+v were not parsed correctly.", keepAliveTimeout)
		}

		if err != nil {
			t.Errorf("Error should not be present, but %v was returned.", err)
		}

	}
}

func TestParseUpstreamKeepaliveTimeoutInvalidFormat(t *testing.T) {
	AnnotationLabel := "ingress.bluemix.net/upstream-keepalive-timeout"
	Annotation := "time=20s"

	gopath := os.Getenv("GOPATH")
	parser.Prepare(gopath + "/src/github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser/annotations.json")

	_, err := parser.ParseInputForAnnotation(AnnotationLabel, Annotation)
	if err == nil {
		t.Errorf("Format is invalid so should have returned and error")
	}
}

type GetCertificateDataError struct {
	Configurator
}

func (*GetCertificateDataError) GetCertificateData(secret []byte) (map[string]string, error) {
	return nil, fmt.Errorf("GetCertificateData returns with error for test purposes")
}

func (*GetCertificateDataError) EventLogf(ingEx *IngressEx, msgCode string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	glog.Infof("[event] " + msg)
}

type GetCertificateDataNoCN struct {
	Configurator
}

func (*GetCertificateDataNoCN) GetCertificateData(secret []byte) (map[string]string, error) {
	return map[string]string{}, nil
}

func (*GetCertificateDataNoCN) EventLogf(ingEx *IngressEx, msgCode string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	glog.Infof("[event] " + msg)
}

type GetCertificateDataWithCN struct {
	Configurator
}

func (*GetCertificateDataWithCN) GetCertificateData(secret []byte) (map[string]string, error) {
	return map[string]string{"CommonName": "abc"}, nil
}

func (*GetCertificateDataWithCN) EventLogf(ingEx *IngressEx, msgCode string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	glog.Infof("[event] " + msg)
}

type NginxFuncsCertAndKey struct{}

func (NginxFuncsCertAndKey) AddOrUpdateTrustedCertAndKey(name string, cert string, key string, trustedCert string) (string, string, string) {
	return "keyfile", "certfile", "trustedcertfile"
}

type NginxFuncsOnlyCertOrKey struct{}

func (NginxFuncsOnlyCertOrKey) AddOrUpdateTrustedCertAndKey(name string, cert string, key string, trustedCert string) (string, string, string) {
	return "", "", "trustedcertfile"
}

func TestUpdateProxyCertificatesImpl(t *testing.T) {

	var cnfData = &Configurator{
		config: &Config{
			ProxySslVerifyDepth: int(5),
		},
	}
	var cnfFuncs Configurator
	var nginxFuncs IngressNginxController
	var getCertificateDataError GetCertificateDataError
	var getCertificateDataNoCN GetCertificateDataNoCN
	var getCertificateDataWithCN GetCertificateDataWithCN
	var nginxFuncsCertAndKey NginxFuncsCertAndKey
	var nginxFuncsOnlyCertOrKey NginxFuncsOnlyCertOrKey

	scenarios := map[string]struct {
		expectedPems map[string]ProxyPems
		ingEx        IngressEx
		cnfData      *Configurator
		cnfFuncs     updateProxyCertificatesDeps
		nginxFuncs   updateProxyCertificatesNginxDeps
	}{
		"No certificates": {
			expectedPems: map[string]ProxyPems{},
			ingEx:        IngressEx{},
			cnfData:      cnfData,
			cnfFuncs:     &cnfFuncs,
			nginxFuncs:   &nginxFuncs,
		},
		"PlainSSL": {
			expectedPems: map[string]ProxyPems{
				"testservice": ProxyPems{
					"", "PlainSSLAuthentication", "", "", "", 0,
				},
			},
			ingEx: IngressEx{
				PlainSSL: []string{"testservice"},
			},
			cnfData:    cnfData,
			cnfFuncs:   &cnfFuncs,
			nginxFuncs: &nginxFuncs,
		},
		"Secret is nil": {
			expectedPems: map[string]ProxyPems{},
			ingEx: IngressEx{
				UpstreamSSLData: map[string]UpstreamSSLConfig{
					"testservice": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "",
							Secret:     nil,
						},
					},
				},
			},
			cnfData:    cnfData,
			cnfFuncs:   &cnfFuncs,
			nginxFuncs: &nginxFuncs,
		},
		"There is no trusted.crt in the Secret": {
			expectedPems: map[string]ProxyPems{
				"testservice": ProxyPems{
					"", "TrustCertificateMissing", "", "", "", 0,
				},
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "testnamespace",
						Name:      "testingress",
					},
				},
				UpstreamSSLData: map[string]UpstreamSSLConfig{
					"testservice": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret:     &api.Secret{},
						},
					},
				},
			},
			cnfData:    cnfData,
			cnfFuncs:   &cnfFuncs,
			nginxFuncs: &nginxFuncs,
		},
		"GetCertificateData returns with error": {
			expectedPems: map[string]ProxyPems{},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "testnamespace",
						Name:      "testingress",
					},
				},
				UpstreamSSLData: map[string]UpstreamSSLConfig{
					"testservice": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
								},
							},
						},
					},
				},
			},
			cnfData:    cnfData,
			cnfFuncs:   &getCertificateDataError,
			nginxFuncs: &nginxFuncs,
		},
		"Common Name is empty in the certificate": {
			expectedPems: map[string]ProxyPems{},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "testnamespace",
						Name:      "testingress",
					},
				},
				UpstreamSSLData: map[string]UpstreamSSLConfig{
					"testservice": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
								},
							},
						},
					},
				},
			},
			cnfData:    cnfData,
			cnfFuncs:   &getCertificateDataNoCN,
			nginxFuncs: &nginxFuncs,
		},
		"Oneway SSL authentication": {
			expectedPems: map[string]ProxyPems{
				"testservice": ProxyPems{
					"abc", oneWaySSLAuthentication, "trustedcertfile", "", "", 5,
				},
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "testnamespace",
						Name:      "testingress",
					},
				},
				UpstreamSSLData: map[string]UpstreamSSLConfig{
					"testservice": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
								},
							},
						},
					},
				},
			},
			cnfData:    cnfData,
			cnfFuncs:   &getCertificateDataWithCN,
			nginxFuncs: &nginxFuncsOnlyCertOrKey,
		},
		"Both client cert and client key are present": {
			expectedPems: map[string]ProxyPems{
				"testservice": ProxyPems{
					"abc", twoWaySSLAuthentication, "trustedcertfile", "certfile", "keyfile", 5,
				},
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "testnamespace",
						Name:      "testingress",
					},
				},
				UpstreamSSLData: map[string]UpstreamSSLConfig{
					"testservice": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
									"client.crt":  []byte{},
									"client.key":  []byte{},
								},
							},
						},
					},
				},
			},
			cnfData:    cnfData,
			cnfFuncs:   &getCertificateDataWithCN,
			nginxFuncs: &nginxFuncsCertAndKey,
		},
		"Only client cert is present": {
			expectedPems: map[string]ProxyPems{
				"testservice": ProxyPems{
					"abc", oneWaySSLAuthentication, "trustedcertfile", "", "", 5,
				},
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "testnamespace",
						Name:      "testingress",
					},
				},
				UpstreamSSLData: map[string]UpstreamSSLConfig{
					"testservice": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
									"client.crt":  []byte{},
								},
							},
						},
					},
				},
			},
			cnfData:    cnfData,
			cnfFuncs:   &getCertificateDataWithCN,
			nginxFuncs: &nginxFuncsOnlyCertOrKey,
		},
		"Only client key is present": {
			expectedPems: map[string]ProxyPems{
				"testservice": ProxyPems{
					"abc", oneWaySSLAuthentication, "trustedcertfile", "", "", 5,
				},
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "testnamespace",
						Name:      "testingress",
					},
				},
				UpstreamSSLData: map[string]UpstreamSSLConfig{
					"testservice": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
									"client.key":  []byte{},
								},
							},
						},
					},
				},
			},
			cnfData:    cnfData,
			cnfFuncs:   &getCertificateDataWithCN,
			nginxFuncs: &nginxFuncsOnlyCertOrKey,
		},
		"proxy_ssl_verify_depth is configured in annotation": {
			expectedPems: map[string]ProxyPems{
				"testservice": ProxyPems{
					"abc", twoWaySSLAuthentication, "trustedcertfile", "certfile", "keyfile", 8,
				},
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "testnamespace",
						Name:      "testingress",
					},
				},
				UpstreamSSLData: map[string]UpstreamSSLConfig{
					"testservice": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
									"client.crt":  []byte{},
									"client.key":  []byte{},
								},
							},
						},
						ProxySSLConfig: ProxySSLConfig{
							ProxySSLVerifyDepth: int(8),
						},
					},
				},
			},
			cnfData:    cnfData,
			cnfFuncs:   &getCertificateDataWithCN,
			nginxFuncs: &nginxFuncsCertAndKey,
		},
		"2 services configured and proxy_ssl_verify_depth is configured only for the 1st one": {
			expectedPems: map[string]ProxyPems{
				"testservice1": ProxyPems{
					"abc", twoWaySSLAuthentication, "trustedcertfile", "certfile", "keyfile", 8,
				},
				"testservice2": ProxyPems{
					"abc", twoWaySSLAuthentication, "trustedcertfile", "certfile", "keyfile", 5,
				},
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "testnamespace",
						Name:      "testingress",
					},
				},
				UpstreamSSLData: map[string]UpstreamSSLConfig{
					"testservice1": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
									"client.crt":  []byte{},
									"client.key":  []byte{},
								},
							},
						},
						ProxySSLConfig: ProxySSLConfig{
							ProxySSLVerifyDepth: int(8),
						},
					},
					"testservice2": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
									"client.crt":  []byte{},
									"client.key":  []byte{},
								},
							},
						},
						ProxySSLConfig: ProxySSLConfig{},
					},
				},
			},
			cnfData:    cnfData,
			cnfFuncs:   &getCertificateDataWithCN,
			nginxFuncs: &nginxFuncsCertAndKey,
		},
		"2 services configured and proxy_ssl_verify_depth is configured only for the 2nd one": {
			expectedPems: map[string]ProxyPems{
				"testservice1": ProxyPems{
					"abc", twoWaySSLAuthentication, "trustedcertfile", "certfile", "keyfile", 5,
				},
				"testservice2": ProxyPems{
					"abc", twoWaySSLAuthentication, "trustedcertfile", "certfile", "keyfile", 9,
				},
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "testnamespace",
						Name:      "testingress",
					},
				},
				UpstreamSSLData: map[string]UpstreamSSLConfig{
					"testservice1": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
									"client.crt":  []byte{},
									"client.key":  []byte{},
								},
							},
						},
						ProxySSLConfig: ProxySSLConfig{},
					},
					"testservice2": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
									"client.crt":  []byte{},
									"client.key":  []byte{},
								},
							},
						},
						ProxySSLConfig: ProxySSLConfig{
							ProxySSLVerifyDepth: int(9),
						},
					},
				},
			},
			cnfData:    cnfData,
			cnfFuncs:   &getCertificateDataWithCN,
			nginxFuncs: &nginxFuncsCertAndKey,
		},
		"2 services configured and proxy_ssl_verify_depth is configured for both": {
			expectedPems: map[string]ProxyPems{
				"testservice1": ProxyPems{
					"abc", twoWaySSLAuthentication, "trustedcertfile", "certfile", "keyfile", 10,
				},
				"testservice2": ProxyPems{
					"abc", twoWaySSLAuthentication, "trustedcertfile", "certfile", "keyfile", 9,
				},
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "testnamespace",
						Name:      "testingress",
					},
				},
				UpstreamSSLData: map[string]UpstreamSSLConfig{
					"testservice1": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
									"client.crt":  []byte{},
									"client.key":  []byte{},
								},
							},
						},
						ProxySSLConfig: ProxySSLConfig{
							ProxySSLVerifyDepth: int(10),
						},
					},
					"testservice2": UpstreamSSLConfig{
						Secrets: Secrets{
							SecretName: "testsecret",
							Secret: &api.Secret{
								Data: map[string][]byte{
									"trusted.crt": []byte{},
									"client.crt":  []byte{},
									"client.key":  []byte{},
								},
							},
						},
						ProxySSLConfig: ProxySSLConfig{
							ProxySSLVerifyDepth: int(9),
						},
					},
				},
			},
			cnfData:    cnfData,
			cnfFuncs:   &getCertificateDataWithCN,
			nginxFuncs: &nginxFuncsCertAndKey,
		},
	}

	for name, scenario := range scenarios {
		t.Run(name, func(t *testing.T) {
			proxyPems := updateProxyCertificatesImpl(&scenario.ingEx, scenario.cnfData, scenario.cnfFuncs, scenario.nginxFuncs)
			if !reflect.DeepEqual(scenario.expectedPems, proxyPems) {
				t.Errorf("Unexpected result for scenario: %s. Expected result: %v, Test result: %v", name, scenario.expectedPems, proxyPems)
			}
		})
	}
}

func TestGetSSLServices(t *testing.T) {
	var cnf = &Configurator{}
	scenarios := map[string]struct {
		expectedSSLServices map[string]SSLServicesData
		expectedIngEx       IngressEx
		ingEx               IngressEx
	}{
		"No annotation": {
			expectedSSLServices: map[string]SSLServicesData{},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{},
					},
				},
				IsUpsreamSSLs: false,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{},
					},
				},
			},
		},
		"Annotation without ssl-service definitions": {
			expectedSSLServices: map[string]SSLServicesData{},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "",
						},
					},
				},
			},
		},
		"Single ssl-service with invalid service name definition": {
			expectedSSLServices: map[string]SSLServicesData{
				"": SSLServicesData{
					SecretName:          "",
					ProxySSLVerifyDepth: 0,
					ProxySSLName:        "",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=",
						},
					},
				},
			},
		},
		"Single ssl-service without certificate": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice",
						},
					},
				},
			},
		},
		"Single ssl-service without proxy-ssl-verify-depth": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{
					SecretName:          "mysecret",
					ProxySSLVerifyDepth: 0,
					ProxySSLName:        "",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret",
						},
					},
				},
			},
		},
		"Single ssl-service with proxy-ssl-verify-depth": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{
					SecretName:          "mysecret",
					ProxySSLVerifyDepth: 4,
					ProxySSLName:        "",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=4",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=4",
						},
					},
				},
			},
		},
		"Two ssl-services with no proxy-ssl-verify-depth in the 2nd service": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{
					SecretName:          "mysecret",
					ProxySSLVerifyDepth: 5,
					ProxySSLName:        "",
				},
				"myservice2": SSLServicesData{
					SecretName:          "mysecret2",
					ProxySSLVerifyDepth: 0,
					ProxySSLName:        "",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=5;ssl-service=myservice2 ssl-secret=mysecret2",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=5;ssl-service=myservice2 ssl-secret=mysecret2",
						},
					},
				},
			},
		},
		"Two ssl-services with proxy-ssl-verify-depth in both services": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{
					SecretName:          "mysecret",
					ProxySSLVerifyDepth: 6,
					ProxySSLName:        "",
				},
				"myservice2": SSLServicesData{
					SecretName:          "mysecret2",
					ProxySSLVerifyDepth: 8,
					ProxySSLName:        "",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=6;ssl-service=myservice2 ssl-secret=mysecret2 proxy-ssl-verify-depth=8",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=6;ssl-service=myservice2 ssl-secret=mysecret2 proxy-ssl-verify-depth=8",
						},
					},
				},
			},
		},
		"Two ssl-services with no proxy-ssl-verify-depth in the 1st service": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{
					SecretName:          "mysecret",
					ProxySSLVerifyDepth: 0,
					ProxySSLName:        "",
				},
				"myservice2": SSLServicesData{
					SecretName:          "mysecret2",
					ProxySSLVerifyDepth: 7,
					ProxySSLName:        "",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret;ssl-service=myservice2 ssl-secret=mysecret2 proxy-ssl-verify-depth=7",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret;ssl-service=myservice2 ssl-secret=mysecret2 proxy-ssl-verify-depth=7",
						},
					},
				},
			},
		},
		"Single ssl-service with proxy-ssl-verify-depth=0": {
			expectedSSLServices: map[string]SSLServicesData{},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=0",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=0",
						},
					},
				},
			},
		},
		"Single ssl-service with proxy-ssl-verify-depth < 0": {
			expectedSSLServices: map[string]SSLServicesData{},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=-1",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=-1",
						},
					},
				},
			},
		},
		"Single ssl-service with proxy-ssl-verify-depth=10": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{
					SecretName:          "mysecret",
					ProxySSLVerifyDepth: 10,
					ProxySSLName:        "",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=10",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=10",
						},
					},
				},
			},
		},
		"Single ssl-service with proxy-ssl-verify-depth > 10": {
			expectedSSLServices: map[string]SSLServicesData{},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=11",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=11",
						},
					},
				},
			},
		},
		"Single ssl-service with invalid proxy-ssl-verify-depth": {
			expectedSSLServices: map[string]SSLServicesData{},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=a",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=a",
						},
					},
				},
			},
		},
		"Single ssl-service with proxy-ssl-name": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{
					SecretName:   "mysecret",
					ProxySSLName: "mysslname",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-name=mysslname",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-name=mysslname",
						},
					},
				},
			},
		},
		"Single ssl-service with proxy-ssl-verify-depth and proxy-ssl-name": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{
					SecretName:          "mysecret",
					ProxySSLVerifyDepth: 7,
					ProxySSLName:        "mysslname",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=7 proxy-ssl-name=mysslname",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=7 proxy-ssl-name=mysslname",
						},
					},
				},
			},
		},
		"Single ssl-service with proxy-ssl-name and proxy-ssl-verify-depth": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{
					SecretName:          "mysecret",
					ProxySSLVerifyDepth: 8,
					ProxySSLName:        "mysslname",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-name=mysslname proxy-ssl-verify-depth=8",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-name=mysslname proxy-ssl-verify-depth=8",
						},
					},
				},
			},
		},
		"Single ssl-service with invalid proxy-ssl-verify-depth and with proxy-ssl-name ": {
			expectedSSLServices: map[string]SSLServicesData{},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=12 proxy-ssl-name=mysslname",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=12 proxy-ssl-name=mysslname",
						},
					},
				},
			},
		},
		"Single ssl-service with valid proxy-ssl-verify-depth and invalid proxy-ssl-name ": {
			expectedSSLServices: map[string]SSLServicesData{},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=3 proxy-ssl-name",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-verify-depth=3 proxy-ssl-name",
						},
					},
				},
			},
		},
		"Two ssl-services with proxy-ssl-name in the 1st service onlxy": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{
					SecretName:          "mysecret",
					ProxySSLVerifyDepth: 0,
					ProxySSLName:        "mysslname",
				},
				"myservice2": SSLServicesData{
					SecretName:          "mysecret2",
					ProxySSLVerifyDepth: 0,
					ProxySSLName:        "",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-name=mysslname;ssl-service=myservice2 ssl-secret=mysecret2",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-name=mysslname;ssl-service=myservice2 ssl-secret=mysecret2",
						},
					},
				},
			},
		},
		"Two ssl-services with proxy-ssl-name in the 2nd service only": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{
					SecretName:          "mysecret",
					ProxySSLVerifyDepth: 0,
					ProxySSLName:        "",
				},
				"myservice2": SSLServicesData{
					SecretName:          "mysecret2",
					ProxySSLVerifyDepth: 0,
					ProxySSLName:        "mysslname2",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret;ssl-service=myservice2 ssl-secret=mysecret2 proxy-ssl-name=mysslname2",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret;ssl-service=myservice2 ssl-secret=mysecret2 proxy-ssl-name=mysslname2",
						},
					},
				},
			},
		},
		"Two ssl-services with proxy-ssl-name in both services": {
			expectedSSLServices: map[string]SSLServicesData{
				"myservice": SSLServicesData{
					SecretName:          "mysecret",
					ProxySSLVerifyDepth: 0,
					ProxySSLName:        "mysslname",
				},
				"myservice2": SSLServicesData{
					SecretName:          "mysecret2",
					ProxySSLVerifyDepth: 0,
					ProxySSLName:        "mysslname2",
				},
			},
			expectedIngEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-name=mysslname;ssl-service=myservice2 ssl-secret=mysecret2 proxy-ssl-name=mysslname2",
						},
					},
				},
				IsUpsreamSSLs: true,
			},
			ingEx: IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.bluemix.net/ssl-services": "ssl-service=myservice ssl-secret=mysecret proxy-ssl-name=mysslname;ssl-service=myservice2 ssl-secret=mysecret2 proxy-ssl-name=mysslname2",
						},
					},
				},
			},
		},
	}

	for name, scenario := range scenarios {
		t.Run(name, func(t *testing.T) {
			resSSLServiceData := cnf.GetSSLServices(&scenario.ingEx)
			if !reflect.DeepEqual(scenario.expectedSSLServices, resSSLServiceData) {
				t.Errorf("Unexpected result for scenario: %s. Expected result: %v, Test result: %v", name, scenario.expectedSSLServices, resSSLServiceData)
			}
			if !reflect.DeepEqual(scenario.expectedIngEx, scenario.ingEx) {
				t.Errorf("Unexpected result for scenario: %s. Expected result: %v, Test result: %v", name, scenario.expectedIngEx, scenario.ingEx)
			}
		})
	}
}
