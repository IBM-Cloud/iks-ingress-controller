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
	"fmt"
	"strconv"
	"strings"

	"os"

	"github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/parser"
	"github.com/golang/glog"
)

var snortPorts = []int{7481, 7482, 7483, 7484, 7485, 7486, 7487, 7488, 7489, 7490}

// CustomPort ...
type CustomPort struct {
	Port     string
	Protocol string
}

func handleCustomPort(annotation parser.ParsedValidatedAnnotation, resourceName, serverName string) (map[string][]CustomPort, error) {
	portMap := map[string][]CustomPort{}
	var err error

	for _, entry := range annotation.Entries {
		if entry.Exists("protocol") && entry.Exists("port") {
			protocol, _ := entry.GetAsString("protocol")
			port, _ := entry.GetAsInt("port")

			snortConflict := false
			for _, snortPort := range snortPorts {
				if port == snortPort {
					snortConflict = true
					break
				}
			}

			if snortConflict {
				glog.Errorf("ParseCustomPorts: Invalid port %v. 'ingress.bluemix.net/custom-port' annotation in %v, cannot use ports 7481 - 7490.", port, resourceName)
				err = fmt.Errorf("Invalid port %v. Annotation cannot use ports 7481 - 7490", port)
			} else {
				cp := CustomPort{
					Protocol: protocol,
					Port:     strconv.Itoa(port),
				}

				portMap[serverName] = append(portMap[serverName], cp)
			}

		} else {
			glog.Errorf("ParseCustomPorts: Invalid format. 'ingress.bluemix.net/custom-port' annotation in %v, must be in format 'protocol=<http or https> port=<port>'.", resourceName)
			err = fmt.Errorf("Invalid format. Annotation must be of the format 'protocol=<http or https> port=<port>'")
		}
	}

	return portMap, err
}

// HandleMutualAuth ...
func HandleMutualAuth(annotation parser.ParsedValidatedAnnotation, resourceName, serverName string) (map[string][]string, []string, error) {
	portMap := map[string][]string{}
	maPaths := []string{}
	var err error

	for _, entry := range annotation.Entries {
		if entry.Exists("port") && entry.Exists("secretName") {
			secretName, _ := entry.GetAsString("secretName")
			port, _ := entry.GetAsInt("port")

			snortConflict := false
			for _, snortPort := range snortPorts {
				if port == snortPort {
					snortConflict = true
					break
				}
			}

			if snortConflict {
				glog.Errorf("ParseMutualAuth: Invalid port %v. 'ingress.bluemix.net/mutual-auth' annotation in %v, cannot use ports 7481 - 7490.", port, resourceName)
				err = fmt.Errorf("Invalid port %v. Annotation cannot use ports 7481 - 7490", port)
			} else {
				services, ok := entry.GetAsStrings("serviceName")
				if ok {
					maPaths = services
				}
				// portMap[host] = [port, secret]
				portMap[serverName] = []string{strconv.Itoa(port), secretName}
			}
		} else {
			glog.Errorf("ParseMutualAuth: Invalid format. 'ingress.bluemix.net/mutual-auth' annotation in %v, must be in format 'port=<port> secretName=<secret> [paths=<path0,path1,...,pathn>]'.", resourceName)
			err = fmt.Errorf("Invalid format. Annotation must be of the format 'port=<port> secretName=<secret> [paths=<path0,path1,...,pathn>]'")
		}
	}

	return portMap, maPaths, err
}

func handleKeepAliveRequests(keepAliveRequestsAnnotation parser.ParsedValidatedAnnotation) (map[string]string, error) {
	keepAliveRequests := make(map[string]string)
	var errstrings []string
	var err error

	for _, keepAliveRequestsEntry := range keepAliveRequestsAnnotation.Entries {
		glog.Infof("keepAliveRequestsEntry %v", keepAliveRequestsEntry)

		if keepAliveRequestsEntry.Exists("requests") && keepAliveRequestsEntry.Exists("serviceName") {
			svcNames, _ := keepAliveRequestsEntry.GetAsStrings("serviceName")
			glog.Infof("serviceNames %v", svcNames)
			for _, svcName := range svcNames {
				if valueAsInt, exists := keepAliveRequestsEntry.GetAsInt("requests"); exists && valueAsInt >= 0 {
					keepAliveRequests[svcName] = strconv.Itoa(valueAsInt)
				} else if !exists || valueAsInt < 0 {
					glog.Infof("Invalid entry %v", keepAliveRequestsEntry)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry: %v. ", keepAliveRequestsEntry))
				}
			}
		} else if keepAliveRequestsEntry.Exists("requests") && !keepAliveRequestsEntry.Exists("serviceName") {
			if valueAsInt, exists := keepAliveRequestsEntry.GetAsInt("requests"); exists && valueAsInt >= 0 {
				keepAliveRequests[""] = strconv.Itoa(valueAsInt)
			} else if !exists || valueAsInt < 0 {
				glog.Infof("Invalid entry %v", keepAliveRequestsEntry)
				errstrings = append(errstrings, fmt.Sprintf("Invalid entry: %v. ", keepAliveRequestsEntry))
			}
		} else if keepAliveRequestsEntry.Keyless() {
			if valueAsString, exists := keepAliveRequestsEntry.GetKeylessValueAsString("int"); exists {
				var valueAsInt int
				if valueAsInt, err = strconv.Atoi(valueAsString); err != nil && valueAsInt >= 0 {
					glog.Infof("valueUnitString keyless %s", valueAsString)
					keepAliveRequests[""] = valueAsString
				} else if !exists || valueAsInt < 0 {
					glog.Infof("Invalid keyless entry: %v", keepAliveRequestsEntry)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry: %v ", keepAliveRequestsEntry))
				}
			} else {
				glog.Infof("Invalid keyless entry: %v", keepAliveRequestsEntry)
				errstrings = append(errstrings, fmt.Sprintf("Invalid entry: %v ", keepAliveRequestsEntry))
			}
		}
	}

	if len(errstrings) > 0 {
		err = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return keepAliveRequests, err
}

func handleKeepAliveTimeout(keepAliveTimeoutAnnotation parser.ParsedValidatedAnnotation) (map[string]string, error) {
	keepAliveTimeouts := make(map[string]string)
	var errstrings []string
	var err error

	for _, keepAliveTimeoutEntry := range keepAliveTimeoutAnnotation.Entries {
		glog.Infof("keepAliveTimeoutEntry: %v", keepAliveTimeoutEntry)

		if keepAliveTimeoutEntry.Exists("timeout") && keepAliveTimeoutEntry.Exists("serviceName") {
			svcNames, _ := keepAliveTimeoutEntry.GetAsStrings("serviceName")
			glog.Infof("serviceNames: %v", svcNames)
			for _, svcName := range svcNames {
				if valueAsString, exists := keepAliveTimeoutEntry.GetAsValueUnitString("timeout"); exists && !strings.HasPrefix(valueAsString, "-") {
					keepAliveTimeouts[svcName] = valueAsString
				} else {
					glog.Infof("Invalid entry: %v", keepAliveTimeoutEntry)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry: %v. ", keepAliveTimeoutEntry))
				}
			}
		} else if keepAliveTimeoutEntry.Exists("timeout") && !keepAliveTimeoutEntry.Exists("serviceName") {
			if valueAsString, exists := keepAliveTimeoutEntry.GetAsValueUnitString("timeout"); exists && !strings.HasPrefix(valueAsString, "-") {
				keepAliveTimeouts[""] = valueAsString
			} else {
				glog.Infof("Invalid entry: %v", keepAliveTimeoutEntry)
				errstrings = append(errstrings, fmt.Sprintf("Invalid entry: %v. ", keepAliveTimeoutEntry))
			}
		} else if keepAliveTimeoutEntry.Keyless() {
			if valueUnitString, exists := keepAliveTimeoutEntry.GetKeylessValueAsValueUnitString("int"); exists && !strings.HasPrefix(valueUnitString, "-") {
				glog.Infof("valueUnitString keyless: %s", valueUnitString)
				keepAliveTimeouts[""] = valueUnitString
			} else {
				glog.Infof("Invalid keyless entry: %v", keepAliveTimeoutEntry)
				errstrings = append(errstrings, fmt.Sprintf("Invalid entry: %v. ", keepAliveTimeoutEntry))
			}
		}
	}

	if len(errstrings) > 0 {
		err = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return keepAliveTimeouts, err
}

func handleLargeClientHeaderBuffers(largeClientHeaderBuffersAnnotation parser.ParsedValidatedAnnotation, serverName string) (map[string]string, error) {
	bufferMap := make(map[string]string)
	var errstrings []string
	var err error

	for _, entry := range largeClientHeaderBuffersAnnotation.Entries {
		if entry.Exists("number") && entry.Exists("size") {
			number, _ := entry.GetAsString("number")
			size, _ := entry.GetAsString("size")

			bufferMap[serverName] = fmt.Sprintf("%s %s", number, size)
		} else {
			errstrings = append(errstrings, fmt.Sprintf("Invalid entry: %v. ", entry))
		}
	}

	if len(errstrings) > 0 {
		err = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return bufferMap, err
}

func handleLocProxyTimeout(timeoutAnnotation parser.ParsedValidatedAnnotation, serviceName string) (string, error) {
	var errstrings []string
	var err error

	for _, timeoutEntry := range timeoutAnnotation.Entries {
		glog.Infof("TimeoutEntry: %v", timeoutEntry)
		if timeoutEntry.Exists("timeout") && timeoutEntry.Exists("serviceName") {
			svcNames, _ := timeoutEntry.GetAsStrings("serviceName")
			glog.Infof("serviceNames: %v", svcNames)
			for _, svcName := range svcNames {
				if serviceName == svcName {
					glog.Infof("serviceName: %s , backend: %s", svcName, serviceName)
					locProxyTimeoutValue, _ := timeoutEntry.GetAsValueUnitString("timeout")
					return locProxyTimeoutValue, err
				}
			}
		}
	}

	for _, timeoutEntry := range timeoutAnnotation.Entries {
		glog.Infof("TimeoutEntry: %v", timeoutEntry)
		if timeoutEntry.Exists("timeout") && !timeoutEntry.Exists("serviceName") {
			locProxyTimeoutValue, _ := timeoutEntry.GetAsValueUnitString("timeout")
			return locProxyTimeoutValue, err
		}
	}
	for _, timeoutEntry := range timeoutAnnotation.Entries {
		glog.Infof("TimeoutEntry: %v", timeoutEntry)
		if timeoutEntry.Keyless() {
			valueUnitString, exist := timeoutEntry.GetKeylessValueAsValueUnitString("timeout")
			if exist {
				glog.Infof("valueUnitString keyless: %s", valueUnitString)
				return valueUnitString, err
			}
			glog.Infof("Invalid keyless entry: %v", timeoutEntry)
			errstrings = append(errstrings, fmt.Sprintf("Invalid keyless entry: %v ", timeoutEntry))
		}
	}

	if len(errstrings) > 0 {
		err = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return "", err
}

func handleLocProxyBuffering(bufferingAnnotation parser.ParsedValidatedAnnotation, serviceName string) (locationEnabled bool, err error) {
	var errstrings []string

	for _, bufferingEntry := range bufferingAnnotation.Entries {
		glog.Infof("Buffering Entry %v", bufferingEntry)
		if bufferingEntry.Exists("enabled") && bufferingEntry.Exists("serviceName") {
			svcNames, _ := bufferingEntry.GetAsStrings("serviceName")
			glog.Infof("serviceNames: %v", svcNames)
			for _, svcName := range svcNames {
				if serviceName == svcName {
					glog.Infof("serviceName: %s , backend: %s ", svcName, serviceName)
					locProxyBufferingValue, _ := bufferingEntry.GetAsBool("enabled")
					glog.Infof("%s set to locProxyBufferingValue: %v", serviceName, locProxyBufferingValue)
					return locProxyBufferingValue, err
				}
			}
		}
	}

	for _, bufferingEntry := range bufferingAnnotation.Entries {
		glog.Info("Buffering Entry: ", bufferingEntry)
		if bufferingEntry.Exists("enabled") && !bufferingEntry.Exists("serviceName") {
			locProxyBufferingValue, _ := bufferingEntry.GetAsBool("enabled")
			glog.Info("All services set to locProxyBufferingValue: ", locProxyBufferingValue)
			return locProxyBufferingValue, err
		}
	}
	for _, bufferingEntry := range bufferingAnnotation.Entries {
		glog.Info("Buffering Entry: ", bufferingEntry)
		if bufferingEntry.Keyless() {
			locProxyBufferingValue, exist := bufferingEntry.GetKeylessValueAsBool("bool")
			if exist {
				glog.Info("locProxyBufferingValue keyless: ", locProxyBufferingValue)
				return locProxyBufferingValue, err
			}
			glog.Info("Invalid keyless entry: ", bufferingEntry)
			errstrings = append(errstrings, fmt.Sprintf("Invalid keyless entry: %v. ", bufferingEntry))
		}
	}

	if len(errstrings) > 0 {
		err = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return true, err
}

func handleLocHostPort(addHostPortAnnotation parser.ParsedValidatedAnnotation, serviceName string) (locationEnabled bool, err error) {
	var errstrings []string

	for _, hostPortEntry := range addHostPortAnnotation.Entries {
		glog.Infof("HostPort Entry %v\n", hostPortEntry)
		if hostPortEntry.Exists("enabled") && hostPortEntry.Exists("serviceName") {
			svcNames, _ := hostPortEntry.GetAsStrings("serviceName")
			glog.Info("serviceNames", svcNames)
			for _, svcName := range svcNames {
				if serviceName == svcName {
					glog.Info("serviceNames: ", svcName)
					glog.Info("backEnd: ", serviceName)
					locHostPortValue, _ := hostPortEntry.GetAsBool("enabled")
					glog.Infof("%s set to locHostPortValue: %v", serviceName, locHostPortValue)
					return locHostPortValue, err
				}
			}
		}
	}

	for _, hostPortEntry := range addHostPortAnnotation.Entries {
		glog.Info("HostPort Entry: ", hostPortEntry)
		if hostPortEntry.Exists("enabled") && !hostPortEntry.Exists("serviceName") {
			locHostPortValue, _ := hostPortEntry.GetAsBool("enabled")
			glog.Info("All services set to locHostPortValue: ", locHostPortValue)
			return locHostPortValue, err
		}
	}

	if len(errstrings) > 0 {
		err = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return false, err
}

func handleLocClientMaxBodySize(clientMaxBodySizeAnnotation parser.ParsedValidatedAnnotation, serviceName string) (clientMaxBodySize string, err error) {
	var errstrings []string

	for _, clientMaxBodySizeEntry := range clientMaxBodySizeAnnotation.Entries {
		glog.Infof("clientMaxBodySizeEntry: %v", clientMaxBodySizeEntry)
		if clientMaxBodySizeEntry.Exists("size") && clientMaxBodySizeEntry.Exists("serviceName") {
			svcNames, _ := clientMaxBodySizeEntry.GetAsStrings("serviceName")
			glog.Infof("serviceNames: %v", svcNames)
			for _, svcName := range svcNames {
				if serviceName == svcName {
					glog.Infof("serviceName: %s , backend: %s", svcName, serviceName)
					locClientMaxBodySize, _ := clientMaxBodySizeEntry.GetAsString("size")
					return locClientMaxBodySize, err
				}
			}
		}
	}

	for _, clientMaxBodySizeEntry := range clientMaxBodySizeAnnotation.Entries {
		glog.Infof("clientMaxBodySizeEntry: %v", clientMaxBodySizeEntry)
		if clientMaxBodySizeEntry.Exists("size") && !clientMaxBodySizeEntry.Exists("serviceName") {
			locClientMaxBodySize, _ := clientMaxBodySizeEntry.GetAsString("size")
			return locClientMaxBodySize, err
		}
	}

	for _, clientMaxBodySizeEntry := range clientMaxBodySizeAnnotation.Entries {
		glog.Infof("clientMaxBodySizeEntry: %v", clientMaxBodySizeEntry)
		if clientMaxBodySizeEntry.Keyless() {
			valueUnitString, exist := clientMaxBodySizeEntry.GetKeylessValueAsString("size")
			if exist {
				glog.Infof("valueUnitString keyless: %s", valueUnitString)
				return valueUnitString, err
			}
			glog.Infof("Invalid keyless entry: %v", clientMaxBodySizeEntry)
			errstrings = append(errstrings, fmt.Sprintf("Invalid keyless entry: %v. ", clientMaxBodySizeEntry))
		}
	}

	if len(errstrings) > 0 {
		err = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return "", err
}

func handleLocProxyBufferSize(proxyBufferSizeAnnotation parser.ParsedValidatedAnnotation, serviceName string) (proxyBufferSize string, err error) {
	var errstrings []string

	for _, proxyBufferSizeEntry := range proxyBufferSizeAnnotation.Entries {
		glog.Infof("proxyBufferSizeEntry: %v", proxyBufferSizeEntry)
		if proxyBufferSizeEntry.Exists("size") && proxyBufferSizeEntry.Exists("serviceName") {
			svcNames, _ := proxyBufferSizeEntry.GetAsStrings("serviceName")
			glog.Infof("serviceNames: %v", svcNames)
			for _, svcName := range svcNames {
				if serviceName == svcName {
					glog.Infof("serviceName: %s , backend: %s", svcName, serviceName)
					locProxyBufferSize, _ := proxyBufferSizeEntry.GetAsString("size")
					return locProxyBufferSize, err
				}
			}
		}
	}

	for _, proxyBufferSizeEntry := range proxyBufferSizeAnnotation.Entries {
		glog.Infof("proxyBufferSizeEntry: %v", proxyBufferSizeEntry)
		if proxyBufferSizeEntry.Exists("size") && !proxyBufferSizeEntry.Exists("serviceName") {
			locProxyBufferSize, _ := proxyBufferSizeEntry.GetAsString("size")
			return locProxyBufferSize, err
		}
	}

	if len(errstrings) > 0 {
		err = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return "", err
}

func handleLocProxyBuffers(proxyBuffersAnnotation parser.ParsedValidatedAnnotation, serviceName string) (proxyBuffersSize string, numberOfProxyBuffers int, err error) {
	var errstrings []string

	for _, proxyBuffersEntry := range proxyBuffersAnnotation.Entries {
		glog.Infof("proxyBuffers Entry: %v ", proxyBuffersEntry)
		if proxyBuffersEntry.Exists("serviceName") && proxyBuffersEntry.Exists("number") && proxyBuffersEntry.Exists("size") {
			svcNames, _ := proxyBuffersEntry.GetAsStrings("serviceName")
			glog.Infof("serviceNames: %v", svcNames)
			for _, svcName := range svcNames {
				if serviceName == svcName {
					glog.Infof("serviceName: %s , backend: %s", svcName, serviceName)
					locProxyBuffersSize, _ := proxyBuffersEntry.GetAsString("size")
					numberOfProxyBuffers, _ := proxyBuffersEntry.GetAsInt("number")
					return locProxyBuffersSize, numberOfProxyBuffers, err
				}
			}
		}
	}

	for _, proxyBuffersEntry := range proxyBuffersAnnotation.Entries {
		glog.Infof("proxyBuffersEntry: %v", proxyBuffersEntry)
		if proxyBuffersEntry.Exists("number") && proxyBuffersEntry.Exists("size") && !proxyBuffersEntry.Exists("serviceName") {
			locProxyBuffersSize, _ := proxyBuffersEntry.GetAsString("size")
			numberOfProxyBuffers, _ := proxyBuffersEntry.GetAsInt("number")
			return locProxyBuffersSize, numberOfProxyBuffers, err
		}
	}

	if len(errstrings) > 0 {
		err = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return "", 0, err
}

func handleUpstreamKeepAlive(upstreamKeepAliveAnnotation parser.ParsedValidatedAnnotation) (map[string]int, error) {
	var errstrings []string
	var err error

	upstreamKeepAlive := make(map[string]int)

	for _, upstreamKeepAliveAnnotationEntry := range upstreamKeepAliveAnnotation.Entries {
		if upstreamKeepAliveAnnotationEntry.Exists("keepalive") && upstreamKeepAliveAnnotationEntry.Exists("serviceName") {
			svcNames, _ := upstreamKeepAliveAnnotationEntry.GetAsStrings("serviceName")
			glog.Infof("serviceNames: %v", svcNames)
			for _, svcName := range svcNames {
				if keepAliveInt, exists := upstreamKeepAliveAnnotationEntry.GetAsInt("keepalive"); exists && keepAliveInt >= 0 {
					upstreamKeepAlive[svcName] = keepAliveInt
				} else if exists && keepAliveInt < 0 {
					glog.Infof("Invalid entry: %v", upstreamKeepAliveAnnotationEntry)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry: %v. ", upstreamKeepAliveAnnotationEntry))
				}
			}
		}
	}

	if len(errstrings) > 0 {
		err = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return upstreamKeepAlive, err
}

func handleCustomErrors(ingEx *IngressEx) (map[string][]IngressNginxCustomError, []IngressNginxCustomError, error) {
	var err error
	var customErrors map[string][]IngressNginxCustomError
	var globalCustomErrors []IngressNginxCustomError

	if customErrorString, exists := ingEx.Ingress.Annotations["ingress.bluemix.net/custom-errors"]; exists {
		customErrors, globalCustomErrors, err = parseCustomErrors(customErrorString)
		if err != nil {
			glog.Errorf("error in parseCustomErrors parsing and validation")
		}
	}
	glog.Infof("getCustomErrors: customErrors=%v globalCustomErrors=%v", customErrors, globalCustomErrors)
	return customErrors, globalCustomErrors, err
}

func parseCustomErrors(annotationStringFromIng string) (map[string][]IngressNginxCustomError, []IngressNginxCustomError, error) {
	customErrors := make(map[string][]IngressNginxCustomError)
	var globalCustomErrors []IngressNginxCustomError

	annotationModel, err := parser.ParseInputForAnnotation("ingress.bluemix.net/custom-errors", annotationStringFromIng)
	if err != nil {
		glog.Errorf("In ingress.bluemix.net/custom-errors (%v) contains invalid declaration.  err = %v, ", annotationStringFromIng, err)
		return customErrors, globalCustomErrors, err
	}

	for _, entry := range annotationModel.Entries {
		var entryCustomError IngressNginxCustomError
		var httpAllStatus string
		httpErrorValue, httpErrorExists := entry.GetAsStrings("httpError")
		if httpErrorExists {
			for _, httpStatus := range httpErrorValue {
				httpAllStatus = httpStatus + " " + httpAllStatus
			}
			entryCustomError.HTTPStatus = strings.TrimSpace(httpAllStatus)

		}
		actionName, actionNameExists := entry.GetAsString("errorActionName")
		if actionNameExists {
			entryCustomError.Action = actionName
		}
		if entry.Exists("serviceName") {
			svcName, svcNameExists := entry.GetAsString("serviceName")
			if svcNameExists {
				customErrors[svcName] = append(customErrors[svcName], entryCustomError)
			}
		} else {
			globalCustomErrors = append(globalCustomErrors, entryCustomError)
		}
	}

	glog.Infof("parseCustomErrors: customErrors=%v, globalCustomErrors=%v", customErrors, globalCustomErrors)
	return customErrors, globalCustomErrors, nil
}

func handleCustomErrActions(snippet []string, ingressName, annotation, deliminator string) []CustomErrorActions {
	var errActions []CustomErrorActions
	bracketIndex := GetIndexesOfValue(snippet, deliminator, " ")
	startIndex := 0
	for _, endIndex := range bracketIndex {
		var errorAction CustomErrorActions
		var errorValue []string
		if strings.Contains(snippet[startIndex], "errorActionName") {
			errorAction.Name = strings.Split(strings.Split(snippet[startIndex], "=")[1], " ")[0]
		}
		for i := startIndex + 1; i < endIndex; i++ {
			errorValue = append(errorValue, snippet[i])
		}
		errorAction.Value = errorValue
		startIndex = endIndex + 1
		errActions = append(errActions, errorAction)
	}

	glog.Infof("in %v, the handleCustomErrActions snippets return the following map %v", ingressName, errActions)
	return errActions
}

func handleAppIDAuth(annotation parser.ParsedValidatedAnnotation, serviceName string) (secret, namespace, requestType string, idToken bool, err error) {
	var errstrings []string

	for _, entry := range annotation.Entries {
		if entry.Exists("serviceName") {
			svcNames, _ := entry.GetAsStrings("serviceName")
			for _, svcName := range svcNames {
				if serviceName == svcName {
					if entry.Exists("namespace") {
						namespace, _ = entry.GetAsString("namespace")
					} else {
						namespace = "default"
					}

					if entry.Exists("requestType") {
						requestType, _ = entry.GetAsString("requestType")
						if requestType == "api" {
							glog.Info("handleAppIDAuth: requestType set to api")
						} else if requestType == "web" {
							glog.Info("handleAppIDAuth: requestType set to web")
						} else {
							errstrings = append(errstrings, fmt.Sprintf("handleAppIDAuth: Incorrect 'RequestType' provided in %v, must be 'api' or 'web'", requestType))
						}
					} else {
						requestType = "api"
					}

					if entry.Exists("idToken") {
						idToken, _ = entry.GetAsBool("idToken")
					} else {
						idToken = true
					}

					if entry.Exists("bindSecret") {
						secret, _ = entry.GetAsString("bindSecret")
					} else {
						errstrings = append(errstrings, fmt.Sprintf("handleAppIDAuth: Missing required field 'bindSecret'"))
					}
				}
			}
		}
	}

	if len(errstrings) > 0 {
		err = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return
}

func handleGlobalRatelimitzones(globalRatelimitAnnotation parser.ParsedValidatedAnnotation, ingressPodCount int, ingressName string) ([]RateLimitZone, error) {
	var errstrings []string
	var finalErr error
	var globalRatelimitZones []RateLimitZone
	var uniqueGlobalZonenameCount = 0
	var globalZoneName, gKey, gRateUnit, gClusterwideRateVal, gClusterwideConnVal string
	var gBurst int

	for _, globalRatelimitEntry := range globalRatelimitAnnotation.Entries {
		glog.Infof("globalRatelimitEntry: %v", globalRatelimitEntry)
		uniqueGlobalZonenameCount = uniqueGlobalZonenameCount + 1

		if globalRatelimitEntry.Exists("key") {
			if globalRatelimitEntry.Exists("rate") && globalRatelimitEntry.Exists("conn") {

				gConn, _ := globalRatelimitEntry.GetAsInt("conn")
				gRateTemp, _ := globalRatelimitEntry.GetAsValueUnitStringArray("rate")
				gRate := gRateTemp[0]
				gRateInt, err := strconv.Atoi(gRate)
				if err != nil {
					glog.Errorf("Error converting rate to int: %s\n", gRate)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry %v. ", globalRatelimitEntry))
				}
				gRateUnit = gRateTemp[1]
				gClusterwideRateVal = getClusterwideVal(gRateInt, ingressPodCount)
				gClusterwideRateValInt, err := strconv.Atoi(gClusterwideRateVal)
				if err != nil {
					glog.Errorf("Error converting rate to int: %s\n", gClusterwideRateVal)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry %v. ", globalRatelimitEntry))
				}
				gBurst = getBurst(gClusterwideRateValInt)
				gClusterwideConnVal = getClusterwideVal(gConn, ingressPodCount)

			} else if globalRatelimitEntry.Exists("rate") && !globalRatelimitEntry.Exists("conn") {

				gRateTemp, _ := globalRatelimitEntry.GetAsValueUnitStringArray("rate")
				gRate := gRateTemp[0]
				gRateInt, err := strconv.Atoi(gRate)
				if err != nil {
					glog.Errorf("Error converting rate to int: %s\n", gRate)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry %v. ", globalRatelimitEntry))
				}
				gRateUnit = gRateTemp[1]
				gClusterwideRateVal = getClusterwideVal(gRateInt, ingressPodCount)
				gClusterwideRateValInt, err := strconv.Atoi(gClusterwideRateVal)
				if err != nil {
					glog.Errorf("Error converting rate to int: %s\n", gClusterwideRateVal)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry %v. ", globalRatelimitEntry))
				}
				gBurst = getBurst(gClusterwideRateValInt)

			} else if globalRatelimitEntry.Exists("conn") && !globalRatelimitEntry.Exists("rate") {

				gConn, _ := globalRatelimitEntry.GetAsInt("conn")
				gClusterwideConnVal = getClusterwideVal(gConn, ingressPodCount)
			}
			gKeyString, _ := globalRatelimitEntry.GetAsString("key")
			gKey = gKeyString
		}

		globalZoneName = getGlobalZoneName(gKey, uniqueGlobalZonenameCount, ingressName)
		zoneSer := RateLimitZone{
			Name:     globalZoneName,
			Key:      gKey,
			Rate:     gClusterwideRateVal,
			RateUnit: gRateUnit,
			Conn:     gClusterwideConnVal,
			Burst:    gBurst}
		glog.V(4).Infof("Global rate limit applied: %v", zoneSer)
		globalRatelimitZones = append(globalRatelimitZones, zoneSer)
	}

	if len(errstrings) > 0 {
		finalErr = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return globalRatelimitZones, finalErr
}

func handleUpstreamLBType(upstreamLBAnnotation parser.ParsedValidatedAnnotation, serviceName string) (map[string]string, error) {
	var errstrings []string
	var err error

	upstreamLBType := make(map[string]string)

	for _, upstreamLBAnnotationEntry := range upstreamLBAnnotation.Entries {
		if upstreamLBAnnotationEntry.Exists("lb-type") && upstreamLBAnnotationEntry.Exists("serviceName") {
			svcNames, _ := upstreamLBAnnotationEntry.GetAsStrings("serviceName")
			glog.Infof("serviceNames: %v", svcNames)
			for _, svcName := range svcNames {
				if svcName == serviceName {
					if lbType, exists := upstreamLBAnnotationEntry.GetAsString("lb-type"); exists && len(lbType) > 0 {
						upstreamLBType[svcName] = lbType
					} else if exists && len(lbType) > 0 {
						glog.Infof("Invalid entry: %v", upstreamLBAnnotationEntry)
						errstrings = append(errstrings, fmt.Sprintf("Invalid entry: %v. ", upstreamLBAnnotationEntry))
					}
				}
			}
		}
	}

	if len(errstrings) > 0 {
		err = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return upstreamLBType, err
}

// Get the Zone name appended with Key Value
func getGlobalZoneName(gKey string, uniqueGlobalZonenameCount int, ingressName string) (globalZoneName string) {
	if strings.Contains(gKey, "$uri") {
		globalZoneName = "uri"
		globalZoneName = ingressName + "_" + globalZoneName + "_" + strconv.Itoa(uniqueGlobalZonenameCount)
		return globalZoneName
	} else if strings.HasPrefix(gKey, "$http_") {

		globalZoneName = gKey
		globalZoneName = strings.Trim(globalZoneName, "$")
		globalZoneName = ingressName + "_" + globalZoneName + "_" + strconv.Itoa(uniqueGlobalZonenameCount)
		return globalZoneName
	}
	return ""
}

func handleLocRateLimitZones(serviceRatelimitAnnotation parser.ParsedValidatedAnnotation, ingressPodCount int, ingressName string) ([]RateLimitZone, error) {
	var errstrings []string
	var finalErr error
	var locationRateLimitZones []RateLimitZone
	var ZoneEntryCount = 0
	var zoneName, keyVal, clusterwideRateVal, rateUnit, clusterwideConnVal, connMem, rateMem string
	var burst int

	for _, Entry := range serviceRatelimitAnnotation.Entries {
		glog.V(4).Infof("Entry: %v ", Entry)
		ZoneEntryCount = ZoneEntryCount + 1

		if Entry.Exists("key") && Entry.Exists("serviceName") {

			svcNames, _ := Entry.GetAsStrings("serviceName")
			servicecount := len(svcNames)

			if Entry.Exists("rate") && Entry.Exists("conn") {
				rateTemp, _ := Entry.GetAsValueUnitStringArray("rate")
				rateVal := rateTemp[0]
				rateValInt, err := strconv.Atoi(rateVal)
				if err != nil {
					glog.Errorf("Error converting rate to int: %s\n", rateVal)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry %v. ", Entry))
				}
				rateUnit = rateTemp[1]
				clusterwideRateVal = getClusterwideVal(rateValInt, ingressPodCount)
				clusterwideRateValInt, err := strconv.Atoi(clusterwideRateVal)
				if err != nil {
					glog.Errorf("Error converting rate to int: %s\n", clusterwideRateVal)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry %v. ", Entry))
				}
				burst = getBurst(clusterwideRateValInt)
				rateMem = getMemory(clusterwideRateValInt, servicecount)

				connVal, _ := Entry.GetAsInt("conn")
				clusterwideConnVal = getClusterwideVal(connVal, ingressPodCount)
				clusterwideConnValInt, err := strconv.Atoi(clusterwideConnVal)
				if err != nil {
					glog.Errorf("Error converting conn to int: %s\n", clusterwideConnVal)
				}
				connMem = getMemory(clusterwideConnValInt, servicecount)

			} else if Entry.Exists("rate") && !Entry.Exists("conn") {
				rateTemp, _ := Entry.GetAsValueUnitStringArray("rate")
				rateVal := rateTemp[0]
				rateValInt, err := strconv.Atoi(rateVal)
				if err != nil {
					glog.Errorf("Error converting rate to int: %s\n", rateVal)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry %v. ", Entry))
				}
				rateUnit = rateTemp[1]
				clusterwideRateVal = getClusterwideVal(rateValInt, ingressPodCount)
				clusterwideRateValInt, err := strconv.Atoi(clusterwideRateVal)
				if err != nil {
					glog.Errorf("Error converting rate to int: %s\n", clusterwideRateVal)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry %v. ", Entry))
				}
				burst = getBurst(clusterwideRateValInt)
				rateMem = getMemory(clusterwideRateValInt, servicecount)

				clusterwideConnVal = ""
				connMem = getMemory(1, servicecount)

			} else if !Entry.Exists("rate") && Entry.Exists("conn") {
				rateUnit = ""
				clusterwideRateVal = ""
				burst = 0
				rateMem = getMemory(1, servicecount)

				connVal, _ := Entry.GetAsInt("conn")
				clusterwideConnVal = getClusterwideVal(connVal, ingressPodCount)
				clusterwideConnValInt, err := strconv.Atoi(clusterwideConnVal)
				if err != nil {
					glog.Errorf("Error converting conn to int: %s\n", clusterwideConnVal)
					errstrings = append(errstrings, fmt.Sprintf("Invalid entry %v. ", Entry))
				}
				connMem = getMemory(clusterwideConnValInt, servicecount)
			}

			keyVal, _ = Entry.GetAsString("key")
			zoneSvcName := strings.Join(svcNames, "_")
			zoneName = getZoneName(zoneSvcName, keyVal, ZoneEntryCount, ingressName)

			zoneloc := RateLimitZone{Name: zoneName, Key: keyVal, Rate: clusterwideRateVal, RateUnit: rateUnit,
				Conn: clusterwideConnVal, ConnMem: connMem, RateMem: rateMem, Burst: burst}
			glog.V(4).Infof("zoneloc: %v ", zoneloc)

			locationRateLimitZones = append(locationRateLimitZones, zoneloc)
		} else {
			glog.Errorf("In ingress.bluemix.net/service-rate-limit contains invalid declaration: %v, ignoring", Entry)
			errstrings = append(errstrings, fmt.Sprintf("Invalid declaration %v. ", Entry))
		}
	}

	if len(errstrings) > 0 {
		finalErr = fmt.Errorf(strings.Join(errstrings, ""))
	}

	return locationRateLimitZones, finalErr
}

func handleHSTS(annotation parser.ParsedValidatedAnnotation) (enabled bool, maxAge int, includeSubdomains bool, err error) {
	for _, entry := range annotation.Entries {
		if entry.Exists("maxAge") {
			maxAge, _ = entry.GetAsInt("maxAge")
		} else {
			maxAge = 31536000
		}

		if entry.Exists("includeSubdomains") {
			includeSubdomains, _ = entry.GetAsBool("includeSubdomains")
		} else {
			includeSubdomains = true
		}

		if entry.Exists("enabled") {
			enabled, _ = entry.GetAsBool("enabled")
		} else {
			err = fmt.Errorf("invalid format. Annotation must be of the format 'enabled=<true or false>'")
		}
	}

	return
}

func handleUpstreamMaxFails(annotation parser.ParsedValidatedAnnotation, serviceName string) (maxFails string, err error) {
	for _, entry := range annotation.Entries {
		if entry.Exists("serviceName") {
			svcNames, _ := entry.GetAsStrings("serviceName")
			for _, svcName := range svcNames {
				if serviceName == svcName {
					if entry.Exists("max-fails") {
						maxFails, _ = entry.GetAsString("max-fails")
					} else {
						err = fmt.Errorf("handleUpstreamMaxFails: Missing required field 'max-fails'")
					}
				}
			}
		} else {
			if entry.Exists("max-fails") {
				maxFails, _ = entry.GetAsString("max-fails")
			} else {
				err = fmt.Errorf("handleUpstreamMaxFails: Missing required field 'max-fails'")
			}
		}
	}

	return
}

func handleUpstreamFailTimeout(annotation parser.ParsedValidatedAnnotation, serviceName string) (failTimeout string, err error) {
	for _, entry := range annotation.Entries {
		if entry.Exists("serviceName") {
			svcNames, _ := entry.GetAsStrings("serviceName")
			for _, svcName := range svcNames {
				if serviceName == svcName {
					if entry.Exists("fail-timeout") {
						failTimeout, _ = entry.GetAsString("fail-timeout")
					} else {
						err = fmt.Errorf("handleUpstreamFailTimeout: Missing required field 'fail-timeout'")
					}
				}
			}
		} else {
			if entry.Exists("fail-timeout") {
				failTimeout, _ = entry.GetAsString("fail-timeout")
			} else {
				err = fmt.Errorf("handleUpstreamFailTimeout: Missing required field 'fail-timeout'")
			}
		}
	}

	return
}

func handleLocationModifier(locationModifierAnnotation parser.ParsedValidatedAnnotation, serviceName string) (locModifier string, err error) {
	for _, locationModifierEntry := range locationModifierAnnotation.Entries {
		glog.Infof("locationModifierEntry %v", locationModifierEntry)

		if locationModifierEntry.Exists("modifier") && locationModifierEntry.Exists("serviceName") {
			svcNames, _ := locationModifierEntry.GetAsStrings("serviceName")
			glog.Infof("serviceName %v", svcNames)
			for _, svcName := range svcNames {
				if svcName == serviceName {
					if valueAsString, exists := locationModifierEntry.GetAsString("modifier"); exists {
						locModifier = validateLocationModifier(valueAsString)
						if locModifier == "" {
							err = fmt.Errorf("Invalid modifier for %s. Allowed Modifiers: '=','~*','^~','~'", serviceName)
						}
						break
					}
				}
			}
		}
	}

	return
}

//Get locRateLimitZones for Service-ratelimit
func getRatelimitZonesForService(rateLimitZones []RateLimitZone, serviceName string) []RateLimitZone {
	var locRateLimitZones []RateLimitZone
	for _, serviceRateLimitZone := range rateLimitZones {
		if strings.Contains(serviceRateLimitZone.Name, serviceName) {
			locRateLimitZones = append(locRateLimitZones, serviceRateLimitZone)
		}
	}
	return locRateLimitZones
}

//Get zonename for Service-ratelimit
func getZoneName(svcNames string, keyVal string, ZoneEntryCount int, ingressName string) (zoneName string) {
	if strings.Contains(svcNames, ",") {
		svcNames = strings.Replace(svcNames, ",", "_", -1)
	}
	if strings.Contains(svcNames, ":") {
		svcNames = strings.Replace(svcNames, ":", "_", -1)
	}

	zoneKeyPart := strings.Trim(keyVal, "$")
	zoneName = svcNames + "_" + zoneKeyPart + "_" + strconv.Itoa(ZoneEntryCount) + "_" + ingressName
	return zoneName
}

//Get Burst value 20% of Rate request
func getBurst(rate int) (burst int) {
	burstRate := int(0.2 * float64(rate))
	if burstRate == 0 {
		burstRate = 1
	}
	return burstRate
}

//Get cluster wide rate and conn
func getClusterwideVal(Value int, ingressPodCount int) (val string) {
	if ingressPodCount == 0 {
		ingressPodCount = 1
	}
	var newVal = Value / ingressPodCount
	if newVal <= 1 {
		newVal = 1
	}
	return strconv.Itoa(newVal)
}

//Get the Memory value based on rate
func getMemory(rate int, servicecount int) (mem string) {
	var retval string
	memval := ((128 * servicecount * rate * 2) / 1024) / 1024
	if memval <= 0 {
		retval = "1m"
	} else {
		val := strconv.Itoa(memval)
		retval = val + "m"
	}
	return retval
}

func validateLocationModifier(modifier string) (actualModifier string) {
	// order of array matters to ensure exact substring match check
	if strings.HasPrefix(modifier, "'") && strings.HasSuffix(modifier, "'") {
		runes := []rune(modifier)
		exactModifier := string(runes[1 : len(modifier)-1])
		validLocationModifiers := []string{"=", "~*", "^~", "~"}
		for _, validLocationModifier := range validLocationModifiers {
			if exactModifier == validLocationModifier {
				actualModifier = validLocationModifier
				break
			}
		}
	}

	return
}

func handleIAMEndpoint(annotation parser.ParsedValidatedAnnotation) (endpoint string, err error) {
	for _, entry := range annotation.Entries {
		if entry.Exists("endpoint") {
			endpoint, _ = entry.GetAsString("endpoint")
		} else {
			err = fmt.Errorf("invalid format. Annotation must be of the format 'endpoint=<endpoint>'")
		}
	}

	return
}

func handleWatsonPreAuth(annotation parser.ParsedValidatedAnnotation) (map[string]bool, map[string]string, map[string]string, error) {
	authServices := make(map[string]bool)
	secondaryHost := make(map[string]string)
	secondaryIngSvc := make(map[string]string)

	for _, entry := range annotation.Entries {
		if entry.Exists("serviceName") {
			svcName, _ := entry.GetAsString("serviceName")
			authServices[svcName] = true

			if entry.Exists("secondaryHost") {
				hostValue, _ := entry.GetAsString("secondaryHost")
				secondaryHost[svcName] = hostValue
				albID := os.Getenv("ALB_ID")
				var err error
				if albID == "" {
					err = fmt.Errorf("ALB_ID env variable is empty")
				} else if !strings.Contains(albID, "public") {
					err = fmt.Errorf("ALB_ID env var is not a public albID: " + albID)
				} else {
					secondaryIngSvc[svcName] = strings.Replace(albID, "public", "private", 1)
				}

				if err != nil {
					return authServices, secondaryHost, secondaryIngSvc, err
				}
			}
		} else {
			err := fmt.Errorf("invalid format. Annotation must be of the format 'serviceName=<svcName>'")
			return authServices, secondaryHost, secondaryIngSvc, err
		}
	}

	return authServices, secondaryHost, secondaryIngSvc, nil
}

func handleWatsonPostAuth(annotation parser.ParsedValidatedAnnotation) (map[string]bool, error) {
	authServices := make(map[string]bool)

	for _, entry := range annotation.Entries {
		if entry.Exists("serviceName") {
			svcName, _ := entry.GetAsString("serviceName")
			authServices[svcName] = true
		} else {
			err := fmt.Errorf("invalid format. Annotation must be of the format 'serviceName=<svcName>'")
			return authServices, err
		}
	}

	return authServices, nil
}

func handleDefaultServer(annotation parser.ParsedValidatedAnnotation) (enabled bool, err error) {
	for _, entry := range annotation.Entries {
		if entry.Exists("enabled") {
			enabled, _ = entry.GetAsBool("enabled")
		} else {
			err = fmt.Errorf("invalid format. Annotation must be of the format 'enabled=<boolean>'")
		}
	}

	return enabled, err
}
