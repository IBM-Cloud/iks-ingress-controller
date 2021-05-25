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

package internal

import (
	"encoding/json"
	"io/ioutil"

	"k8s.io/apimachinery/pkg/util/version"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"
)

// ParseErrors reads the content of the error file and decodes it into a map.
func parseErrors(errMsg ErrMsg, paths ...string) error {
	for _, path := range paths {
		errs := make(ErrMsg)
		errFile, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(errFile, &errs); err != nil {
			return err
		}
		for k, v := range errs {
			errMsg[k] = v
		}
	}
	return nil
}

// IsNetworkingIngressAvailable indicates if package "k8s.io/api/networking/v1beta1" is available or not
var IsNetworkingIngressAvailable bool

// NetworkingIngressAvailable checks if the package "k8s.io/api/networking/v1beta1" is available or not
func NetworkingIngressAvailable(client clientset.Interface) bool {
	// check kubernetes version to use new ingress package or not
	version114, err := version.ParseGeneric("v1.14.0")
	if err != nil {
		klog.Errorf("unexpected error parsing version: %v", err)
		return false
	}

	serverVersion, err := client.Discovery().ServerVersion()
	if err != nil {
		klog.Errorf("unexpected error parsing Kubernetes version: %v", err)
		return false
	}

	runningVersion, err := version.ParseGeneric(serverVersion.String())
	if err != nil {
		klog.Errorf("unexpected error parsing running Kubernetes version: %v", err)
		return false
	}

	return runningVersion.AtLeast(version114)
}
