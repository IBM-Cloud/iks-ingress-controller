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
package controller

import (
	"github.com/golang/glog"
	extensions "k8s.io/api/extensions/v1beta1"
	networking "k8s.io/api/networking/v1beta1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
)

var runtimeScheme = k8sruntime.NewScheme()

func init() {
	networking.AddToScheme(runtimeScheme)
	extensions.AddToScheme(runtimeScheme)
}

func fromExtensions(old *extensions.Ingress) (*networking.Ingress, error) {

	networkingIngress := &networking.Ingress{}

	err := runtimeScheme.Convert(old, networkingIngress, nil)

	if err != nil {
		return nil, err
	}

	glog.V(5).Infof("fromExtensions converted extensions to networking : %v", networkingIngress.Name)

	return networkingIngress, nil
}

func toIngress(obj interface{}) (*networking.Ingress, bool) {
	oldVersion, inExtension := obj.(*extensions.Ingress)
	if inExtension {
		ing, err := fromExtensions(oldVersion)
		if err != nil {
			glog.Errorf("toIngress unexpected error converting Ingress from extensions package: %v", err)
			return nil, false
		}

		glog.V(5).Infof("toIngress converted extensions to networking : %v", ing.Name)

		return ing, true
	}

	if ing, ok := obj.(*networking.Ingress); ok {

		glog.V(5).Infof("toIngress returned back the original networking : %v", ing.Name)

		return ing, true
	}

	return nil, false
}
