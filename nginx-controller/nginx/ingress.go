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
	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1beta1"
)

// Secrets ...
type Secrets struct {
	SecretName string
	Secret     *api.Secret
}

// IstioIngressUpstream ...
type IstioIngressUpstream struct {
	BackendSvc string
	Endpoints  []string
}

// ProxySSLConfig is to store the SSL config parameters that are used on the upstream connections
type ProxySSLConfig struct {
	ProxySSLVerifyDepth int
	ProxySSLName        string
}

// UpstreamSSLConfig is to store the secrets and other SSL config parameters that are used on the upstream connections
type UpstreamSSLConfig struct {
	Secrets        Secrets
	ProxySSLConfig ProxySSLConfig
}

// IngressEx holds an Ingress along with Secrets and Endpoints of the services
// that are referenced in this Ingress
type IngressEx struct {
	Ingress               *networking.Ingress
	Secrets               map[string]*api.Secret
	Endpoints             map[string][]string
	UpstreamSSLData       map[string]UpstreamSSLConfig
	IsUpsreamSSLs         bool
	SSLCommonNames        map[string]string
	PlainSSL              []string
	IstioIngressUpstreams []IstioIngressUpstream
}
