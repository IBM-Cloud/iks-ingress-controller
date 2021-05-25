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

// Config holds NGINX configuration parameters
type Config struct {
	LocationSnippets              map[string][]string
	AllLocationSnippet            []string
	ServerSnippets                []string
	ServerTokens                  bool
	ProxyConnectTimeout           string
	ProxyReadTimeout              string
	ClientMaxBodySize             string
	LargeClientHeaderBuffers      string
	HTTP2                         bool
	RedirectToHTTPS               bool
	MainHTTPSnippets              []string
	MainServerNamesHashBucketSize string
	MainServerNamesHashMaxSize    string
	MainLogFormat                 string
	MainLogFormatEscapeJSON       string
	VtsStatusZoneSize             string
	ProxyBuffering                bool
	ProxyMaxTempFileSize          string
	ProxyProtocol                 bool
	ProxyHideHeaders              []string
	ProxyPassHeaders              []string
	HSTS                          bool
	HSTSMaxAge                    int
	HSTSIncludeSubdomains         bool
	InKeepAlive                   string
	InKeepaliveRequests           string
	Backlog                       string
	ReusePort                     bool
	ProxySslVerifyDepth           int

	// http://nginx.org/en/docs/http/ngx_http_realip_module.html
	RealIPHeader    string
	SetRealIPFrom   []string
	RealIPRecursive bool
	Stream          string

	// http://nginx.org/en/docs/http/ngx_http_ssl_module.html
	MainServerSSLProtocols           string
	MainServerSSLPreferServerCiphers bool
	MainServerSSLCiphers             string
	MainServerSSLDHParam             string

	// Ratelimit Annotations
	RatelimitMemory string
	RatelimitValue  string
	RatelimitBurst  string

	//ActivityTracker log
	ActivityTracker bool

	//Customer Logs
	CustomerLogs bool

	//Access Logs
	AccessLogEnabled bool
	AccessLogBuffer  string
	AccessLogFlush   string

	//Indicates if istio is present
	IsIstioPresent bool
	IstioPort      int64
	IstioIP        string

	IamGlobalEndpoint string
}

// NewDefaultConfig creates a Config with default values
func NewDefaultConfig() *Config {
	return &Config{
		ServerTokens:               true,
		ProxyConnectTimeout:        "60s",
		ProxyReadTimeout:           "60s",
		ClientMaxBodySize:          "1m",
		MainServerNamesHashMaxSize: "512",
		ProxyBuffering:             true,
		HSTSMaxAge:                 2592000,
		RatelimitMemory:            "10m",
		RatelimitValue:             "10r/s",
		RatelimitBurst:             "5",
		ActivityTracker:            true,
		CustomerLogs:               true,
		AccessLogEnabled:           false,
		AccessLogBuffer:            "100K",
		AccessLogFlush:             "5m",
		ProxySslVerifyDepth:        5,
	}
}
