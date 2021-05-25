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
	"github.com/golang/glog"
)

// buildLocation $server $server.(Non)MutualAuthPaths
func buildLocation(a interface{}, b []string) Server {
	server, ok := a.(Server)
	if !ok {
		glog.Errorf("Template Function buildLocation: Expected a 'Server' type but %T was returned", a)
		return Server{}
	}

	locationList := []Location{}
	for _, loc := range server.Locations {
		for _, str := range b {
			if str == loc.Path {
				locationList = append(locationList, loc)
			}
		}
	}

	server.Locations = locationList
	return server
}
