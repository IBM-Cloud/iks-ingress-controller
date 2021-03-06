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

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// There seems to be no composite interface in the kubernetes api package,
// so we have to declare our own.
type apiObject interface {
	meta_v1.Object
	runtime.Object
}

// GetMapKeyAsBool searches the map for the given key and parses the key as bool
func GetMapKeyAsBool(m map[string]string, key string, context apiObject) (bool, bool, error) {
	if str, exists := m[key]; exists {
		b, err := strconv.ParseBool(str)
		if err != nil {
			return false, exists, fmt.Errorf("%s %v/%v '%s' contains invalid bool: %v, ignoring", context.GetObjectKind().GroupVersionKind().Kind, context.GetNamespace(), context.GetName(), key, err)
		}
		return b, exists, nil
	}
	return false, false, nil
}

// GetMapKeyAsInt tries to find and parse a key in a map as int64
func GetMapKeyAsInt(m map[string]string, key string, context apiObject) (int64, bool, error) {
	if str, exists := m[key]; exists {
		i, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			return 0, exists, fmt.Errorf("%s %v/%v '%s' contains invalid integer: %v, ignoring", context.GetObjectKind().GroupVersionKind().Kind, context.GetNamespace(), context.GetName(), key, err)
		}
		return i, exists, nil
	}
	return 0, false, nil
}

// GetMapKeyAsStringSlice tries to find and parse a key in the map as string slice splitting it on delimiter
func GetMapKeyAsStringSlice(m map[string]string, key string, context apiObject, delimiter string) ([]string, bool, error) {
	if str, exists := m[key]; exists {
		slice := strings.Split(str, delimiter)
		return slice, exists, nil
	}
	return nil, false, nil
}

// GetIndexesOfValue returns all the indexes of a key in the string slice
func GetIndexesOfValue(arr []string, key string, cutset string) []int {
	var indexArray []int
	for index, values := range arr {
		if strings.Compare(strings.Trim(values, cutset), key) == 0 {
			indexArray = append(indexArray, index)
		}
	}

	return indexArray
}
