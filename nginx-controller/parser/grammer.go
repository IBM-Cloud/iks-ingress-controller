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

package parser

import (
	"encoding/json"
	"io/ioutil"
)

// AnnotationGrammer ...
type AnnotationGrammer struct {
	Definitions []struct {
		Label           string `json:"label"`
		MandatoryFields []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"mandatoryFields"`
		AtleastoneFields []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"atleastoneFields"`
		OptionalFields []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"optionalFields"`
		StrictOrdering string `json:"strictOrdering,omitempty"`
		KeyLessEntry   string `json:"keyLessEntry,omitempty"`
	} `json:"definition"`
}

//Grammer Model

// AnnotationDefintion ...
type AnnotationDefintion struct {
	mandatoryfieldDefinitions           map[string]ParseMethodDef
	atleastOneMandatoryFieldDefinitions map[string]ParseMethodDef
	optionalFieldDefinitions            map[string]ParseMethodDef
	keyLessAllowed                      bool
	strictOrdering                      bool
	label                               string
}

// Load user Defined annotations defintions from json file

func getAnnotationDefintions(filename string) AnnotationGrammer {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	var annotationGrammer AnnotationGrammer
	json.Unmarshal(raw, &annotationGrammer)
	return annotationGrammer
}

// Prepare ...
func Prepare(filenames ...string) {
	if len(filenames) < 1 {
		err := prepareAnnotationDefintions(getAnnotationDefintions("annotations.json"))
		if err != nil {
			panic(err)
		}
	} else {
		for _, filename := range filenames {
			err := prepareAnnotationDefintions(getAnnotationDefintions(filename))
			if err != nil {
				panic(err)
			}
		}
	}
}
