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
	"fmt"
	"strings"

	"github.com/golang/glog"
)

//Parser Code

func prepareFields(entry Entry, entryParts []string, definitions map[string]ParseMethodDef) (err error) {
	for _, fieldKeyValueStr := range entryParts {
		fieldKeyValueStr = strings.TrimSpace(fieldKeyValueStr)
		if fieldKeyValueStr == "" {
			continue
		}
		fieldparts := strings.SplitN(fieldKeyValueStr, "=", 2)
		if len(fieldparts) != 2 {
			glog.Warning("Annotation format error: field invalid : ", fieldKeyValueStr)
			return fmt.Errorf("invalid annotation format: %v", fieldKeyValueStr)
		}
		if fieldParser, fieldDefintionExists := definitions[fieldparts[0]]; fieldDefintionExists {
			subfieldParts := strings.Split(fieldparts[1], ",")
			for _, subfieldPart := range subfieldParts {
				if subfieldPart == "" {
					glog.Warning("Annotation format error: field invalid : ", fieldparts[0])
					return fmt.Errorf("invalid Annotation format: %v", fieldparts[0])
				}

				valueOutput, err := fieldParser(subfieldPart)
				if err != nil {
					glog.Warning(err.Error())
					glog.Warning("Annotation format error: Parsing of field type failed :", fieldparts[0])
					return err
				}
				entry.Put(fieldparts[0], valueOutput)
			}
		}
	}
	return nil
}

func areAllMandatoryFieldsProvided(entry Entry, definition AnnotationDefintion) (isAllMandatoryFieldsProvided bool) {
	for fieldName := range definition.mandatoryfieldDefinitions {
		if !entry.Exists(fieldName) {
			glog.Warning("Annotation format error: Mandatory field missing : ", fieldName)
			return false
		}
	}
	return true
}

func parseAllMandatoryFields(entry Entry, entryParts []string, definition AnnotationDefintion) (err error) {
	if err = prepareFields(entry, entryParts, definition.mandatoryfieldDefinitions); err != nil {
		return err
	}
	if !areAllMandatoryFieldsProvided(entry, definition) {
		return fmt.Errorf("not all mandatory Fields provided in annotation: %v", definition.label)
	}
	return err
}

func validateAtleastOneMandatoryFields(entry Entry, definition AnnotationDefintion) (validateAtleastOneMandatoryFields bool) {
	if len(definition.atleastOneMandatoryFieldDefinitions) == 0 {
		return true
	}
	for fieldName := range definition.atleastOneMandatoryFieldDefinitions {
		if entry.Exists(fieldName) {
			return true
		}
	}
	return false
}

func parseAtleastOneFields(entry Entry, entryParts []string, definition AnnotationDefintion) (err error) {
	//var atleastOneFound bool
	err = prepareFields(entry, entryParts, definition.atleastOneMandatoryFieldDefinitions)
	if err != nil {
		return err
	}

	if !validateAtleastOneMandatoryFields(entry, definition) {
		return fmt.Errorf("Not all mandatory Fields provided in annotation: %v ", definition.label)
	}
	return err
}

func parseOptionalFields(entry Entry, entryParts []string, definition AnnotationDefintion) (err error) {
	err = prepareFields(entry, entryParts, definition.optionalFieldDefinitions)
	return err
}

func checkIfInvalidKeysProvided(entryParts []string, definition AnnotationDefintion) (invalidKeysProvided bool) {
	for _, fieldKeyValueStr := range entryParts {

		fieldKeyValueStr = strings.TrimSpace(fieldKeyValueStr)
		if fieldKeyValueStr == "" {
			continue
		}
		fieldparts := strings.Split(fieldKeyValueStr, "=")
		if len(fieldparts) != 2 {
			continue
		} else {
			if _, fieldDefintionExists := definition.mandatoryfieldDefinitions[fieldparts[0]]; fieldDefintionExists {
				continue
			} else if _, fieldDefintionExists := definition.atleastOneMandatoryFieldDefinitions[fieldparts[0]]; fieldDefintionExists {
				continue
			} else if _, fieldDefintionExists := definition.optionalFieldDefinitions[fieldparts[0]]; fieldDefintionExists {
				continue
			}
			glog.V(3).Infof("checkIfInvalidKeysProvided: invalid key is  %s", fieldparts[0])
			return true

		}
	}
	return false

}

//Annotation Library
var annotationToDefintionMap = make(map[string]AnnotationDefintion)

func prepareAnnotationDefintions(annotationGrammer AnnotationGrammer) (err error) {

	for _, defintion := range annotationGrammer.Definitions {
		var mandatoryfieldDefinitions = make(map[string]ParseMethodDef)

		for _, mandatortFieldDefinitionInput := range defintion.MandatoryFields {
			parseMethodDef := fieldTypeToParserMap[mandatortFieldDefinitionInput.Type]
			if parseMethodDef == nil {
				return fmt.Errorf("invalid field type %v", mandatortFieldDefinitionInput.Type)
			}
			mandatoryfieldDefinitions[mandatortFieldDefinitionInput.Name] = parseMethodDef
		}

		var atleastOneMandatoryFieldDefinitions = make(map[string]ParseMethodDef)

		for _, atleasOneFieldDefinitionInput := range defintion.AtleastoneFields {
			parseMethodDef := fieldTypeToParserMap[atleasOneFieldDefinitionInput.Type]
			if parseMethodDef == nil {
				return fmt.Errorf("invalid field type %v", atleasOneFieldDefinitionInput.Type)
			}

			atleastOneMandatoryFieldDefinitions[atleasOneFieldDefinitionInput.Name] = parseMethodDef
		}
		var optionalFieldDefinitions = make(map[string]ParseMethodDef)

		for _, optionalFieldDefinitionInput := range defintion.OptionalFields {
			parseMethodDef := fieldTypeToParserMap[optionalFieldDefinitionInput.Type]
			if parseMethodDef == nil {
				return fmt.Errorf("invalid field type %v", optionalFieldDefinitionInput.Type)
			}

			optionalFieldDefinitions[optionalFieldDefinitionInput.Name] = parseMethodDef
		}

		var annotationDefintion AnnotationDefintion
		annotationDefintion.mandatoryfieldDefinitions = mandatoryfieldDefinitions
		annotationDefintion.atleastOneMandatoryFieldDefinitions = atleastOneMandatoryFieldDefinitions
		annotationDefintion.optionalFieldDefinitions = optionalFieldDefinitions
		annotationDefintion.label = defintion.Label

		keyLessAllowed, _ := parseBoolean(defintion.KeyLessEntry)
		annotationDefintion.keyLessAllowed = keyLessAllowed.(bool)
		strictOrdering, _ := parseBoolean(defintion.StrictOrdering)
		annotationDefintion.strictOrdering, _ = strictOrdering.(bool)
		annotationToDefintionMap[defintion.Label] = annotationDefintion
	}
	return nil
}

// ParseInputForAnnotation ...
func ParseInputForAnnotation(label string, input string) (parsedOutput ParsedValidatedAnnotation, err error) {
	glog.V(3).Infof("parsing annotation %s with entries %s", label, input)
	var parsedAnnotation ParsedValidatedAnnotation
	var Entries []Entry

	definition, definitionExists := annotationToDefintionMap[label]
	if !definitionExists {
		return parsedAnnotation, fmt.Errorf("invalid Annotation label: %s", label)
	}
	if input == "" {
		return parsedAnnotation, fmt.Errorf("no entries for the annotation: %s", input)
	}

	input = strings.Replace(strings.Replace(input, ";\n", ";", -1), "\n", ";", -1)
	entryStrings := strings.Split(input, ";")

	for _, entryString := range entryStrings {
		entryString = strings.Replace(strings.Replace(entryString, " =", "=", -1), "= ", "=", -1)
		entryString = strings.Replace(strings.Replace(entryString, " ,", ",", -1), ", ", ",", -1)
		entryString = strings.TrimSpace(entryString)
		if entryString == "" {
			continue
		}

		// CHECK IF KEYLESS ENTRY SUPPORTED

		if !strings.Contains(entryString, "=") && definition.keyLessAllowed {
			glog.Infof("annotation entry is keyless with value %s", entryString)
			keylessEntry := NewKeylessEntry(entryString)
			fmt.Println("Entry :::::: ", keylessEntry)
			Entries = append(Entries, keylessEntry)
			continue
		}

		entry := NewEntry()
		entryParts := strings.Split(entryString, " ")

		if checkIfInvalidKeysProvided(entryParts, definition) {
			glog.Warning("annotation format error : Invalid Keys Provided in the annotation entry: ", entryString)
			return parsedAnnotation, fmt.Errorf("annotation format error : Invalid Keys Provided in the annotation entry: %s", entryString)
		}

		errMandatory := parseAllMandatoryFields(entry, entryParts, definition)
		if errMandatory != nil {
			glog.Warning("Annotation format error : One of the mandatory fields not valid/missing for annotation: ", label)
			return parsedAnnotation, fmt.Errorf("annotation format error : One of the mandatory fields not valid/missing for annotation %s", label)
		}

		errAtleastOne := parseAtleastOneFields(entry, entryParts, definition)

		if errAtleastOne != nil {
			glog.Warning("annotation format error : One of the fields required is not valid/missing for annotation: ", label)
			return parsedAnnotation, fmt.Errorf("annotation format error : One of the fields required is not valid/missing for annotation %s", label)
		}

		errOptional := parseOptionalFields(entry, entryParts, definition)

		if errOptional != nil {
			glog.Warning("Annotation format error : One of the optional fields not valid for annotation: ", label)
			return parsedAnnotation, fmt.Errorf("annotation format error : One of the optional fields not valid for annotation %s", label)
		}

		Entries = append(Entries, entry)

	}

	parsedAnnotation.Entries = Entries
	glog.V(3).Infof("Successfully parsed annotation %s with entries %s and converted to model", label, input)
	return parsedAnnotation, nil
}
