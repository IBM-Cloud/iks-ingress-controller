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
	"strconv"
	"strings"
)

// Entry ... Output model
type Entry struct {
	isKeyless bool
	fields    map[string][]interface{}
}

// ParsedValidatedAnnotation ...
type ParsedValidatedAnnotation struct {
	Entries []Entry
	label   string
}

// NewEntry ... Constructor Entry
func NewEntry() Entry {
	var entry Entry
	entry.fields = make(map[string][]interface{})
	return entry
}

// NewKeylessEntry ... Constructor For KeylessEntry
func NewKeylessEntry(keylessValue string) Entry {
	var entry Entry
	entry.fields = make(map[string][]interface{})
	entry.isKeyless = true
	entry.Put("KEYLESS", keylessValue)
	return entry
}

// GetAsBool support for boolean values for example : proxy-buffering : True or false
func (entry Entry) GetAsBool(key string) (boolvalue bool, exists bool) {
	values, keyExists := entry.GetAsBools(key)
	return values[0], keyExists
}

// GetAsBools support for multiple boolean values
func (entry Entry) GetAsBools(key string) (boolvalues []bool, exists bool) {
	values, keyExists := entry.fields[key]
	boolValues := []bool{}

	for _, interfaceValue := range values {
		boolValues = append(boolValues, interfaceValue.(bool))
	}
	return boolValues, keyExists
}

// GetEntriesWithFieldValueInt gets the entries which containing integer values
func (parsedValidatedAnnotation ParsedValidatedAnnotation) GetEntriesWithFieldValueInt(fieldName string, fieldValue int) (selectedEntries []Entry, exists bool) {
	var entriesSelected []Entry
	var fieldFound bool
	for _, entry := range parsedValidatedAnnotation.Entries {
		values, keyExists := entry.fields[fieldName]
		if keyExists {
			for _, interfaceValue := range values {
				var intFieldValue = interfaceValue.(int)
				if fieldValue == intFieldValue {
					entriesSelected = append(entriesSelected, entry)
					fieldFound = true
					break
				}
			}
		}
	}
	return entriesSelected, fieldFound
}

//GetEntriesWithFieldValueUnitString support only string values having units for example : timeout , rate
func (parsedValidatedAnnotation ParsedValidatedAnnotation) GetEntriesWithFieldValueUnitString(fieldName string, fieldValue string) (selectedEntries []Entry, exists bool) {
	var entriesSelected []Entry
	var fieldFound bool
	for _, entry := range parsedValidatedAnnotation.Entries {
		values, keyExists := entry.GetAsValueUnitString(fieldName)
		if keyExists {
			if strings.TrimSpace(fieldValue) == values {
				entriesSelected = append(entriesSelected, entry)
				fieldFound = true
			}
		}
	}
	return entriesSelected, fieldFound
}

// GetEntriesWithFieldValueString support only string values for example : serviceName
func (parsedValidatedAnnotation ParsedValidatedAnnotation) GetEntriesWithFieldValueString(fieldName string, fieldValue string) (selectedEntries []Entry, exists bool) {
	var entriesSelected []Entry
	var fieldFound bool
	for _, entry := range parsedValidatedAnnotation.Entries {
		values, keyExists := entry.fields[fieldName]
		if keyExists {
			for _, interfaceValue := range values {
				var strFieldValue = (interfaceValue.(string))
				if strings.TrimSpace(fieldValue) == strFieldValue {
					entriesSelected = append(entriesSelected, entry)
					fieldFound = true
					break
				}
			}
		}
	}
	return entriesSelected, fieldFound
}

// GetEntriesWithSingleField gets entries with single string field  for example : serviceName
func (parsedValidatedAnnotation ParsedValidatedAnnotation) GetEntriesWithSingleField(fieldName string) (selectedEntries []Entry, exists bool) {
	var entriesSelected []Entry
	var entryFound bool
	for _, entry := range parsedValidatedAnnotation.Entries {
		_, keyExists := entry.fields[fieldName]
		if keyExists && len(entry.fields) == 1 {
			entriesSelected = append(entriesSelected, entry)
			entryFound = true
			break
		}
	}
	return entriesSelected, entryFound
}

// Keyless checks if the entry is keyless
func (entry Entry) Keyless() (isKeyless bool) {
	return entry.isKeyless
}

// GetKeylessValue gets the keyless value of a given entry
func (entry Entry) GetKeylessValue() (values []interface{}, exists bool) {
	value, keyExists := entry.fields["KEYLESS"]
	return value, keyExists
}

// GetKeylessValueAsString Support for getting string values for a given fieldType for example : "cafe.example.com"
func (entry Entry) GetKeylessValueAsString(fieldType string) (strvalue string, exists bool) {
	parseMethodDef := fieldTypeToParserMap[fieldType]
	if parseMethodDef == nil {
		return "", false
	}
	values, valueExists := entry.GetKeylessValue()
	if valueExists {
		var valueStr string
		for _, interfaceValue := range values {
			valueStr = interfaceValue.(string)
			break
		}

		value, err := parseMethodDef(valueStr)

		if err == nil {
			return value.(string), true
		}
	}
	return "", false
}

// GetKeylessValueAsValueUnitString Support for getting string unit values for a given fieldType for example : 10ms , 10r/s
func (entry Entry) GetKeylessValueAsValueUnitString(fieldType string) (strvalue string, exists bool) {
	parseMethodDef := fieldTypeToParserMap[fieldType]
	if parseMethodDef == nil {
		return "", false
	}
	values, valueExists := entry.GetKeylessValue()
	if valueExists {
		var valueStr string
		for _, interfaceValue := range values {
			valueStr = interfaceValue.(string)
			break
		}

		value, err := parseMethodDef(valueStr)

		if err == nil {
			strArray := value.([2]string)
			return strArray[0] + strArray[1], true
		}
	}
	return "", false
}

// GetKeylessValueAsBool Support for getting boolean value for keyless value
func (entry Entry) GetKeylessValueAsBool(fieldType string) (strvalue bool, exists bool) {

	values, valueExists := entry.GetKeylessValue()
	if valueExists {
		var valueStr string
		for _, interfaceValue := range values {
			valueStr = interfaceValue.(string)
			break
		}

		boolValue, err := strconv.ParseBool(valueStr)

		if err == nil {
			return boolValue, true
		}

	}
	return false, false
}

// Exists check if the key exists for a given entry
func (entry Entry) Exists(key string) (isPresent bool) {
	_, keyExists := entry.fields[key]
	return keyExists
}

// Put ...
func (entry Entry) Put(key string, value interface{}) {
	entry.fields[key] = append(entry.fields[key], value)
}

// Get ...
func (entry Entry) Get(key string) (values []interface{}, exists bool) {
	values, keyExists := entry.fields[key]
	return values, keyExists
}

// GetAsString Get the values of single string value for given fieldName for a given entry
func (entry Entry) GetAsString(key string) (strvalue string, exists bool) {
	values, keyExists := entry.GetAsStrings(key)
	return values[0], keyExists
}

// GetAsStrings Get the values of mutiple string vlaues for a given filedname for a given entry
func (entry Entry) GetAsStrings(key string) (strvalues []string, exists bool) {
	values, keyExists := entry.fields[key]
	var stringValues []string

	for _, interfaceValue := range values {
		stringValues = append(stringValues, interfaceValue.(string))
	}
	return stringValues, keyExists
}

// GetAsInt Get the values of single Integer value for given fieldName for a given entry
func (entry Entry) GetAsInt(key string) (intvalue int, exists bool) {
	values, keyExists := entry.GetAsInts(key)
	return values[0], keyExists
}

// GetAsInts Get the values of multiple  Integer value for given fieldName for a given entry
func (entry Entry) GetAsInts(key string) (intvalues []int, exists bool) {
	values, keyExists := entry.fields[key]
	var intValues []int

	for _, interfaceValue := range values {
		intValues = append(intValues, interfaceValue.(int))
	}
	return intValues, keyExists
}

// GetAsValueUnitString Get the values of single string value having unit for given fieldName for a given entry ex : timeout,rate
func (entry Entry) GetAsValueUnitString(key string) (valueUnit string, exists bool) {
	values, exists := entry.GetAsValueUnitStringArray(key)

	if exists {
		return values[0] + values[1], exists
	}
	return "", false
}

// GetAsValueUnitStringArray Get the first array values of the multiple string having units of key
func (entry Entry) GetAsValueUnitStringArray(key string) (strvalues [2]string, exists bool) {
	values, keyExists := entry.GetAsValueUnitStringArrays(key)
	return values[0], keyExists
}

// GetAsValueUnitStringArrays Get all the values of the strings values for the given field name
func (entry Entry) GetAsValueUnitStringArrays(key string) (strvalues [][2]string, exists bool) {
	values, keyExists := entry.fields[key]
	var strArrvalues [][2]string

	for _, interfaceValue := range values {
		strArrvalues = append(strArrvalues, interfaceValue.([2]string))
	}
	return strArrvalues, keyExists
}
