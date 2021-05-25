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
	"reflect"
	"testing"
)

func TestGetAsInt(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/global-rate-limit"
	annotationStr := "key=location conn=20"
	Prepare("annotations.json")
	expectedConnValue := 20
	if annotationEntryModel, err := ParseInputForAnnotation(annotationLabel, annotationStr); err != nil {
		t.Errorf("invalid entry %v annotationEntryModel %v ", err, annotationEntryModel)
	} else {
		for _, selectEntry := range annotationEntryModel.Entries {
			connValue, _ := selectEntry.GetAsInt("conn")
			if connValue != expectedConnValue {
				t.Errorf(" GetAsInt should return %v but  %v ", expectedConnValue, connValue)
			}
		}
	}
}

func TestGetEntriesWithFieldValueInt(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/global-rate-limit"
	annotationStr := "key=location conn=25;key=location conn=20"
	Prepare("annotations.json")
	expectedConnValue := 25
	if annotationEntryModel, err := ParseInputForAnnotation(annotationLabel, annotationStr); err != nil {
		t.Errorf("invalid entry %v annotationEntryModel %v ", err, annotationEntryModel)
	} else {
		selectedEntries, _ := annotationEntryModel.GetEntriesWithFieldValueInt("conn", 25)
		for _, selectEntry := range selectedEntries {
			connValue, _ := selectEntry.GetAsInt("conn")
			if connValue != expectedConnValue {
				t.Errorf(" GetEntriesWithFieldValueInt should return %v but  %v ", expectedConnValue, connValue)
			}
		}
	}
}

func TestGetEntriesWithFieldValueUnitString(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/proxy-read-timeout"
	annotationStr := "serviceName=bean-svc timeout=10s;serviceName=tea-svc,coffee-svc timeout=20s"
	Prepare("annotations.json")
	expectedTimeout := "10s"
	if annotationEntryModel, err := ParseInputForAnnotation(annotationLabel, annotationStr); err != nil {
	} else {
		selectedEntries, _ := annotationEntryModel.GetEntriesWithFieldValueUnitString("timeout", "10s")
		for _, selectEntry := range selectedEntries {
			timeoutValue, _ := selectEntry.GetAsValueUnitString("timeout")
			if timeoutValue != expectedTimeout {
				t.Errorf(" GetEntriesWithFieldValueUnitString should return {false map[timeout:[[10 s]] serviceName:[tea-svc coffee-svc]]} but returned %v", selectedEntries)
			}
		}
	}
}

func TestGetEntriesWithFieldValueString(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/proxy-read-timeout"
	annotationStr := "serviceName=tea-svc,coffee-svc timeout=10s;serviceName=bean-svc timeout=10s;"
	Prepare("annotations.json")
	expectedServiceName := "bean-svc"
	if annotationEntryModel, err := ParseInputForAnnotation(annotationLabel, annotationStr); err != nil {
		t.Errorf("invalid entry %s annotationEntryModel %v ", err, annotationEntryModel)
	} else {
		selectedEntries, _ := annotationEntryModel.GetEntriesWithFieldValueString("serviceName", "bean-svc")
		for _, selectEntry := range selectedEntries {
			svcNames, _ := selectEntry.GetAsStrings("serviceName")
			for _, svcName := range svcNames {
				if svcName != expectedServiceName {
					t.Errorf(" GetEntriesWithFieldValueString should return %s but  %s ", expectedServiceName, svcName)
				}
			}
		}
	}
}

func TestGetAsStringsValid(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/proxy-read-timeout"
	Prepare("annotations.json")
	if annotationEntryModel, err := ParseInputForAnnotation(annotationLabel, "serviceName=tea-svc,coffee-svc timeout=10s"); err != nil {
		t.Errorf("invalid entry %s annotationEntryModel %v ", err, annotationEntryModel)
	} else {
		for _, entry := range annotationEntryModel.Entries {
			if entry.Exists("serviceName") {
				svcNames, _ := entry.GetAsStrings("serviceName")
				if svcNames[0] == "tea-svc" && svcNames[1] == "coffee-svc" {
				} else {
					t.Errorf("GetAsStringsValid is invalid %v ", annotationLabel)
				}
			} else {
				t.Errorf("Exists method is invalid %v", entry)
			}
		}
	}
}

func TestGetAsValueUnitString(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/proxy-read-timeout"
	annotationStr := "serviceName=tea-svc timeout=10s"
	Prepare("annotations.json")
	expectedValue := "10s"
	if annotationEntryModel, err := ParseInputForAnnotation(annotationLabel, annotationStr); err != nil {
		t.Errorf("invalid entry %s annotationEntryModel %v ", err, annotationEntryModel)
	} else {
		for _, entry := range annotationEntryModel.Entries {
			timeoutValue, _ := entry.GetAsValueUnitString("timeout")
			if timeoutValue != expectedValue {
				t.Errorf("GetAsValueUnitString method should return expectecd %s got %s", expectedValue, timeoutValue)
			}
		}
	}
}

func TestGetAsValueUnitStringArray(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/proxy-read-timeout"
	annotationStr := "serviceName=tea-svc timeout=10s"
	var timeoutValues [2]string
	Prepare("annotations.json")
	var expectedStrValues = [2]string{"10", "s"}
	if annotationEntryModel, err := ParseInputForAnnotation(annotationLabel, annotationStr); err != nil {
		t.Errorf("invalid entry %s annotationEntryModel %v ", err, annotationEntryModel)
	} else {
		for _, entry := range annotationEntryModel.Entries {
			timeoutValuesArray, _ := entry.GetAsValueUnitStringArray("timeout")
			timeoutValues = timeoutValuesArray
		}
		if reflect.DeepEqual(timeoutValues, expectedStrValues) == false {
			t.Errorf("GetAsValueUnitStringArray method should return expectecd %s got %s", expectedStrValues, timeoutValues)
		}
	}
}

func TestGetAsValueUnitStringArrays(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/proxy-read-timeout"
	annotationStr := "serviceName=tea-svc timeout=10s"
	Prepare("annotations.json")

	var expectedStrValues [][2]string
	row1 := [2]string{"10", "s"}
	expectedStrValues = append(expectedStrValues, row1)

	if annotationEntryModel, err := ParseInputForAnnotation(annotationLabel, annotationStr); err != nil {
		t.Errorf("invalid entry %s annotationEntryModel %v ", err, annotationEntryModel)
	} else {
		for _, entry := range annotationEntryModel.Entries {
			timeoutValuesArrayTest, _ := entry.GetAsValueUnitStringArrays("timeout")
			if reflect.DeepEqual(expectedStrValues, timeoutValuesArrayTest) == false {
				t.Errorf("GetAsValueUnitStringArrays method should return expectecd %s got %s", expectedStrValues, timeoutValuesArrayTest)
			}
		}
	}
}

func TestKeyless(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/proxy-read-timeout"
	annotationStr := "10s"
	expectedStrValues := true
	Prepare("annotations.json")

	if annotationEntryModel, err := ParseInputForAnnotation(annotationLabel, annotationStr); err != nil {
		t.Errorf("invalid entry %s annotationEntryModel %v ", err, annotationEntryModel)
	} else {
		for _, entry := range annotationEntryModel.Entries {
			if entry.Keyless() == false {
				t.Errorf("Keyless method should return expectecd %v got %v", expectedStrValues, entry.Keyless())
			}
		}
	}
}

func TestGetKeylessValueAsValueUnitString(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/proxy-read-timeout"
	annotationStr := "10s"
	expectedStrValues := "10s"
	Prepare("annotations.json")
	if annotationEntryModel, err := ParseInputForAnnotation(annotationLabel, annotationStr); err != nil {
		t.Errorf("invalid entry %s annotationEntryModel %v ", err, annotationEntryModel)
	} else {
		for _, entry := range annotationEntryModel.Entries {
			timeoutValue, _ := entry.GetKeylessValueAsValueUnitString("timeout")
			if timeoutValue != expectedStrValues {
				t.Errorf("GetKeylessValueAsValueUnitString should return expected values %s got %s", expectedStrValues, timeoutValue)
			}
		}
	}
}

func TestGetKeylessValue(t *testing.T) {
	annotationLabel := "ingress.bluemix.net/proxy-read-timeout"
	annotationStr := "10s"
	expectedStrValues := "10s"
	Prepare("annotations.json")
	if annotationEntryModel, err := ParseInputForAnnotation(annotationLabel, annotationStr); err != nil {
		t.Errorf("invalid entry %s annotationEntryModel %v ", err, annotationEntryModel)
	} else {
		for _, entry := range annotationEntryModel.Entries {
			timeoutValues, _ := entry.GetKeylessValue()
			for _, timeoutValue := range timeoutValues {
				if timeoutValue != expectedStrValues {
					t.Errorf("GetKeylessValue should return expected values %s got %s", expectedStrValues, timeoutValue)
				}
			}
		}
	}
}
