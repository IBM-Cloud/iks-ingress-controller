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

func TestParseBooleanValid(t *testing.T) {
	testValue := "true"
	b, err := parseBoolean(testValue)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if b != true {
		t.Errorf("parseBoolean is invalid. Expected %v, got %v", testValue, b)
	}
}

func TestParseBooleanInvalid(t *testing.T) {
	testValue := "yes"
	_, err := parseBoolean(testValue)
	if err == nil {
		t.Errorf("parseBoolean is invalid. An error was expected")
	}
}

func TestParseIntegerValid(t *testing.T) {
	testValue := "15"
	i, err := parseInteger(testValue)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if i != 15 {
		t.Errorf("parseInteger is invalid. Expected %v, got %v", testValue, i)
	}
}

func TestParseIntegerInvalid(t *testing.T) {
	testValue := "1.55"
	_, err := parseInteger(testValue)
	if err == nil {
		t.Errorf("parseInteger is invalid. An error was expected")
	}
}

func TestParseStringValid(t *testing.T) {
	testValue := "on"
	s, err := parseString(testValue)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if s != "on" {
		t.Errorf("parseString is invalid. Expected %v, got %v", testValue, s)
	}
}

func TestParseSizeValid(t *testing.T) {
	testValue := "5m"
	expectedValue := "5m"
	sizeI, err := parseSize(testValue)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if reflect.DeepEqual(expectedValue, sizeI) == false {
		t.Errorf("parseSize method should return expectecd %v got %v", expectedValue, sizeI)
	}
}

func TestParseSize0Valid(t *testing.T) {
	testValue := "0"
	expectedValue := "0"
	sizeI, err := parseSizeAndZero(testValue)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if reflect.DeepEqual(expectedValue, sizeI) == false {
		t.Errorf("parseSize method should return expectecd %v got %v", expectedValue, sizeI)
	}
}

func TestParseSizeInvalid(t *testing.T) {
	testValue := "15b"
	_, err := parseSize(testValue)
	if err == nil {
		t.Errorf("parseSize is invalid. An error was expected")
	}
}

func TestParseKeyLocation(t *testing.T) {
	testValue := "location"
	ratekey, err := parseKey(testValue)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if ratekey != "$uri" {
		t.Errorf("parseKey is invalid. Result for key=location should be $uri. Got %v", ratekey)
	}
}

func TestParseKeyHeader(t *testing.T) {
	testValue := "$http_x_user_id"
	ratekey, err := parseKey(testValue)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if ratekey != testValue {
		t.Errorf("parseKey is invalid. Result for key=$http_x_user_id should be $http_x_user_id. Got %v", ratekey)
	}
}

func TestParseKeyInvalid(t *testing.T) {
	testValue := "$https_x_user"
	_, err := parseKey(testValue)
	if err == nil {
		t.Errorf("parseKey is invalid. An error was expected")
	}
}

func TestParseRateValid(t *testing.T) {
	testValue := "15r/m"
	expectedValue := [2]string{"15", "r/m"}
	rateI, err := parseRate(testValue)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if reflect.DeepEqual(expectedValue, rateI) == false {
		t.Errorf("parseRate method should return expectecd %v got %v", expectedValue, rateI)
	}
}

func TestParseRateInvalid(t *testing.T) {
	testValue := "50r/h"
	_, err := parseRate(testValue)
	if err == nil {
		t.Errorf("parseRate is invalid. An error was expected")
	}
}

func TestParseTimeoutValid(t *testing.T) {
	testValue := "20s"
	expectedValue := [2]string{"20", "s"}
	timeI, err := ParseTimeout(testValue)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if reflect.DeepEqual(expectedValue, timeI) == false {
		t.Errorf("parseTimeout method should return expectecd %v got %v", expectedValue, timeI)
	}
}

func TestParseTimeoutValidO(t *testing.T) {
	testValue := "0"
	expectedValue := [2]string{"0", ""}
	timeI, err := parseTimeoutAndZero(testValue)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if reflect.DeepEqual(expectedValue, timeI) == false {
		t.Errorf("parseTimeout method should return expectecd %v got %v", expectedValue, timeI)
	}
}

func TestParseTimeoutInvalid(t *testing.T) {
	testValue := "10min"
	_, err := ParseTimeout(testValue)
	if err == nil {
		t.Errorf("parseTimeout is invalid. An error was expected")
	}
}

func TestParseTimeoutToSecondsValid(t *testing.T) {
	testValue := "20m"
	expectedValue := 1200
	timeOut, err := ParseTimeoutToSeconds(testValue)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if timeOut != expectedValue {
		t.Errorf("parseTimeout method should return expectecd %v got %v", expectedValue, timeOut)
	}
}

func TestParseTimeoutToSecondsValid2(t *testing.T) {
	testValue := "20s"
	expectedValue := 20
	timeOut, err := ParseTimeoutToSeconds(testValue)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if timeOut != expectedValue {
		t.Errorf("parseTimeout method should return expectecd %v got %v", expectedValue, timeOut)
	}
}

func TestParseTimeoutToSecondsInvalidUnit(t *testing.T) {
	testValue := "20w"
	_, err := ParseTimeoutToSeconds(testValue)
	if err == nil {
		t.Errorf("parseRate is invalid. An error was expected")
	}
}

func TestParseTimeoutToSecondsInvalidInput(t *testing.T) {
	testValue := ""
	_, err := ParseTimeoutToSeconds(testValue)
	if err == nil {
		t.Errorf("parseRate is invalid. An error was expected")
	}
}

func TestParseTimeoutToSecondsInvalidInput2(t *testing.T) {
	var testValue string
	_, err := ParseTimeoutToSeconds(testValue)
	if err == nil {
		t.Errorf("parseRate is invalid. An error was expected")
	}
}

func TestParseTimeoutToSecondsInvalidInput3(t *testing.T) {
	testValue := "0"
	_, err := ParseTimeoutToSeconds(testValue)
	if err == nil {
		t.Errorf("parseRate is invalid. An error was expected")
	}
}
