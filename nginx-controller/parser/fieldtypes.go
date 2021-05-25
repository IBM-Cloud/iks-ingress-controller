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
	"strconv"
	"strings"
)

// Add new field to parser mapping here

var fieldTypeToParserMap = map[string]ParseMethodDef{
	"int":             parseInteger,
	"string":          parseString,
	"bool":            parseBoolean,
	"key":             parseKey,
	"rate":            parseRate,
	"timeout":         ParseTimeout,
	"timeout0":        parseTimeoutAndZero,
	"size":            parseSize,
	"size0":           parseSizeAndZero,
	"proxybuffersize": parseProxyBufferSize,
}

// ParseMethodDef - Field Parser Defintion
type ParseMethodDef func(valueInput string) (value interface{}, err error)

// Field Parsers
func parseBoolean(valueInput string) (value interface{}, err error) {
	return strconv.ParseBool(valueInput)
}

func parseInteger(valueInput string) (value interface{}, err error) {
	return strconv.Atoi(valueInput)
}

func parseString(valueInput string) (value interface{}, err error) {
	return valueInput, nil
}

// Parser for size
func sizeParser(input string, allowZero bool) (value interface{}, err error) {
	suffix := strings.ToLower(input[len(input)-1:])
	if suffix == "k" || suffix == "m" {
		prefix := strings.TrimSuffix(strings.ToLower(input), suffix)
		intPrefix, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("sizeParser: cannot convert %v to int. Error: %v", prefix, err)
		}
		if intPrefix < 0 {
			return nil, fmt.Errorf("sizeParser: negatives are not allowed as a size")
		}
	} else {
		intInput, err := strconv.Atoi(input)
		if err == nil {
			if !allowZero && intInput == 0 {
				return nil, fmt.Errorf("sizeParser: 0 is not allowed as a size")
			}
			if intInput < 0 {
				return nil, fmt.Errorf("sizeParser: negatives are not allowed as a size")
			}
		} else {
			return nil, fmt.Errorf("sizeParser: cannot convert %v to int. Error: %v", input, err)
		}
	}

	return input, nil
}

func parseProxyBufferSize(input string) (value interface{}, err error) {
	suffix := strings.ToLower(input[len(input)-1:])
	if suffix == "k" {
		prefix := strings.TrimSuffix(strings.ToLower(input), suffix)
		intPrefix, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("parseProxyBufferSize: cannot convert %v to int. Error: %v", prefix, err)
		}
		if intPrefix <= 0 {
			return nil, fmt.Errorf("parseProxyBufferSize: negatives and zero are not allowed %v", input)
		}
	} else {
		return nil, fmt.Errorf("parseProxyBufferSize: invalid format %v", input)
	}

	return input, nil
}

// Special Parser for size
func parseSize(valueInput string) (value interface{}, err error) {
	size, err := sizeParser(valueInput, false)
	return size, err
}

// Special Parser for size plus having value of 0
func parseSizeAndZero(valueInput string) (value interface{}, err error) {
	size, err := sizeParser(valueInput, true)
	return size, err
}

// Special Parser for key
func parseKey(valueInput string) (value interface{}, err error) {
	if valueInput == "location" {
		value = "$uri"
	} else {

		if !strings.HasPrefix(valueInput, "$http_") {
			return nil, fmt.Errorf("annotation format error: %s Invalid key provided ", valueInput)
		}
		value = valueInput
	}
	return value, nil
}

//Parser for rate
func parseRate(ratePart string) (value interface{}, err error) {
	allowedUnits := [2]string{"r/s", "r/m"}
	var ratesuffix string
	var ratevalue string
	var foundUnit = false
	for _, unittmp := range allowedUnits {
		//check suffix
		if strings.HasSuffix(ratePart, unittmp) {
			foundUnit = true
			ratesuffix = unittmp
			break
		}
	}
	if foundUnit {
		//got an allowed unit, check value now
		ratevalue = strings.TrimSuffix(ratePart, ratesuffix)

		if _, err := strconv.Atoi(ratevalue); err == nil {

		} else {
			return nil, fmt.Errorf("invalid rate-limit value format: %s", ratePart)
		}
	} else {
		return nil, fmt.Errorf("invalid rate unit format: %s", ratePart)
	}

	rateValueSuffixArray := [2]string{ratevalue, ratesuffix}
	return rateValueSuffixArray, nil
}

// TimeoutParser parses a timeout value (ie 10s) and returns an interface {10, s}
func TimeoutParser(timeoutPart string, allowZero bool, allowedUnits []string) (value interface{}, err error) {
	var timeoutsuffix string
	var timeoutvalue string
	var foundUnit = false
	for _, unittmp := range allowedUnits {
		//check suffix
		if strings.HasSuffix(timeoutPart, unittmp) {
			foundUnit = true
			timeoutsuffix = unittmp
			break
		}
	}
	if foundUnit {
		//got an allowed unit, check value now
		timeoutvalue = strings.TrimSuffix(timeoutPart, timeoutsuffix)

		if _, err := strconv.Atoi(timeoutvalue); err == nil {

		} else {
			return nil, fmt.Errorf("invalid timeout format: %s", timeoutPart)
		}
	} else {
		if allowZero {
			if strings.TrimSpace(timeoutPart) == "0" {
				//a value of zero is an exception
				timeoutvalue = "0"
				timeoutsuffix = ""
			} else {
				return nil, fmt.Errorf("invalid timeout format when 0 is allowed: %s", timeoutPart)
			}
		} else {
			return nil, fmt.Errorf("invalid timeout format when unit must be present: %s", timeoutPart)
		}
	}

	timeoutValueSuffixArray := [2]string{timeoutvalue, timeoutsuffix}
	return timeoutValueSuffixArray, nil
}

func parseTimeoutAndZero(timeoutPart string) (value interface{}, err error) {
	allowedUnits := []string{"ms", "s", "m", "h", "w"}
	timeoutValueSuffixArray, err := TimeoutParser(timeoutPart, true, allowedUnits)
	return timeoutValueSuffixArray, err
}

// ParseTimeout converts any timeout input with "s" or "m " into seconds
func ParseTimeout(timeoutPart string) (value interface{}, err error) {
	allowedUnits := []string{"ms", "s", "m", "h", "w"}
	timeoutValueSuffixArray, err := TimeoutParser(timeoutPart, false, allowedUnits)
	return timeoutValueSuffixArray, err
}

// ParseTimeoutToSeconds converts any timeout input with "s" or "m " into seconds
func ParseTimeoutToSeconds(timeoutPart string) (numSeconds int, err error) {
	// only allow seconds and minutes to be converted to seconds
	allowedUnits := []string{"s", "m"}
	timeoutValueSuffixArray, err := TimeoutParser(timeoutPart, false, allowedUnits)

	// if there's an error return it at the beginning
	if err != nil {
		return -1, err
	}

	// convert the interface to a string error
	timeoutArray := timeoutValueSuffixArray.([2]string)
	timeoutValue, err := strconv.Atoi(timeoutArray[0])
	if err != nil {
		return -1, fmt.Errorf("invalid timeout format: %s", timeoutPart)
	}

	// if no error, then convert to seconds
	if err == nil {
		switch unit := timeoutArray[1]; unit {
		case "s":
			// do nothing as it's already in seconds
		case "m":
			// convert minutes to seconds
			timeoutValue = timeoutValue * 60
		}
	}
	return timeoutValue, err
}
