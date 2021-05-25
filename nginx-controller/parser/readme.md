

# Generic Parser for ALB Annotations

## Usage : Add support to a new annotation

### Example Annotation

``` 
ingress.bluemix.net/proxy-connect-timeout : "serviceName=tea-svc timeout=60s"

``` 
The above annotation will apply 60s proxy connect timeout to tea-svc location


``` 
 ingress.bluemix.net/proxy-connect-timeout : "timeout=60s"
 
``` 
 The above annotation will apply 60s to all locations
 
 
``` 
  ingress.bluemix.net/proxy-connect-timeout : "60s"
 
```  
  
  Just like last example annotation will apply 60s to all locations.  This is an example of keyless entry
  
  

### Configuring Annotation in annotations.json (/nginx-controller/parser/annotations.json)


Following are the characteristics of the example annotation

1. 2 fields in which timeout is a mandatory field

2. serviceName is an optional field - its a string

3. If no fields provided it would be taken as timeout

4. timeout(60s) has to have a valid unit ("s") as suffix and prefix should be an integer (60)  


In annotations.json the above can be configured trivially as

       {
         "label":"ingress.bluemix.net/proxy-connect-timeout",
         "mandatoryFields":[
            {
               "name":"timeout",
               "type":"timeout"
            }
        ],
         "atleastoneFields":[],
         "optionalFields":[
            {
               "name":"serviceName",
               "type":"string"
            }],
         "keyLessEntry" : "True"
    }
    
    
### Fields supported and Custom fields (refer /nginx-controller/parser/fieldtypes.go)


In the above example - timeout is a custom field which we need to be added to fieldtypes.go.  



step 1:  Add field to fieldTypeToParserMap  as shown below

``` 
var fieldTypeToParserMap = map[string]ParseMethodDef{
	"int":     parseInteger,
	"string":  parseString,
	"bool":    parseBoolean,
	"key":     parseKey,
	"rate":    parseRate,
	"timeout": parseTimeout,
}

``` 

step 2:  Add your field parser method 

The field parser method should be an extension of Field Parser Defintion

``` 
type ParseMethodDef func(valueInput string) (value interface{}, err error)

``` 
in our case timeout parser method signature should be as given below.

``` 
func parseTimeout(timeoutPart string) (value interface{}, err error)

``` 

Please note following

1. We should go for a new custom field only if  existing fields available in fieldstypes.go are not suiting to our purpose and field validation

2. All the field level validations can be added here

For eg:  if you want to add a new field called "port"   all the port related validations can be added in "parsePort" method

Parser will execute those validations in all annotations "port" field is used


### How to call parser and Use Model

``` 
annotationModel, err := parser.ParseInputForAnnotation("ingress.bluemix.net/proxy-connect-timeout", annotationStringFromIng)

``` 
If there is any error in the parsing  - an error object will be returned which should be checked before starting use the annotationModel object. In configurator getAnnotationModel  method can be used for the same purpose



1.  annotationModel is an object of struct ParsedValidatedAnnotation ( refer model.go)

the model has list of Entry objects in it

``` 
ingress.bluemix.net/proxy-connect-timeout : "serviceName=tea-svc timeout=60s;serviceName=coffee-svc timeout=60s"

``` 
In this case it will have 2 entries.Entry1 is serviceName=tea-svc timeout=60s Entry 2 is serviceName=coffee-svc timeout=60s


2.  Entries can be traversed as a normal list
```
 for _, entry := range annotationModel.Entries 
``` 
 Each entry has all the fields that represents a single sentence
 
 Following are the methods in Entry that can be used to fetch values
 
 -  entry.GetAsString("serviceName")  will return you the serviceName value for that entry.Please make sure that this is used against string type field. You can use entry.GetAsStrings("serviceName")   if you are expecting serviceName=tea-svc,coffee-svc  format
 
 -   entry.GetAsInt("conn")  will return you the conn value for that entry. Please make sure that this is used against int type fields
 
 - entry.Exists("serviceName") checks whether serviceName is provided in the entry
 
 - entry.GetAsValueUnitString("rate")  - this will return fields like  rate(5r/s), timeout(60s) etc  which have a value and unit in it .Please see the fieldtypes.go for defenition of parseRate and parseTimeout methods
 
 
We can add more methods to model (like GetAsFloats etc..) based on the future requirements for new types of fields if any.
