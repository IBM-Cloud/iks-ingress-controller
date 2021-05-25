module github.com/IBM-Cloud/iks-ingress-controller

go 1.15

require (
	github.com/gogo/protobuf v1.3.2 // indirect; indirect due to vulnerability fix
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.4.1-0.20190904163530-85f2b59c4459
	golang.org/x/text v0.3.6 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v2 v2.3.0 // indirect
	k8s.io/api v0.18.17
	k8s.io/apimachinery v0.18.17
	k8s.io/client-go v0.18.17
	k8s.io/klog v1.0.0
)
