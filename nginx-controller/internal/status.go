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

package internal

import (
	"context"
	"os"
	"strings"

	"github.com/golang/glog"
	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1beta1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"errors"

	"time"

	"math"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

const (
	ingressTypeKey      = "ingress.bluemix.net/ALB-ID"
	ingressSvcNameSpace = "kube-system"
)

// EventError ...
type EventError struct {
	Ing          *networking.Ingress
	MsgCode      string
	OverwriteMsg string
}

// ResourceManager ...
type ResourceManager struct {
	Client          kubernetes.Interface
	ListOfResources []IngressResource
}

// IngressResource ...
type IngressResource struct {
	Name                   string
	Namespace              string
	NotFirstSecretError    bool
	NotFirstSSLSecretError bool
	NotFirstMASecretError  bool
}

// CloudEventRecorder is the cloud event recorder data
type CloudEventRecorder struct {
	Name     string
	Recorder record.EventRecorder
}

// EventMsg ...
type EventMsg struct {
	Code   string `json:"code" binding:"required"`
	Msg    string `json:"message" binding:"required"`
	Reason string `json:"reason"`
	Type   string `json:"type"`
}

type ErrMsg map[string]EventMsg

// UpdateIngressStatus updates the ingress address section
func (rm *ResourceManager) UpdateIngressStatus(ing *networking.Ingress) {
	if IsNetworkingIngressAvailable {
		glog.V(4).Infof("UpdateIngressStatus networking is available")
		currIng, err := rm.Client.NetworkingV1beta1().Ingresses(ing.Namespace).Get(context.Background(), ing.Name, meta_v1.GetOptions{})
		if err != nil {
			glog.Warningf("error getting ingress %v err: %v", ing.Name, err)
		}

		// need to get the ip for the alb that is being used
		status := rm.getIPStatus(currIng.Name, currIng.ObjectMeta.Annotations)
		glog.V(4).Infof("updating Ingress %v/%v status to %v", currIng.Namespace, currIng.Name, status)

		if len(status) > 0 {
			for _, statuses := range status {
				if !statusInSlice(statuses, currIng.Status.LoadBalancer.Ingress) {
					// append to ip list only if not already present in status
					currIng.Status.LoadBalancer.Ingress = append(currIng.Status.LoadBalancer.Ingress, statuses)
				}
			}
		}

		glog.V(4).Infof("updating Ingress %v/%v status to %v (after updating status list)", currIng.Namespace, currIng.Name, currIng.Status.LoadBalancer.Ingress)

		_, err = rm.Client.NetworkingV1beta1().Ingresses(ing.Namespace).UpdateStatus(context.Background(), currIng, meta_v1.UpdateOptions{})
		if err != nil {
			glog.Warningf("error updating ingress rule: %v", err)
		}
	} else {
		glog.V(4).Infof("UpdateIngressStatus networking is unavailable so using extensions")

		currIng, err := rm.Client.ExtensionsV1beta1().Ingresses(ing.Namespace).Get(context.Background(), ing.Name, meta_v1.GetOptions{})
		if err != nil {
			glog.Warningf("error getting ingress %v err: %v", ing.Name, err)
		}

		// need to get the ip for the alb that is being used
		status := rm.getIPStatus(currIng.Name, currIng.ObjectMeta.Annotations)
		glog.V(4).Infof("updating Ingress %v/%v status to %v", currIng.Namespace, currIng.Name, status)

		if len(status) > 0 {
			for _, statuses := range status {
				if !statusInSlice(statuses, currIng.Status.LoadBalancer.Ingress) {
					// append to ip list only if not already present in status
					currIng.Status.LoadBalancer.Ingress = append(currIng.Status.LoadBalancer.Ingress, statuses)
				}
			}
		}

		glog.V(4).Infof("updating Ingress %v/%v status to %v (after updating status list)", currIng.Namespace, currIng.Name, currIng.Status.LoadBalancer.Ingress)

		_, err = rm.Client.ExtensionsV1beta1().Ingresses(ing.Namespace).UpdateStatus(context.Background(), currIng, meta_v1.UpdateOptions{})
		if err != nil {
			glog.Warningf("error updating ingress rule: %v", err)
		}
	}
}

// getIPStatus determines the IP address that needs to be reflected in the ingress address section
// If ALB-ID annotation provided, it gets the IP from the service exposing the desired alb
// If no annotation provided, it gets the IP from the service using the env var ALB_ID_LB (local)
func (rm *ResourceManager) getIPStatus(ingName string, annotations map[string]string) []api.LoadBalancerIngress {
	var lbi []api.LoadBalancerIngress
	var svcName string

	if annotations[ingressTypeKey] != "" {
		// get the service with the albID provided in annotation
		svcs := strings.Split(annotations[ingressTypeKey], ";")
		for _, elem := range svcs {
			svc := strings.TrimSpace(elem)
			if svc == os.Getenv("ALB_ID") {
				svcName = os.Getenv("ALB_ID_LB")
				break
			}
		}
		glog.Infof("using the alb-id annotation: %v to retrieve ip for ingress %v status", svcName, ingName)

	} else {
		// if no annotation provided, it is picked up by all public albs by default
		svcName = os.Getenv("ALB_ID_LB")
		glog.Infof("using the alb-id env var: %v to retrieve ip for ingress %v status", svcName, ingName)
	}

	if svcName != "" {
		svcObj, err := rm.Client.CoreV1().Services(ingressSvcNameSpace).Get(context.Background(), svcName, meta_v1.GetOptions{})
		if err != nil {
			glog.Errorf("error getting ip status from service %v for ingress %v %v", svcName, ingName, err)
			return lbi
		}

		// ensure length of object is not 0
		if len(svcObj.Status.LoadBalancer.Ingress) > 0 {
			lbi = append(lbi, svcObj.Status.LoadBalancer.Ingress[0])
		}
	}

	return lbi
}

// ResetIngressStatus resets the ingress status in resource to an empty list
// This will trigger the other albs to resync the ingress resource thereby reflecting the correct IP constantly.
func (rm *ResourceManager) ResetIngressStatus() {
	glog.Infof("resetting ingress resources status before shutdown %+v", rm.ListOfResources)
	if len(rm.ListOfResources) > 0 {
		for _, ingResource := range rm.ListOfResources {
			glog.Infof("resetting ingress resource %+v", ingResource)

			if IsNetworkingIngressAvailable {
				glog.V(4).Infof("ResetIngressStatus using networking")
				currIng, err := rm.Client.NetworkingV1beta1().Ingresses(ingResource.Namespace).Get(context.Background(), ingResource.Name, meta_v1.GetOptions{})
				if err != nil {
					glog.Warningf("error getting ingress %v err: %v", ingResource.Name, err)
					continue
				}

				currIng.Status.LoadBalancer.Ingress = nil
				_, err = rm.Client.NetworkingV1beta1().Ingresses(ingResource.Namespace).UpdateStatus(context.Background(), currIng, meta_v1.UpdateOptions{})

				if err != nil {
					glog.Warningf("error resetting ingress status: %v", err)
				}
			} else {
				glog.V(4).Infof("ResetIngressStatus using extensions")
				currIng, err := rm.Client.ExtensionsV1beta1().Ingresses(ingResource.Namespace).Get(context.Background(), ingResource.Name, meta_v1.GetOptions{})
				if err != nil {
					glog.Warningf("error getting ingress %v err: %v", ingResource.Name, err)
					continue
				}

				currIng.Status.LoadBalancer.Ingress = nil
				_, err = rm.Client.ExtensionsV1beta1().Ingresses(ingResource.Namespace).UpdateStatus(context.Background(), currIng, meta_v1.UpdateOptions{})

				if err != nil {
					glog.Warningf("error resetting ingress status: %v", err)
				}
			}

		}
	}
}

func (rm *ResourceManager) RemoveStatusAddress(ing *networking.Ingress) {
	glog.Infof("removing alb ip from ingress address %s", ing.ObjectMeta.Name)

	currIng, err := rm.Client.NetworkingV1beta1().Ingresses(ing.Namespace).Get(context.Background(), ing.Name, meta_v1.GetOptions{})
	if err != nil {
		glog.Warningf("error getting ingress %v err: %v", ing.Name, err)
	}

	// need to get the ip for the alb that is being used
	status := rm.getIPStatus(currIng.Name, currIng.ObjectMeta.Annotations)
	if len(status) > 0 {
		for _, statuses := range status {
			if len(currIng.Status.LoadBalancer.Ingress) > 0 {
				for idx, lbIP := range currIng.Status.LoadBalancer.Ingress {
					if lbIP.IP == statuses.IP {
						currIng.Status.LoadBalancer.Ingress = append(currIng.Status.LoadBalancer.Ingress[:idx], currIng.Status.LoadBalancer.Ingress[idx+1:]...)
					}
				}
			}
		}
	}

	glog.Infof("updating Ingress %v/%v status to %v (after removing status list)", currIng.Namespace, currIng.Name, currIng.Status.LoadBalancer.Ingress)
	_, err = rm.Client.NetworkingV1beta1().Ingresses(ing.Namespace).UpdateStatus(context.Background(), currIng, meta_v1.UpdateOptions{})
	if err != nil {
		glog.Warningf("error updating ingress rule: %v", err)
	}
}

// GenerateKubeEvent generates a normal or warning kubernetes event specific to an ingress
func (rm *ResourceManager) GenerateKubeEvent(errs EventError) error {
	generateEvent := true
	glog.Infof("Generating a kube event for ingress %s", errs.Ing.ObjectMeta.Name)

	errMsg := make(ErrMsg)
	if err := parseErrors(errMsg, "errors.json"); err != nil {
		glog.Errorf("unable to read errors file %v", err)
		return err
	}

	eventsGenerated, err := rm.Client.CoreV1().Events(errs.Ing.ObjectMeta.Namespace).List(context.Background(), meta_v1.ListOptions{})
	if err != nil {
		return err
	}

	var finalMsg string
	// if we want to show a custom event message
	if errs.OverwriteMsg != "" {
		finalMsg = errs.OverwriteMsg
	} else {
		finalMsg = errMsg[errs.MsgCode].Msg
	}

	if len(eventsGenerated.Items) > 0 {
		for i := len(eventsGenerated.Items) - 1; i >= 0; i-- {
			if eventsGenerated.Items[i].Namespace == errs.Ing.Namespace && eventsGenerated.Items[i].Type == errMsg[errs.MsgCode].Type &&
				eventsGenerated.Items[i].Reason == errMsg[errs.MsgCode].Reason && eventsGenerated.Items[i].Message == finalMsg &&
				strings.Contains(eventsGenerated.Items[i].ObjectMeta.Name, errs.Ing.ObjectMeta.Name) &&
				math.Abs(eventsGenerated.Items[i].FirstTimestamp.Sub(time.Now()).Seconds()) < 10 &&
				eventsGenerated.Items[i].Source.Component == os.Getenv("ARMADA_POD_NAME") {
				generateEvent = false
				break
			}
		}
	}

	if generateEvent {
		eventRecorder := rm.NewCloudEventRecorder(errs.Ing.ObjectMeta.Namespace)
		eventRecorder.Recorder.Event(errs.Ing, errMsg[errs.MsgCode].Type, errMsg[errs.MsgCode].Reason, finalMsg)
	}
	return errors.New(finalMsg)
}

// NewCloudEventRecorder returns a cloud event recorder.
func (rm *ResourceManager) NewCloudEventRecorder(namespace string) *CloudEventRecorder {
	return NewCloudEventRecorderV1(rm.Client.CoreV1().Events(namespace))
}

// NewCloudEventRecorderV1 returns a cloud event recorder for v1 client
func NewCloudEventRecorderV1(eventInterface v1core.EventInterface) *CloudEventRecorder {
	name := os.Getenv("ARMADA_POD_NAME")
	broadcaster := record.NewBroadcaster()
	broadcaster.StartLogging(glog.Infof)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: eventInterface})
	eventRecorder := CloudEventRecorder{
		Name:     name,
		Recorder: broadcaster.NewRecorder(scheme.Scheme, api.EventSource{Component: name}),
	}
	return &eventRecorder
}

func statusInSlice(status api.LoadBalancerIngress, statusList []api.LoadBalancerIngress) bool {
	for _, statuses := range statusList {
		if statuses.IP == status.IP {
			return true
		}
	}
	return false
}
