/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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

package controller

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/IBM-Cloud/iks-ingress-controller/nginx-controller/nginx"

	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1beta1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// taskQueue manages a work queue through an independent worker that
// invokes the given sync function for every work item inserted.
type taskQueue struct {
	// queue is the work queue the worker polls
	queue *workqueue.Type
	// sync is called for each item in the queue
	sync func(string)
	// workerDone is closed when the worker exits
	workerDone chan struct{}
}

func (t *taskQueue) run(period time.Duration, stopCh <-chan struct{}) {
	wait.Until(t.worker, period, stopCh)
}

// enqueue enqueues ns/name of the given api object in the task queue.
func (t *taskQueue) enqueue(obj interface{}) {
	key, err := keyFunc(obj)
	if err != nil {
		glog.V(3).Infof("Couldn't get key for object %+v: %v", obj, err)
		return
	}
	t.queue.Add(key)
}

func (t *taskQueue) requeue(key string, err error) {
	glog.Errorf("Requeuing %v, err %v", key, err)
	t.queue.Add(key)
}

func (t *taskQueue) requeueAfter(key string, err error, after time.Duration) {
	glog.Errorf("Requeuing %v after %s, err %v", key, after.String(), err)
	go func(key string, after time.Duration) {
		time.Sleep(after)
		t.queue.Add(key)
	}(key, after)
}

// worker processes work in the queue through sync.
func (t *taskQueue) worker() {
	for {
		key, quit := t.queue.Get()
		if quit {
			close(t.workerDone)
			return
		}
		glog.V(4).Infof("Syncing %v", key)
		t.sync(key.(string))
		t.queue.Done(key)
	}
}

// shutdown shuts down the work queue and waits for the worker to ACK
func (t *taskQueue) shutdown() {
	t.queue.ShutDown()
	<-t.workerDone
}

// newTaskQueue creates a new task queue with the given sync function.
// The sync function is called for every element inserted into the queue.
func newTaskQueue(syncFn func(string)) *taskQueue {
	return &taskQueue{
		queue:      workqueue.New(),
		sync:       syncFn,
		workerDone: make(chan struct{}),
	}
}

// List lists all Ingress' in the store.
func (s *StoreToIngressLister) List() (ing networking.IngressList, err error) {
	for _, m := range s.Store.List() {
		ingNetworking, _ := toIngress(m)
		ing.Items = append(ing.Items, *ingNetworking)
	}
	return ing, nil
}

// GetServiceIngress gets all the Ingress' that have rules pointing to a service.
// Note that this ignores services without the right nodePorts.
func (s *StoreToIngressLister) GetServiceIngress(svc *api.Service) (ings []networking.Ingress, err error) {
	syncFlag := false
	for _, m := range s.Store.List() {
		ing, _ := toIngress(m)

		if ing.Spec.Backend != nil {
			if ing.Spec.Backend.ServiceName == svc.Name {
				ings = append(ings, *ing)
			}
		}
		for _, rules := range ing.Spec.Rules {
			if rules.IngressRuleValue.HTTP == nil {
				continue
			}
			for _, p := range rules.IngressRuleValue.HTTP.Paths {
				parseService := strings.Split(p.Backend.ServiceName, namespaceDelimiter)
				if len(parseService) == 2 {
					p.Backend.ServiceName = parseService[0]
					if svc.Namespace == parseService[1] {
						syncFlag = true
					}
				} else {
					syncFlag = true
				}

				if p.Backend.ServiceName == svc.Name && syncFlag == true {
					ings = append(ings, *ing)
				}
			}
		}
		if streamAnnotation, exists := ing.Annotations["ingress.bluemix.net/tcp-ports"]; exists {
			streamConfigs, streamErr := nginx.ParseStreamConfigs(streamAnnotation)
			if streamErr == nil {
				for _, streamConfig := range streamConfigs {
					if svc.Name == streamConfig.ServiceName {
						ings = append(ings, *ing)
					}
				}
			}
		}
	}
	if len(ings) == 0 {
		err = fmt.Errorf("no ingress for service %v", svc.Name)
	}
	return
}

// List lists all ConfigMap' in the store.
func (s *StoreToConfigMapLister) List() (cfgm api.ConfigMapList, err error) {
	for _, m := range s.Store.List() {
		cfgm.Items = append(cfgm.Items, *(m.(*api.ConfigMap)))
	}

	return cfgm, nil
}

// remove Duplicates from string slice
func removeDuplicates(items []string) []string {

	exists := map[string]bool{}

	// If the item exists then we set its key to true
	for i := range items {
		exists[items[i]] = true
	}

	// Add all existing keys to a string[]
	result := []string{}
	for key := range exists {
		result = append(result, key)
	}

	return result
}

// check if ports match
func matchingPorts(svcPorts, newPorts []api.ServicePort) bool {
	a := []int{}
	b := []int{}

	for _, port := range svcPorts {
		a = append(a, int(port.Port))
	}
	for _, port := range newPorts {
		b = append(b, int(port.Port))
	}
	sort.Ints(a)
	sort.Ints(b)

	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FindPort locates the container port for the given pod and portName.  If the
// targetPort is a number, use that.  If the targetPort is a string, look that
// string up in all named ports in all containers in the target pod.  If no
// match is found, fail.
func FindPort(pod *api.Pod, svcPort *api.ServicePort) (int32, error) {
	portName := svcPort.TargetPort
	switch portName.Type {
	case intstr.String:
		name := portName.StrVal
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				if port.Name == name && port.Protocol == svcPort.Protocol {
					return port.ContainerPort, nil
				}
			}
		}
	case intstr.Int:
		return int32(portName.IntValue()), nil
	}

	return 0, fmt.Errorf("no suitable port for manifest: %s", pod.UID)
}

// GetServiceEndpoints returns the endpoints of a service, matched on service name.
func (s *StoreToEndpointLister) GetServiceEndpoints(svc *api.Service) (ep api.Endpoints, err error) {
	for _, m := range s.Store.List() {
		ep = *m.(*api.Endpoints)
		if svc.Name == ep.Name && svc.Namespace == ep.Namespace {
			return ep, nil
		}
	}
	err = fmt.Errorf("could not find endpoints for service: %v", svc.Name)
	return
}

// Gets all files from the given directory.
func getFiles(directory string) []os.FileInfo {
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		return []os.FileInfo{}
	}
	files, err := ioutil.ReadDir(directory)
	if err != nil {
		glog.Error(err)
	}
	return files
}

// Creates a file which contains the given content.
func createFile(content string, path string, filename string) {
	filePath := path + filename
	file, err := os.Create(filePath)
	if err != nil {
		glog.Error(err)
	}
	defer file.Close()
	file.WriteString(content)
}

// StoreToConfigMapLister makes a Store that lists ConfigMaps
type StoreToConfigMapLister struct {
	cache.Store
}

// StoreToIngressLister makes a Store that lists Ingress.
type StoreToIngressLister struct {
	cache.Store
}

// StoreToEndpointLister makes a Store that lists Endpoints
type StoreToEndpointLister struct {
	cache.Store
}

// StoreToServiceLister makes a Store that lists Services
type StoreToServiceLister struct {
	cache.Store
}

// StoreToSecretLister makes a Store that lists Secrets
type StoreToSecretLister struct {
	cache.Store
}

// StoreToPodLister makes a Store that lists Pods.
type StoreToPodLister struct {
	cache.Store
}
