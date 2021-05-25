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
	"strings"
	"testing"

	"fmt"

	"os"

	"time"

	networking "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func createTestResources() *networking.Ingress {
	ing := &networking.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingressName",
			Namespace: "default",
			SelfLink:  "/apis/networking/v1beta1/namespaces/default/ingresses/ingressName",
		},
	}
	return ing
}

func TestNewCloudEventRecorder(t *testing.T) {
	os.Setenv("ARMADA_POD_NAME", "public-crcluster-alb1-xxxx")
	cer := NewCloudEventRecorderV1(fake.NewSimpleClientset().CoreV1().Events("default"))
	if nil == cer {
		t.Fatalf("Failed to create cloud event recorder")
	} else if 0 != strings.Compare(os.Getenv("ARMADA_POD_NAME"), cer.Name) {
		t.Fatalf("Invalid cloud event recorder name: %v", cer.Name)
	}
}

func TestErrorEvent(t *testing.T) {
	os.Setenv("ARMADA_POD_NAME", "public-crcluster-alb1-xxxx")
	ing := createTestResources()
	fakeClient := fake.NewSimpleClientset()
	testLbc := ResourceManager{
		Client: fakeClient,
	}

	err := testLbc.GenerateKubeEvent(EventError{
		MsgCode: "E0001",
		Ing:     ing,
	})
	if nil == err {
		t.Fatalf("Failed to create warning event")
	}

	time.Sleep(5 * time.Second)
	err = testLbc.GenerateKubeEvent(EventError{
		MsgCode: "E0001",
		Ing:     ing,
	})
	if nil == err {
		t.Fatalf("Failed to create warning event")
	}

	time.Sleep(10 * time.Second)
	eventsGenerated, err := fakeClient.CoreV1().Events(ing.ObjectMeta.Namespace).List(context.Background(), metav1.ListOptions{})
	fmt.Printf("events %+v", eventsGenerated.Items)
	if err != nil || len(eventsGenerated.Items) != 1 {
		t.Fatalf("Failed to generate events: error: %v, events: %v", err, eventsGenerated.Items)
	}
	os.Unsetenv("ARMADA_POD_NAME")
}
