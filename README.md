# TODO

### Building

To build on a Mac or Linux based machine, ensure Docker is running and run:
`make container`


### Pushing to IBM Cloud Registry
* Find IBM Cloud Registry documentation here: https://cloud.ibm.com/docs/Registry?topic=Registry-registry_overview

* Login to the IBM Container Registry
`ibmcloud login`
`ibmcloud cr login`

* Tag your local image
`docker tag ibm-cloud-kubernetes/ingress:test <region>.icr.io/<namespace>/ingress:latest`

* Push your image
`docker push <region>.icr.io/<namespace>/ingress:latest`


### Deploying
* Disable current ingress controller, if you are using one
`ibmcloud ks ingress alb disable -c <cluster> --alb <alb-id>`

* Wait and check for the ingress controller to be disabled
`ibmcloud ks ingress alb get -c <cluster> --alb <alb-id>`

* Make sure you have a local kubernetes config with a valid token.  If not, run the following:
`ibmcloud ks cluster config -c <cluster>`

* Modify the image reference in the deploy.yaml
 - In sample_deploy/deploy.yaml, change <image_reference> with the location of your image, i.e. <region>.icr.io/<namespace>/ingress:latest

* Copy image pull secret to the kube-system namespace
 - Since the service account for the ingress controller sample references the default pull secret in kube-system, it must be copied to the kube-system namespace
`kubectl get secret all-icr-io -o yaml | sed 's/namespace: .*/namespace: kube-system/' | kubectl apply -f -`
 - note: If the all-icr-io secret does not exist in the default namespace, follow the instructions in this document to apply it: https://cloud.ibm.com/docs/containers?topic=containers-registry#imagePullSecret_migrate_api_key

* Apply the deployment
`kubectl apply -f ./sample_deploy`

* Ensure the pods are Running
`kubectl get po -n kube-system | grep ibm-cloud-ingress`
 - If not, check the events for errors:
   `kubectl describe deploy -n kube-system ibm-cloud-ingress`

### Register DNS domain
* Get your service IP(Classic) or LB Domain(VPC)
`kubectl get svc -n kube-system | grep ibm-cloud-ingress`
  - note: The IP or domain is the 4th column

* Create a DNS domain for your ingress
  - for classic:
`ibmcloud ks nlb-dns create classic -c <cluster> --ip <service ip address>`
  - for VPC:
`ibmcloud ks nlb-dns create vpc-gen2 -c <cluster> --lb-host <lb hostname>`