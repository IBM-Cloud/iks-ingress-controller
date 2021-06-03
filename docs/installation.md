# Deploying the Ingress controller

Set up the configuration for and deploy the Ingress controller.

## Prerequisites and considerations
Before you get started with the IBM Cloud Kubernetes Service open source Ingress controller, review the following prerequisites and considerations.

- Setting up Ingress in an IBM Cloud Kubernetes Service cluster requires the following [IBM Cloud IAM roles](https://cloud.ibm.com/docs/containers?topic=containers-users#platform):
    - **Administrator** platform access role for the cluster
    - **Manager** service access role in all namespaces
- If you restrict network traffic to edge worker nodes, ensure that at least two [edge worker nodes](https://cloud.ibm.com/docs/containers?topic=containers-edge) are enabled in each zone so that Ingress controllers deploy uniformly.
- To be included in Ingress load balancing, the names of the `ClusterIP` services that expose your apps must be unique across all namespaces in your cluster.
- VPC clusters: [Allow traffic requests that are routed by Ingress to node ports on your worker nodes](https://cloud.ibm.com/docs/containers?topic=containers-vpc-network-policy#security_groups).
- To build on a Mac or Linux based machine, ensure Docker is running, and run `make container`.
- This project is not officially supported by IBM for IBM Cloud Kubernetes Service clusters. You are responsible for deploying, managing, and maintaining the Ingress controllers in your cluster.

## Step 1: Pushing to IBM Cloud Registry
Push your local image to [IBM Cloud Container Registry](https://cloud.ibm.com/docs/Registry?topic=Registry-registry_overview).

1. Login to IBM Cloud Container Registry.
```
ibmcloud login
```
```
ibmcloud cr login
```

2. Tag your local image.
```
docker tag ibm-cloud-kubernetes/ingress:test <region>.icr.io/<namespace>/ingress:latest
```

3. Push your image.
```
docker push <region>.icr.io/<namespace>/ingress:latest
```

## Step 2: Deploying the Ingress controller
1. Disable any Ingress controllers that are currently running in the cluster, such as Ingress application load balancers (ALBs).
```
ibmcloud ks ingress alb disable -c <cluster> --alb <alb-id>
```

2. Check that the ALBs are disabled. This might take a few minutes.
```
ibmcloud ks ingress alb get -c <cluster> --alb <alb-id>
```

3. Get the local `kubeconfig` file with a valid token for your cluster.
```
ibmcloud ks cluster config -c <cluster>
```

4. Modify the image reference in the `deploy.yaml` file. For example, in `sample_deployment/deploy.yaml`, replace `<image_reference>` with the location of your image, such as `<region>.icr.io/<namespace>/ingress:latest`.

5. Copy the image pull secret to the `kube-system` namespace in your cluster. Because the service account for the Ingress controller sample references the default pull secret in `kube-system`, the secret must exist in the `kube-system` namespace.
```
kubectl get secret all-icr-io -o yaml | sed 's/namespace: .*/namespace: kube-system/' | kubectl apply -f -
```
> Note: If the `all-icr-io` secret does not exist in the `default` namespace, follow [these steps to apply it](https://cloud.ibm.com/docs/containers?topic=containers-registry#imagePullSecret_migrate_api_key).

6. Optional: By default, the sample deployment creates an Ingress controller that is exposed by a public service. To create a private Ingress controller instead, modify the `sample_deployment/service.yaml` file to add the following annotation:
  ```yaml
  apiVersion: v1
  kind: Service
  metadata:
    name: ibm-cloud-ingress
    namespace: kube-system
    annotations:
      service.kubernetes.io/ibm-load-balancer-cloud-provider-ip-type: <public_or_private>
  ...
  ```

7. Apply the deployment.
```
kubectl apply -f ./sample_deployment
```

8. Ensure the Ingress controller pods are in a `Running` state.
```
kubectl get po -n kube-system | grep ibm-cloud-ingress
```
 - If not, check the events for errors:
   ```
   kubectl describe deploy -n kube-system ibm-cloud-ingress
   ```

## Step 3: Registering a DNS subdomain
Register the service that exposes the Ingress controller with an IBM-provided DNS subdomain or a custom domain.

### IBM-provided domain
1. Get the ingress controller service's IP address (classic clusters) or VPC load balancer hostname (VPC clusters). The IP or hostname is the 4th column of the output.
```
kubectl get svc -n kube-system | grep ibm-cloud-ingress
```

2. Create a DNS subdomain for your Ingress controller. When you run the following command, an INM-provided subdomain is automatically generated and registered with the ingress controller. A TLS secret for the domain is automatically generated in the namespace that you can optionally specify; otherwise, the secret is created in the `default` namespace. The secret name follows a truncated format of the subdomain, such as `mycluster-a1b2cdef345678g9hi012j3kl4567890-0003`.
  - Classic:
    ```
    ibmcloud ks nlb-dns create classic -c <cluster> --ip <service ip address> [--namespace <namespace>]
    ```
    Note: Currently, you cannot generate an IBM-provided subdomain for an Ingress controller that is exposed by a private service in a classic cluster. Instead, you can register a custom domain.
  - VPC:
    ```
    ibmcloud ks nlb-dns create vpc-gen2 -c <cluster> --lb-host <lb hostname> [--namespace <namespace>] [--type (public|private)]
    ```

3. Optional: Register a custom domain by working with your DNS provider and define an alias by specifying the IBM-provided subdomain as a Canonical Name record (CNAME).

### Custom domain
Alternatively, you can work with your DNS provider to register a custom domain for your service's IP address (classic) or VPC LB hostname (VPC), and use your own TLS certificate to manage TLS termination.

1. Get the ingress controller service's IP address (classic clusters) or VPC load balancer hostname (VPC clusters). The IP or hostname is the 4th column of the output.
```
kubectl get svc -n kube-system | grep ibm-cloud-ingress
```

2. Register a custom domain for your service's IP address (classic) or VPC LB hostname (VPC) by working with your DNS provider.

3. To process HTTPS requests, choose from the following options for using a TLS certificate for your domain.

**Certificate stored in IBM Cloud Certificate Manager**: If you store a TLS certificate for your domain in IBM Cloud Certificate Manager, you can import its associated secret into your cluster by running the following command. If you do not specify a namespace, the certificate secret is created in a namespace called `ibm-cert-store`. A reference to this secret is then created in the `default` namespace, which any Ingress resource in any namespace can access. When the Ingress controller is processing requests, it follows this reference to pick up and use the certificate secret from the `ibm-cert-store` namespace. Note that TLS certificates that contain pre-shared keys (TLS-PSK) are not supported.
```
ibmcloud ks ingress secret create --name <secret_name> --cluster <cluster_name_or_ID> --cert-crn <certificate_crn> [--namespace <namespace>]
```

**Create a secret for a certificate**: If you do not have a TLS certificate ready, you can follow these steps:
1. Generate a certificate authority (CA) cert and key from your certificate provider. If you have your own domain, purchase an official TLS certificate for your domain. Make sure the [CN](https://support.dnsimple.com/articles/what-is-common-name/) is different for each certificate. **Note:** If you cannot get a certificate from a CA, you can create a self-signed certificate for testing purposes by using OpenSSL. For more information, see this [self-signed SSL certificate tutorial](https://www.akadia.com/services/ssh_test_certificate.html).
  1. Create a `tls.key`.
    ```
    openssl genrsa -out tls.key 2048
    ```
  2. Use the key to create a `tls.crt`.
    ```
    openssl req -new -x509 -key tls.key -out tls.crt
    ```
2. Convert the cert and key into base64.
   1. Encode the cert and key into base64 and save the base64 encoded value in a new file.
    ```
    openssl base64 -in tls.key -out tls.key.base64
    ```
   2. View the base64 encoded value for your cert and key.
    ```
    cat tls.key.base64
    ```
3. Create a secret YAML file using the cert and key.
 ```yaml
 apiVersion: v1
 kind: Secret
 metadata:
   name: ssl-my-test
 type: Opaque
 data:
   tls.crt: <client_certificate>
   tls.key: <client_key>
 ```

4. Create a Kubernetes secret for your certificate.
```
kubectl apply -f ssl-my-test
```

## Step 4: Creating the Ingress resource
Ingress resources define the routing rules that the Ingress controller uses to route traffic to your app service.

If your cluster has multiple namespaces where apps are exposed, one Ingress resource is required per namespace. However, each namespace must use a different host. You must register a wildcard domain and specify a different subdomain in each resource. For more information, see [Planning networking for single or multiple namespaces](#planning-networking-for-single-or-multiple-namespaces).

1. [Deploy your app to the cluster](https://cloud.ibm.com/docs/containers?topic=containers-deploy_app#app_cli). Ensure that you add a label to your deployment in the metadata section of your configuration file, such as `app: code`. This label is needed to identify all pods where your app runs so that the pods can be included in the Ingress load balancing.

2. For each app deployment that you want to expose, create a Kubernetes `ClusterIP` service. Your app must be exposed by a Kubernetes service to be included in the Ingress load balancing.
```
kubectl expose deploy <app_deployment_name> --name my-app-svc --port <app_port> -n <namespace>
```

3. Using the DNS subdomain and secret, create an Ingress resource file. Replace `<app_path>` with the path that your app listens on. If your app does not listen on a specific path, define the root path as a slash (`/`) only.
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingressresource
spec:
  tls:
  - hosts:
    - <dns_subdomain>
    secretName: <secret>
  rules:
  - host: <dns_subdomain>
    http:
      paths:
      - path: /<app_path>
        pathType: ImplementationSpecific
        backend:
          service:
            name: my-app-svc
            port:
              number: 80
```

|Parameter|Description|
|---|---|
|`tls.hosts` and `host`|To use TLS, replace `<domain>` with the IBM-provided DNS subdomain or your custom domain. Note: <ul><li>If your apps are exposed by services in different namespaces in one cluster, add a wildcard subdomain to the beginning of the domain, such as `subdomain1.custom_domain.net` or `subdomain1.mycluster-<hash>-0000.us-south.containers.appdomain.cloud`. Use a unique subdomain for each resource that you create in the cluster.</li><li>Do not use `*` for your host or leave the host property empty to avoid failures during Ingress creation.</li></ul>|
|`tls.secretName`|Replace `<tls_secret_name>` with the secret that you created earlier that holds your custom TLS certificate and key.|
|`path`|Replace `<app_path>` with a slash or the path that your app is listening on. The path is appended to the IBM-provided or your custom domain to create a unique route to your app. When you enter this route into a web browser, network traffic is routed to the Ingress controller. The Ingress controller looks up the associated service and sends network traffic to the service. The service then forwards the traffic to the pods where the app runs. Note: Many apps do not listen on a specific path, but use the root path and a specific port. In this case, define the root path as `/` and do not specify an individual path for your app. Examples: <ul><li>For `http://domain/`, enter `/` as the path.</li><li>For `http://domain/app1_path`, enter `/app1_path` as the path.</li></ul> Tip: To configure Ingress to listen on a path that is different than the path that your app listens on, you can use the [rewrite annotation](/docs/annotations.md#rewrite-paths-rewrite-path).|
|`service.name`|Replace `<app1_service>` and `<app2_service>`, and so on, with the name of the services you created to expose your apps. If your apps are exposed by services in different namespaces in the cluster, include only app services that are in the same namespace. You must create one Ingress resource for each namespace where you have apps that you want to expose.|
|`service.port.number`|The port that your service listens to. Use the same port that you defined when you created the Kubernetes service for your app.|

4. Create the Ingress resource.
```
kubectl apply -f myingressresource.yaml
```

5. In a web browser, enter the DNS subdomain and the path for your app.
```
https://<dns_subdomain>/<app_path>
```

## Exposing apps that are outside your cluster to the public
Expose apps that are outside your cluster to the public by including them in public Ingress controller load balancing. Incoming public requests on the IBM-provided or your custom domain are forwarded automatically to the external app.

You have two options for setting up routing to an external app:
* To forward requests directly to the IP address of your external service, see [Exposing external apps through a Kubernetes endpoint](#exposing-external-apps-through-a-kubernetes-endpoint) to set up a Kubernetes endpoint that defines the external IP address and port of the app.
* To route requests through the Ingress controller to your external service, see [Exposing external apps through the `proxy-external-service` Ingress annotation](#exposing-external-apps-through-the-proxy-external-service-ingress-annotation) to annotate your Ingress resource file.

**Before you begin:**
* Ensure that the external app that you want to include into the cluster load balancing can be accessed by using a public IP address.
* VPC clusters: In order to forward requests to the public external endpoint of your app, your VPC subnets must have a public gateway attached.

### Exposing external apps through a Kubernetes endpoint

Forward requests directly to the IP address of your external service by setting up a Kubernetes endpoint that defines the external IP address and port of the app.

1.  Define a Kubernetes service configuration file for the app that the Ingress controller will expose. This service forwards incoming requests to an external endpoint that you create in subsequent steps.
```yaml
apiVersion: v1
kind: Service
metadata:
  name: myexternalservice
spec:
  ports:
   - protocol: TCP
     port: <app_port>
```

2.  Create the service in your cluster.
```
kubectl apply -f myexternalservice.yaml
```

3.  Define an external endpoint configuration file. Include all public IP addresses and ports that you can use to access your external app. Note that the name of the endpoint must be the same as the name of the service that you defined in the previous step, `myexternalservice`. Replace `<external_IP>` with the public IP addresses to connect to your external app and `<external_port>` with the port that your external app listens to.
```yaml
kind: Endpoints
apiVersion: v1
metadata:
  name: myexternalservice
subsets:
  - addresses:
      - ip: <external_IP1>
      - ip: <external_IP2>
    ports:
      - port: <external_port>
```

4.  Create the endpoint in your cluster.
```
kubectl apply -f myexternalendpoint.yaml
```

5. Continue with the steps in "Step 4: Creating the Ingress resource".

### Exposing external apps through the `proxy-external-service` Ingress annotation

Route requests through the Ingress controller to your external service by using the `proxy-external-service` annotation in your Ingress resource file.

1. Create an Ingress resource file that is named, for example, `myingressresource.yaml`. Replace `<mypath>` with the path that the external service listens on, `<external_service>` with the external service to be called (e.g., `https://<myservice>.<region>.appdomain.com`), and `<dns_subdomain>` with the DNS subdomain for your cluster or the custom domain that you set up.
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/proxy-external-service: "path=<mypath> external-svc=https:<external_service> host=<dns_subdomain>"
spec:
  rules:
  - host: <dns_subdomain>
```

3.  Create the Ingress resource for your cluster.
```
kubectl apply -f myingressresource.yaml
```

4. In a web browser, enter the URL of the app service to access.
```
https://<domain>/<app_path>
```

## Planning networking for single or multiple namespaces

One Ingress resource is required per namespace where you have apps that you want to expose.

### All apps are in one namespace

If the apps in your cluster are all in the same namespace, one Ingress resource is required to define routing rules for the apps that are exposed there.

For example, if you have `app1` and `app2` exposed by services in a development namespace, you can create an Ingress resource in the namespace. The resource specifies `domain.net` as the host and registers the paths that each app listens on with `domain.net`.

### Apps are in multiple namespaces

If the apps in your cluster are in different namespaces, you must create one resource per namespace to define rules for the apps that are exposed there.

However, you can define a hostname in only one resource. You cannot define the same hostname in multiple resources. To register multiple Ingress resources with the same hostname, you must use a wildcard domain. When a wildcard domain such as `*.domain.net` is registered, multiple subdomains can all resolve to the same host. Then, you can create an Ingress resource in each namespace and specify a different subdomain in each Ingress resource.

For example, consider the following scenario:
* You have two versions of the same app, `app1` and `app3`, for testing purposes.
* You deploy the apps in two different namespaces within the same cluster: `app1` into the development namespace, and `app3` into the staging namespace.

To use the same cluster Ingress controller to manage traffic to these apps, you create the following services and resources:
* A Kubernetes service in the development namespace to expose `app1`.
* An Ingress resource in the development namespace that specifies the host as `dev.domain.net`.
* A Kubernetes service in the staging namespace to expose `app3`.
* An Ingress resource in the staging namespace that specifies the host as `stage.domain.net`.

Now, both URLs resolve to the same domain and are thus both serviced by the same Ingress controller. However, because the resource in the staging namespace is registered with the `stage` subdomain, the Ingress controller correctly routes requests from the `stage.domain.net/app3` URL to only `app3`.

If you want to use a wildcard custom domain, you must register the custom domain as a wildcard domain such as `*.custom_domain.net`, and to use TLS, you must get a wildcard certificate.

### Multiple domains within a namespace

Within an individual namespace, you can use one domain to access all the apps in the namespace. If you want to use different domains for the apps within an individual namespace, use a wildcard domain. When a wildcard domain such as `*.mycluster-<hash>-0000.us-south.containers.appdomain.cloud` is registered, multiple subdomains all resolve to the same host. Then, you can use one resource to specify multiple subdomain hosts within that resource. Alternatively, you can create multiple Ingress resources in the namespace and specify a different subdomain in each Ingress resource.

If you want to use a wildcard custom domain, you must register the custom domain as a wildcard domain such as `*.custom_domain.net`, and to use TLS, you must get a wildcard certificate.
