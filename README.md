# IBM Cloud Kubernetes Service open source Ingress controller

The Ingress controller provided by this project can be used as-is in IBM Cloud Kubernetes Service clusters without any support from IBM. The main purpose of providing this open source Ingress controller is to allow users to continue to use the custom IBM CLoud Kubernetes Service Ingress controller after official support is ended by IBM.

## Prerequisites and considerations
Before you get started with the IBM Cloud Kubernetes Service open source Ingress controller, review the following prerequisites and considerations.

- Setting up Ingress in an IBM Cloud Kubernetes Service cluster requires the following [IBM Cloud IAM roles](cloud.ibm.com/docs/containers?topic=containers-users#platform):
    - **Administrator** platform access role for the cluster
    - **Manager** service access role in all namespaces
- If you restrict network traffic to edge worker nodes, ensure that at least two [edge worker nodes](cloud.ibm.com/docs/containers?topic=containers-edge) are enabled in each zone so that Ingress controllers deploy uniformly.
- To be included in Ingress load balancing, the names of the `ClusterIP` services that expose your apps must be unique across all namespaces in your cluster.
- VPC clusters: [Allow traffic requests that are routed by Ingress to node ports on your worker nodes](cloud.ibm.com/docs/containers?topic=containers-vpc-network-policy#security_groups).
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
  ```
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

If your cluster has multiple namespaces where apps are exposed, one Ingress resource is required per namespace. However, each namespace must use a different host. You must register a wildcard domain and specify a different subdomain in each resource. For more information, see "Planning networking for single or multiple namespaces".

1. [Deploy your app to the cluster](cloud.ibm.com/docs/containers?topic=containers-deploy_app#app_cli). Ensure that you add a label to your deployment in the metadata section of your configuration file, such as `app: code`. This label is needed to identify all pods where your app runs so that the pods can be included in the Ingress load balancing.

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
|`path`|Replace `<app_path>` with a slash or the path that your app is listening on. The path is appended to the IBM-provided or your custom domain to create a unique route to your app. When you enter this route into a web browser, network traffic is routed to the Ingress controller. The Ingress controller looks up the associated service and sends network traffic to the service. The service then forwards the traffic to the pods where the app runs. Note: Many apps do not listen on a specific path, but use the root path and a specific port. In this case, define the root path as `/` and do not specify an individual path for your app. Examples: <ul><li>For `http://domain/`, enter `/` as the path.</li><li>For `http://domain/app1_path`, enter `/app1_path` as the path.</li></ul> Tip: To configure Ingress to listen on a path that is different than the path that your app listens on, you can use the rewrite annotation.|
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
* To forward requests directly to the IP address of your external service, see "Exposing external apps through a Kubernetes endpoint" to set up a Kubernetes endpoint that defines the external IP address and port of the app.
* To route requests through the Ingress controller to your external service, see "Exposing external apps through the `proxy-external-service` Ingress annotation" to use the `proxy-external-service` annotation in your Ingress resource file.

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

## Adding annotations

To add capabilities to your Ingress controller, you can specify annotations as metadata in an Ingress resource.

|General annotations|Name|Description|
|-------------------|----|-----------|
| Custom error actions | `custom-errors, custom-error-actions` | Indicate custom actions that the Ingress controller can take for specific HTTP errors. |
| Location snippets | `location-snippets` | Add a custom location block configuration for a service. |
| Server snippets | `server-snippets` | Add a custom server block configuration. |
| {{site.data.keyword.appid_short}} Authentication | `appid-auth` | Use IBM Cloud App ID to authenticate with your app. |

|Connection annotations|Name|Description|
|----------------------|----|-----------|
| Custom connect-timeouts and read-timeouts | `proxy-connect-timeout, proxy-read-timeout` | Set the time that the Ingress controller waits to connect to and read from the back-end app before the back-end app is considered unavailable. |
| Keepalive requests | `keepalive-requests` | Set the maximum number of requests that can be served through one keepalive connection. |
| Keepalive timeout | `keepalive-timeout` | Set the maximum time that a keepalive connection stays open between the client and the Ingress controller proxy server. |
| Proxy next upstream | `proxy-next-upstream-config` | Set when the Ingress controller can pass a request to the next upstream server. |
| Session-affinity with cookies | `sticky-cookie-services` | Always route incoming network traffic to the same upstream server by using a sticky cookie. |
| Upstream fail timeout | `upstream-fail-timeout` | Set the amount of time during which the Ingress controller can attempt to connect to the server before the server is considered unavailable. |
| Upstream keepalive | `upstream-keepalive` | Set the maximum number of idle keepalive connections for an upstream server. |
| Upstream keepalive timeout | `upstream-keepalive-timeout` | Set the maximum time that a keepalive connection stays open between the Ingress controller proxy server and your app's upstream server. |
| Upstream max fails | `upstream-max-fails` | Set the maximum number of unsuccessful attempts to communicate with the server before the server is considered unavailable. |

|HTTPS and TLS/SSL authentication annotations|Name|Description|
|--------------------------------------------|----|-----------|
| Custom HTTP and HTTPS ports] network traffic. |
| HTTP redirects to HTTPS | `redirect-to-https` | Redirect insecure HTTP requests on your domain to HTTPS. |
| HTTP Strict Transport Security (HSTS) | `hsts` | Set the browser to access the domain only by using HTTPS. |
| Mutual authentication | `mutual-auth` | Configure mutual authentication for the Ingress controller. |
| SSL services support | `ssl-services` | Allow SSL services support to encrypt traffic to your upstream apps that require HTTPS. |
| TCP ports | `tcp-ports` | Access an app via a non-standard TCP port.|

|Path routing annotations|Name|Description|
|------------------------|----|-----------|
| External services | `proxy-external-service` | Add path definitions to external services, such as a service hosted in IBM Cloud. |
| Location modifier | `location-modifier` | Modify the way the Ingress controller matches the request URI against the app path. |
| Rewrite paths | `rewrite-path` | Route incoming network traffic to a different path that your back-end app listens on. |

|Proxy buffer annotations|Name|Description|
|------------------------|----|-----------|
| Large client header buffers | `large-client-header-buffers` | Set the maximum number and size of buffers that read large client request headers. |
| Client response data buffering | `proxy-buffering` | Disable the buffering of a client response on the Ingress controller while sending the response to the client. |
| Proxy buffers | `proxy-buffers` | Set the number and size of the buffers that read a response for a single connection from the proxied server. |
| Proxy buffer size | `proxy-buffer-size` | Set the size of the buffer that reads the first part of the response that is received from the proxied server. |
| Proxy busy buffers size | `proxy-busy-buffers-size` | Set the size of proxy buffers that can be busy. |

|Request and response annotations|Name|Description|
|--------------------------------|----|-----------|
| Add server port to host header | `add-host-port` | Add the server port to the host for routing requests. |
| Client request body size | `client-max-body-size` | Set the maximum size of the body that the client can send as part of a request. |
| Additional client request or response header | `proxy-add-headers, response-add-headers` | Add header information to a client request before forwarding the request to your back-end app or to a client response before sending the response to the client. |
| Client response header removal | `response-remove-headers` | Remove header information from a client response before forwarding the response to the client. |

|Service limit annotations|Name|Description|
|------------------------|----|-----------|
| Global rate limits | `global-rate-limit` | Limit the request processing rate and number of connections per a defined key for all services. |
| Service rate limits | `service-rate-limit` | Limit the request processing rate and the number of connections per a defined key for specific services. |

### Custom error actions (`custom-errors`, `custom-error-actions`)


Indicate custom actions that the Ingress controller can take for specific HTTP errors.


**Description**

To handle specific HTTP errors that might occur, you can set up custom error actions for the Ingress controller to take.

* The `custom-errors` annotation defines the service name, the HTTP error to handle, and the name of the error action that the Ingress controller takes when it encounters the specified HTTP error for the service.
* The `custom-error-actions` annotation defines custom error actions in NGINX code snippets.

For example, in the `custom-errors` annotation, you can set up the Ingress controller to handle `401` HTTP errors for `app1` by returning a custom error action called `/errorAction401`. Then, in the `custom-error-actions` annotation, you can define a code snippet that is called `/errorAction401` so that the Ingress controller returns a custom error page to the client.

You can also use the `custom-errors` annotation to redirect the client to an error service that you manage. You must define the path to this error service in the `paths` section of the Ingress resource file.

**Sample Ingress resource YAML**


```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/custom-errors: "serviceName=<app1> httpError=<401> errorActionName=</errorAction401>;serviceName=<app2> httpError=<403> errorActionName=</errorPath>"
    ingress.bluemix.net/custom-error-actions: |
      errorActionName=</errorAction401>
      #Example custom error snippet
      proxy_pass http://example.com/forbidden.html;
      <EOS>
  spec:
    tls:
    - hosts:
      - mydomain
      secretName: mysecret
    rules:
    - host: mydomain
      http:
        paths:
        - path: /path1
          backend:
            serviceName: app1
            servicePort: 80
        - path: /path2
          backend:
            serviceName: app2
            servicePort: 80
        - path: </errorPath>
          backend:
            serviceName: <error-svc>
            servicePort: 80
```


|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<app1>` with the name of the Kubernetes service that the custom error applies to. The custom error applies only to the specific paths that use this same upstream service. If you do not set a service name, then the custom errors are applied to all service paths. |
| `httpError` | Replace `<401>` with the HTTP error code that you want to handle with a custom error action. |
| `errorActionName` | Replace `</errorAction401>` with the name of a custom error action to take or the path to an error service.<ul><li>If you specify the name of a custom error action, you must define that error action in a code snippet in the `custom-error-actions` annotation. In the sample YAML, `app1` uses `/errorAction401`, which is defined in the snippet in the `custom-error-actions` annotation.</li><li>If you specify the path to an error service, you must specify that error path and the name of the error service in the `paths` section. In the sample YAML, `app2` uses `/errorPath`, which is defined at the end of the `paths` section.</li></ul> |
| `ingress.bluemix.net/custom-error-actions` | Define a custom error action that the Ingress controller takes for the service and HTTP error that you specified. Use an NGINX code snippet and end each snippet with `<EOS>`. In the sample YAML, the Ingress controller passes a custom error page, `http://example.com/forbidden.html`, to the client when a `401` error occurs for `app1`.|

### Location snippets (`location-snippets`)


Add a custom location block configuration for a service.

**Description**

A server block is an NGINX directive that defines the configuration for the Ingress controller virtual server. A location block is an NGINX directive defined within the server block. Location blocks define how Ingress processes the request URI, or the part of the request that comes after the domain name or IP address and port.

When a server block receives a request, the location block matches the URI to a path and the request is forwarded to the IP address of the pod where the app is deployed. By using the `location-snippets` annotation, you can modify how the location block forwards requests to particular services.

To modify the server block as a whole instead, see the `server-snippets` annotation.

To view server and location blocks in the NGINX configuration file, run the following command for one of your Ingress controller pods: `kubectl exec -ti <ingress_controller_pod> -n kube-system -c nginx-ingress -- cat ./etc/nginx/conf.d/<kubernetes_namespace>-<ingress_resource_name>.conf`


**Sample Ingress resource YAML**


```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/location-snippets: |
      serviceName=<myservice1>
      # Example location snippet
      proxy_request_buffering off;
      rewrite_log on;
      proxy_set_header "x-additional-test-header" "location-snippet-header";
      <EOS>
      serviceName=<myservice2>
      proxy_set_header Authorization "";
      <EOS>
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: myservice
          servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name of the service that you created for your app. |
| Location snippet | Provide the configuration snippet that you want to use for the specified service. The sample snippet for the `myservice1` service configures the location block to turn off proxy request buffering, turn on log rewrites, and set additional headers when it forwards a request to the service. The sample snippet for the `myservice2` service sets an empty `Authorization` header. Every location snippet must end with the value `<EOS>`. |

### Server snippets (`server-snippets`)


Add a custom server block configuration.


**Description**

A server block is an NGINX directive that defines the configuration for the Ingress controller virtual server. By providing a custom configuration snippet in the `server-snippets` annotation, you can modify how the Ingress controller handles requests at the server level.

To view server and location blocks in the NGINX configuration file, run the following command for one of your Ingress controller pods: `kubectl exec -ti <ingress_controller_pod> -n kube-system -c nginx-ingress -- cat ./etc/nginx/conf.d/<kubernetes_namespace>-<ingress_resource_name>.conf`


**Sample Ingress resource YAML**


```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/server-snippets: |
      # Example snippet
      location = /health {
      return 200 'Healthy';
      add_header Content-Type text/plain;
      }
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: myservice
          servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| Server snippet | Provide the configuration snippet that you want to use. This sample snippet specifies a location block to handle `/health` requests. The location block is configured to return a healthy response and add a header when it forwards a request. |


You can use the `server-snippets` annotation to add a header for all service responses at a server level:


```yaml
annotations:
  ingress.bluemix.net/server-snippets: |
    add_header <header1> <value1>;
```




## Connection annotations


With connection annotations, you can change how the Ingress controller connects to the back-end app and upstream-servers, and set timeouts or a maximum number of keepalive connections before the app or server is considered to be unavailable.


### Custom connect-timeouts and read-timeouts (`proxy-connect-timeout`, `proxy-read-timeout`)


Set the time that the Ingress controller waits to connect to and read from the back-end app before the back-end app is considered unavailable.


**Description**

When a client request is sent to the Ingress controller, a connection to the back-end app is opened by the Ingress controller. By default, the Ingress controller waits 60 seconds to receive a reply from the back-end app. If the back-end app does not reply within 60 seconds, then the connection request is aborted and the back-end app is considered to be unavailable.

After the Ingress controller is connected to the back-end app, response data is read from the back-end app by the Ingress controller. During this read operation, the Ingress controller waits a maximum of 60 seconds between two read operations to receive data from the back-end app. If the back-end app does not send data within 60 seconds, the connection to the back-end app is closed and the app is considered to be not available.

A 60 second connect-timeout and read-timeout are the default timeouts on a proxy and usually should not be changed.

If the availability of your app is not steady or your app is slow to respond because of high workloads, you might want to increase the connect-timeout or read-timeout. Keep in mind that increasing the timeout impacts the performance of the Ingress controller as the connection to the back-end app must stay open until the timeout is reached.

On the other hand, you can decrease the timeout to gain performance on the Ingress controller. Ensure that your back-end app is able to handle requests within the specified timeout, even during higher workloads.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: myingress
 annotations:
   ingress.bluemix.net/proxy-connect-timeout: "serviceName=<myservice> timeout=<connect_timeout>"
   ingress.bluemix.net/proxy-read-timeout: "serviceName=<myservice> timeout=<read_timeout>"
spec:
 tls:
 - hosts:
   - mydomain
   secretName: mytlssecret
 rules:
 - host: mydomain
   http:
     paths:
     - path: /
       backend:
         serviceName: myservice
         servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `<connect_timeout>` | The number of seconds or minutes to wait to connect to the back-end app, for example `65s` or `1m`. A connect-timeout cannot exceed 75 seconds. |
| `<read_timeout>` | The number of seconds or minutes to wait before the back-end app is read, for example `65s` or `2m`.|

### Keepalive requests (`keepalive-requests`)


**Description**

Sets the maximum number of requests that can be served through one keepalive connection.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/keepalive-requests: "serviceName=<myservice> requests=<max_requests>"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: <myservice>
          servicePort: 8080
```



|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name of the Kubernetes service that you created for your app. This parameter is optional. The configuration is applied to all of the services in the Ingress subdomain unless a service is specified. If the parameter is provided, the keepalive requests are set for the given service. If the parameter is not provided, the keepalive requests are set at the server level of the `nginx.conf` for all the services that do not have the keepalive requests configured. |
| `requests` | Replace `<max_requests>` with the maximum number of requests that can be served through one keepalive connection. |

### Keepalive timeout (`keepalive-timeout`)


**Description**

Sets the maximum time that a keepalive connection stays open between the client and the Ingress controller proxy server. If you do not use this annotation, the default timeout value is `60s`.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: myingress
 annotations:
   ingress.bluemix.net/keepalive-timeout: "serviceName=<myservice> timeout=<time>s"
spec:
 tls:
 - hosts:
   - mydomain
   secretName: mytlssecret
 rules:
 - host: mydomain
   http:
     paths:
     - path: /
       backend:
         serviceName: myservice
         servicePort: 8080
```



|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name of the Kubernetes service that you created for your app. This parameter is optional. If the parameter is provided, the keepalive timeout is set for the given service. If the parameter is not provided, the keepalive timeout is set at the server level of the `nginx.conf` for all the services that do not have the keepalive timeout configured. |
| `timeout` | Replace `<time>` with an amount of time in seconds. Example: `timeout=20s`. A `0` value disables the keepalive client connections. |

### Proxy next upstream (`proxy-next-upstream-config`)


Set when the Ingress controller can pass a request to the next upstream server.


**Description**

The Ingress controller acts as a proxy between the client app and your app. Some app setups require multiple upstream servers that handle incoming client requests from the Ingress controller. Sometimes the proxy server that the Ingress controller uses cannot establish a connection with an upstream server that the app uses. The Ingress controller can then try to establish a connection with the next upstream server to pass the request to it instead. You can use the `proxy-next-upstream-config` annotation to set in which cases, for how long, and how many times the Ingress controller can try to pass a request to the next upstream server.

Timeout is always configured when you use `proxy-next-upstream-config`, so don't add `timeout=true` to this annotation.


**Sample Ingress resource YAML**


```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/proxy-next-upstream-config: "serviceName=<myservice1> retries=<tries> timeout=<time> error=true http_502=true; serviceName=<myservice2> http_403=true non_idempotent=true"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mysecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: myservice1
          servicePort: 80
```



|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name of the Kubernetes service that you created for your app. |
| `retries` | Replace `<tries>` with the maximum number of times that the Ingress controller tries to pass a request to the next upstream server. This number includes the original request. To turn off this limitation, use `0`. If you do not specify a value, the default value `0` is used. |
| `timeout` | Replace `<time>` with the maximum amount of time, in seconds, that the Ingress controller tries to pass a request to the next upstream server. For example, to set a time of 30 seconds, enter `30s`. To turn off this limitation, use `0`. If you do not specify a value, the default value `0` is used. |
| `error` | If set to `true`, the Ingress controller passes a request to the next upstream server when an error occurred while establishing a connection with the first upstream server, passing a request to it, or reading the response header. |
| `invalid_header` | If set to `true`, the Ingress controller passes a request to the next upstream server when the first upstream server returns an empty or invalid response. |
| `http_502` | If set to `true`, the Ingress controller passes a request to the next upstream server when the first upstream server returns a response with the code 502. You can designate the following HTTP response codes: `500`, `502`, `503`, `504`, `403`, `404`, `429`. |
| `non_idempotent` | If set to `true`, the Ingress controller can pass requests with a non-idempotent method to the next upstream server. By default, the Ingress controller does not pass these requests to the next upstream server. |
| `off` | To prevent the Ingress controller from passing requests to the next upstream server, set to `true`. |

### Session-affinity with cookies (`sticky-cookie-services`)


Use the sticky cookie annotation to add session affinity to your Ingress controller and always route incoming network traffic to the same upstream server.


**Description**

For high availability, some app setups require you to deploy multiple upstream servers that handle incoming client requests. When a client connects to your back-end app, you can use session-affinity so that a client is served by the same upstream server during a session or for the time it takes to complete a task. You can configure your Ingress controller to ensure session-affinity by always routing incoming network traffic to the same upstream server.

Every client that connects to your back-end app is assigned to one of the available upstream servers by the Ingress controller. The Ingress controller creates a session cookie that is stored in the client's app, which is included in the header information of every request between the Ingress controller and the client. The information in the cookie ensures that all requests are handled by the same upstream server throughout the session.

Relying on sticky sessions can add complexity and reduce your availability. For example, you might have an HTTP server that maintains some session state for an initial connection so that the HTTP service accepts only subsequent requests with the same session state value. However, this prevents easy horizontal scaling of the HTTP service. Consider using an external database, such as Redis or Memcached, to store the HTTP request session value so that you can maintain the session state across multiple servers.


When you include multiple services, use a semi-colon (;) to separate them.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/sticky-cookie-services: "serviceName=<myservice1> name=<cookie_name1> expires=<expiration_time1> path=<cookie_path1> hash=sha1 [secure] [httponly]"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /service1_path
        backend:
          serviceName: <myservice1>
          servicePort: 8080
      - path: /service2_path
        backend:
          serviceName: <myservice2>
          servicePort: 80
```



|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name of the Kubernetes service that you created for your app. |
| `name` | Replace `<cookie_name>` with the name of a sticky cookie that is created during a session. |
| `expires` | Replace `<expiration_time>` with the time in seconds (s), minutes (m), or hours (h) before the sticky cookie expires. This time is independent of the user activity. After the cookie is expired, the cookie is deleted by the client web browser and no longer sent to the Ingress controller. For example, to set an expiration time of 1 second, 1 minute, or 1 hour, enter `1s`, `1m`, or `1h`. |
| `path` | Replace `<cookie_path>` with the path that is appended to the Ingress subdomain and that indicates for which domains and subdomains the cookie is sent to the Ingress controller. For example, if your Ingress domain is `www.myingress.com` and you want to send the cookie in every client request, you must set `path=/`. If you want to send the cookie only for `www.myingress.com/myapp` and all its subdomains, then you must set `path=/myapp`. |
| `hash` | The hash algorithm that protects the information in the cookie. Only `sha1` is supported. SHA1 creates a hash sum based on the information in the cookie and appends this hash sum to the cookie. The server can decrypt the information in the cookie and verify data integrity. |
| `secure` | Include this parameter to enable secure cookies that are transferred only via HTTPS. This parameter is not required for HTTPS connections, but causes failures for HTTP connections. |
| `httponly` | Include this parameter to help prevent Cross Site Scripting attacks that use JavaScript to steal session cookies. If any apps that you expose with Ingress require JavaScript to interact with the session cookie, do not include this parameter. |

### Upstream fail timeout (`upstream-fail-timeout`)


Set the amount of time during which the Ingress controller can attempt to connect to the server.


**Description**

Set the amount of time during which the Ingress controller can attempt to connect to a server before the server is considered unavailable. For a server to be considered unavailable, the Ingress controller must hit the maximum number of failed connection attempts set by the `upstream-max-fails` annotation within the set amount of time. This amount of time also determines how long the server is considered unavailable.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/upstream-fail-timeout: "serviceName=<myservice> fail-timeout=<fail_timeout>"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: myservice
          servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `serviceName` (optional) | Replace `<myservice>` with the name of the Kubernetes service that you created for your app. |
| `fail-timeout` | Replace `<fail_timeout>` with the amount of time that the Ingress controller can attempt to connect to a server before the server is considered unavailable. The default is `10s`. Time must be in seconds. |

### Upstream keepalive (`upstream-keepalive`)


Set the maximum number of idle keepalive connections for an upstream server.


**Description**

Set the maximum number of idle keepalive connections to the upstream server of a given service. The upstream server has 64 idle keepalive connections by default.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/upstream-keepalive: "serviceName=<myservice> keepalive=<max_connections>"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: myservice
          servicePort: 8080
```



|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name of the Kubernetes service that you created for your app. |
| `keepalive` | Replace `<max_connections>` with the maximum number of idle keepalive connections to the upstream server. The default is `64`. A `0` value disables upstream keepalive connections for the given service. |

### Upstream keepalive timeout (`upstream-keepalive-timeout`)


**Description**

Sets the maximum time that a keepalive connection stays open between the Ingress controller proxy server and the upstream server for your back-end app. If you do not use this annotation, the default timeout value is `60s`.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: myingress
 annotations:
   ingress.bluemix.net/upstream-keepalive-timeout: "serviceName=<myservice> timeout=<time>s"
spec:
 tls:
 - hosts:
   - mydomain
   secretName: mytlssecret
 rules:
 - host: mydomain
   http:
     paths:
     - path: /
       backend:
         serviceName: myservice
         servicePort: 8080
```



|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name of the Kubernetes service that you created for your app. This parameter is optional. |
| `timeout` | Replace `<time>` with an amount of time in seconds. Example: `timeout=20s`. A `0` value disables the keepalive client connections. |

### Upstream max fails (`upstream-max-fails`)


Set the maximum number of unsuccessful attempts to communicate with the server.


**Description**

Set the maximum number of times the Ingress controller can fail to connect to the server before the server is considered unavailable. For the server to be considered unavailable, the Ingress controller must hit the maximum number within the duration of time set by the `upstream-fail-timeout` annotation. The duration of time that the server is considered unavailable is also set by the `upstream-fail-timeout` annotation.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/upstream-max-fails: "serviceName=<myservice> max-fails=<max_fails>"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: myservice
          servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `serviceName(Optional)` | Replace `<myservice>` with the name of the Kubernetes service that you created for your app. |
| `max-fails` | Replace `<max_fails>` with the maximum number of unsuccessful attempts the Ingress controller can make to communicate with the server. The default is `1`. A `0` value disables the annotation. |

## HTTPS and TLS/SSL authentication annotations


With HTTPS and TLS/SSL authentication annotations, you can configure your Ingress controller for HTTPS traffic, change default HTTPS ports, enable SSL encryption for traffic that is sent to your back-end apps, or set up mutual authentication.


### Custom HTTP and HTTPS ports (`custom-port`)


Change the default ports for HTTP (port 80) and HTTPS (port 443) network traffic.


**Description**

By default, the Ingress controller is configured to listen for incoming HTTP network traffic on port 80 and for incoming HTTPS network traffic on port 443. You can change the default ports to add security to your Ingress controller domain, or to enable only an HTTPS port.

To enable mutual authentication on a port, see "Opening non-default ports in the Ingress controller" to configure the Ingress controller to open the valid port, and then specify that port in the `mutual-auth` annotation. Do not use the `custom-port` annotation to specify a port for mutual authentication.


**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: myingress
 annotations:
   ingress.bluemix.net/custom-port: "protocol=<protocol1> port=<port1>;protocol=<protocol2> port=<port2>"
spec:
 tls:
 - hosts:
   - mydomain
   secretName: mytlssecret
 rules:
 - host: mydomain
   http:
     paths:
     - path: /
       backend:
         serviceName: myservice
         servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `<protocol>` | Enter `http` or `https` to change the default port for incoming HTTP or HTTPS network traffic. |
| `<port>` | Enter the port number to use for incoming HTTP or HTTPS network traffic. Note: When a custom port is specified for either HTTP or HTTPS, the default ports are no longer valid for both HTTP and HTTPS. For example, to change the default port for HTTPS to 8443, but use the default port for HTTP, you must set custom ports for both: `custom-port: "protocol=http port=80; protocol=https port=8443"`. |
**Usage**

1. Review open ports for your Ingress controller.
  ```
  kubectl get service -n kube-system
  ```


2. Open the Ingress controller config map.
  ```
  kubectl edit configmap ibm-cloud-provider-ingress-cm -n kube-system
  ```


3. Add the non-default HTTP and HTTPS ports to the config map. Replace `<port>` with the HTTP or HTTPS port that you want to open. Note: By default, ports 80 and 443 are open. If you want to keep 80 and 443 open, you must also include them in addition to any other TCP ports you specify in the `public-ports` field. If you enabled a private Ingress controller, you must also specify any ports you want to keep open in the `private-ports` field. For more information, see "Opening non-default ports in the Ingress controller".
  ```yaml
  apiVersion: v1
  kind: ConfigMap
  data:
    public-ports: <port1>;<port2>
  metadata:
    creationTimestamp: 2017-08-22T19:06:51Z
    name: ibm-cloud-provider-ingress-cm
    namespace: kube-system
    resourceVersion: "1320"
    selfLink: /api/v1/namespaces/kube-system/configmaps/ibm-cloud-provider-ingress-cm
    uid: <uid>
  ```


4. Verify that your Ingress controller is reconfigured with the non-default ports.
  ```
  kubectl get service -n kube-system
  ```
5. Configure your Ingress to use the non-default ports when routing incoming network traffic to your services. Use the annotation in the sample YAML file in this reference.

6. Update your Ingress controller configuration.
  ```
  kubectl apply -f myingress.yaml
  ```


7. Open your preferred web browser to access your app. Example: `https://<ibmdomain>:<port>/<service_path>/`



### HTTP redirects to HTTPS (`redirect-to-https`)


Convert insecure HTTP client requests to HTTPS.


**Description**

You set up your Ingress controller to secure your domain with the IBM-provided TLS certificate or your custom TLS certificate. Some users might try to access your apps by using an insecure `http` request to your Ingress controller domain, for example `http://www.myingress.com`, instead of using `https`. You can use the redirect annotation to always convert insecure HTTP requests to HTTPS. If you do not use this annotation, insecure HTTP requests are not converted into HTTPS requests by default and might expose unencrypted confidential information to the public.


Redirecting HTTP requests to HTTPS is disabled by default.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: myingress
 annotations:
   ingress.bluemix.net/redirect-to-https: "True"
spec:
 tls:
 - hosts:
   - mydomain
   secretName: mytlssecret
 rules:
 - host: mydomain
   http:
     paths:
     - path: /
       backend:
         serviceName: myservice
         servicePort: 8080
```




### HTTP Strict Transport Security (`hsts`)


**Description**

HSTS instructs the browser to access a domain only by using HTTPS. Even if the user enters or follows a plain HTTP link, the browser strictly upgrades the connection to HTTPS.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/hsts: enabled=true maxAge=<31536000> includeSubdomains=true
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mysecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /service1_path
        backend:
          serviceName: myservice1
          servicePort: 8443
      - path: /service2_path
        backend:
          serviceName: myservice2
          servicePort: 8444
          ```


|Annotation field|Value|
|----------------|-----|
| `enabled` | Use `true` to enable HSTS. |
| `maxAge` | Replace `<31536000>` with an integer that represents how many seconds a browser will cache sending requests straight to HTTPS. The default is `31536000`, which is equal to 1 year. |
| `includeSubdomains` | Use `true` to tell the browser that the HSTS policy also applies to all subdomains of the current domain. The default is `true`.  |

### Mutual authentication (`mutual-auth`)


Configure mutual authentication for the Ingress controller.


**Description**

Configure mutual authentication of downstream traffic for the Ingress controller. The external client authenticates the server and the server also authenticates the client by using certificates. Mutual authentication is also known as certificate-based authentication or two-way authentication.

Use the `mutual-auth` annotation for SSL termination between the client and the Ingress controller. Use the `ssl-services` annotation for SSL termination between the Ingress controller and the back-end app.

The mutual authentication annotation validates client certificates. To forward client certificates in a header for the applications to handle authorization, you can use the following `proxy-add-headers` annotation: `"ingress.bluemix.net/proxy-add-headers": "serviceName=router-set {\n X-Forwarded-Client-Cert $ssl_client_escaped_cert;\n}\n"`


**Pre-requisites**


* You must have a valid mutual authentication secret that contains the required `ca.crt`. To create a mutual authentication secret, see the steps at the end of this section.
* To enable mutual authentication on a port other than 443, see "Opening non-default ports in the Ingress controller" to configure the Ingress controller to open the valid port, and then specify that port in this annotation. Do not use the `custom-port` annotation to specify a port for mutual authentication.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/mutual-auth: "secretName=<mysecret> port=<port>"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: myservice
          servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `secretName` | Replace `<mysecret>` with a name for the secret resource. |
| `port` | Replace `<port>` with the Ingress controller port number. |


**To create a mutual authentication secret:**

1. Generate a certificate authority (CA) cert and key from your certificate provider. If you have your own domain, purchase an official TLS certificate for your domain. Make sure the [CN](https://support.dnsimple.com/articles/what-is-common-name/) is different for each certificate.
    For testing purposes, you can create a self-signed certificate by using OpenSSL. For more information, see this [self-signed SSL certificate tutorial](https://www.akadia.com/services/ssh_test_certificate.html) or this [mutual authentication tutorial, which includes creating your own CA](https://www.cloudbees.com/blog/how-to-set-up-mutual-tls-authentication/).

2. [Convert the cert into base64](https://www.base64encode.org/).
3. Create a secret YAML file by using cert.
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: ssl-my-test
   type: Opaque
   data:
     ca.crt: <ca_certificate>
   ```

4. Create a Kubernetes secret for your certificate.
   ```
   kubectl apply -f ssl-my-test
   ```




### SSL services support (`ssl-services`)


Allow HTTPS requests and encrypt traffic to your upstream apps.


**Description**

When your Ingress resource configuration has a TLS section, the Ingress controller can handle HTTPS-secured URL requests to your app. By default, the Ingress controller terminates the TLS termination and decrypts the request before using the HTTP protocol to forward the traffic to your apps. If you have apps that require the HTTPS protocol and need traffic to be encrypted, use the `ssl-services` annotation. With the `ssl-services` annotation, the Ingress controller terminates the external TLS connection, then creates a new SSL connection between the Ingress controller and the app pod. Traffic is re-encrypted before it is sent to the upstream pods.

If your back-end app can handle TLS and you want to add additional security, you can add one-way or mutual authentication by providing a certificate that is contained in a secret.

Use the `ssl-services` annotation for SSL termination between the Ingress controller and the back-end app. Use the `mutual-auth` annotation for SSL termination between the client and the Ingress controller.


**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: <myingressname>
  annotations:
    ingress.bluemix.net/ssl-services: ssl-service=<myservice1> ssl-secret=<service1-ssl-secret> proxy-ssl-verify-depth=<verification_depth> proxy-ssl-name=<service_CN>;ssl-service=<myservice2> ssl-secret=<service2-ssl-secret> proxy-ssl-verify-depth=<verification_depth> proxy-ssl-name=<service_CN>
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mysecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /service1_path
        backend:
          serviceName: myservice1
          servicePort: 8443
      - path: /service2_path
        backend:
          serviceName: myservice2
          servicePort: 8444
          ```


|Annotation field|Value|
|----------------|-----|
| `ssl-service` | Replace `<myservice>` with the name of the service that requires HTTPS. Traffic is encrypted from the Ingress controller to this app's service. |
| `ssl-secret` | If your back-end app can handle TLS and you want to add additional security, replace `<service-ssl-secret>` with the one-way or mutual authentication secret for the service.<ul><li>If you provide a one-way authentication secret, the value must contain the `trusted.crt` from the upstream server. To create a one-way secret, see the steps at the end of this section.</li><li>If you provide a mutual authentication secret, the value must contain the required `client.crt` and `client.key` that your app is expecting from the client. To create a mutual authentication secret, see the steps at the end of this section.</li></ul>If you do not provide a secret, Ingress does not verify the connection and relies on the back-end app to correctly use TLS. The connection is still encrypted, but insecure connections might be permitted. You might choose to omit a secret if you want to test the connection and do not have certificates ready, or if your certificates are expired and you want to allow insecure connections. |
| `proxy-ssl-verify-depth` | Optional: If you specify a secret in the `ssl-secret` parameter, replace `<verification_depth>` with the maximum number of certificates that are expected in the proxied HTTPS server certificates chain. This value indicates the maximum number of HTTPS server certificates in the chain that the Ingress controller verifies. The size of your server certificates chain can vary based on which kinds of authentication you set up. By default, the depth is set to `5`, which is sufficient for most cases. If you have a larger certificate chain, you can change the value of this parameter. The value must be an integer from `1` to `10`. |
| `proxy-ssl-name` | Optional: Specify a server name for the back-end server that is protected by the SSL certificate. The Ingress controller uses this server name as the Common Name (CN), instead of the CN in the certificate of the back-end server, to check the certificate of the back-end HTTPS server. This server name is also passed to the back-end server in the Server Name Indication (SNI) extension during the TLS handshake.Specifying an override CN for each service is helpful when you create two or more Ingress resource files, and the resources share the same wildcard trusted certificate for the secret. In this case, the resource share the same CN for the certificate. Because the Ingress controller generates the back-end server name based on the CN in the certificate, the Ingress controller configuration is invalid because the two services in the separate resources have the same back-end server name. You must use `proxy-ssl-name` to provide an override CN that is unique to each services' back-end server.For example, you might want the hostname to be `foo.mydomain.com` for Ingress resource A, and `mydomain.com` for Ingress resource B. You create one trusted certificate for both resources by using a wildcard CN. In the `ssl-services` annotation for resource A, you specify the CN as `proxy-ssl-name=foo.mydomain.com`. In the `ssl-services` annotation for resource B, you specify the CN as `proxy-ssl-name=mydomain.com`. The Ingress controller can now generate two distinct back-end server names for the services in each resource.The CN must exactly match the name of the back-end HTTPS server where the certificate is installed. If the certificate is issued for a subdomain, specify the full subdomain, such as `test.example.com`. If you use a wildcard certificate, you can specify the full hostname, such as `test.example.com` or `foo.example.com`, so that each hostname can use the same certificate. |


**To create a one-way authentication secret:**

1. Get the certificate authority (CA) key and certificate from your upstream server and an SSL client certificate. The IBM Ingress controller is based on NGINX, which requires the root certificate, intermediate certificate, and back-end certificate. For more information, see the [NGINX docs](https://docs.nginx.com/nginx/admin-guide/security-controls/securing-http-traffic-upstream/).
2. [Convert the cert into base64](https://www.base64encode.org/).
3. Create a secret YAML file by using the cert.
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: ssl-my-test
   type: Opaque
   data:
     trusted.crt: <ca_certificate>
   ```


   To also enforce mutual authentication for upstream traffic, you can provide a `client.crt` and `client.key` in addition to the `trusted.crt` in the data section.


4. Create a Kubernetes secret for your certificate.
   ```
   kubectl apply -f ssl-my-test
   ```



**To create a mutual authentication secret:**

1. Generate a certificate authority (CA) cert and key from your certificate provider. If you have your own domain, purchase an official TLS certificate for your domain. Make sure the [CN](https://support.dnsimple.com/articles/what-is-common-name/) is different for each certificate.
    For testing purposes, you can create a self-signed certificate by using OpenSSL. For more information, see this [self-signed SSL certificate tutorial](https://www.akadia.com/services/ssh_test_certificate.html) or this [mutual authentication tutorial, which includes creating your own CA](https://www.cloudbees.com/blog/how-to-set-up-mutual-tls-authentication/).

2. [Convert the cert into base64](https://www.base64encode.org/).
3. Create a secret YAML file by using the cert.
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: ssl-my-test
   type: Opaque
   data:
     client.crt: <ca_certificate>
     client.key: <ca_key>
   ```

4. Create a Kubernetes secret for your certificate.
   ```
   kubectl apply -f ssl-my-test
   ```




### TCP ports (`tcp-ports`)


Access an app via a non-standard TCP port.


**Description**

Use this annotation for an app that runs a TCP streams workload.

The Ingress controller operates in pass-through mode and forwards traffic to back-end apps. SSL termination is not supported in this case. The TLS connection is not terminated and passes through untouched.


**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/tcp-ports: "serviceName=<myservice> ingressPort=<ingress_port> servicePort=<service_port>"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mysecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: myservice
          servicePort: 80
```


|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name of the Kubernetes service to access over non-standard TCP port. |
| `ingressPort` | Replace `<ingress_port>` with the TCP port on which you want to access your app. |
| `servicePort` | This parameter is optional. When provided, the port is substituted to this value before traffic is sent to the back-end app. Otherwise, the port remains the same as the Ingress port. If you don't want to set this parameter, you can remove it from your configuration.  |


**Usage**

1. Review open ports for your Ingress controller.
```
kubectl get service -n kube-system
```

2. Open the Ingress controller config map.
```
kubectl edit configmap ibm-cloud-provider-ingress-cm -n kube-system
```

3. Add the TCP ports to the config map. Replace `<port>` with the TCP ports that you want to open.
  By default, ports 80 and 443 are open. If you want to keep 80 and 443 open, you must also include them in addition to any other TCP ports you specify in the `public-ports` field. If you enabled a private Ingress controller, you must also specify any ports that you want to keep open in the `private-ports` field. For more information, see "Opening non-default ports in the Ingress controller".

  ```yaml
  apiVersion: v1
  kind: ConfigMap
  data:
    public-ports: 80;443;<port1>;<port2>
  metadata:
    creationTimestamp: 2017-08-22T19:06:51Z
    name: ibm-cloud-provider-ingress-cm
    namespace: kube-system
    resourceVersion: "1320"
    selfLink: /api/v1/namespaces/kube-system/configmaps/ibm-cloud-provider-ingress-cm
    uid: <uid>
   ```


4. Verify that your Ingress controller is re-configured with the TCP ports.
  ```
  kubectl get service -n kube-system
  ```

5. Configure the Ingress controller to access your app via a non-standard TCP port. Use the `tcp-ports` annotation in the sample YAML file in this reference.

6. Either create your Ingress controller resource or update your existing Ingress controller configuration.
  ```
  kubectl apply -f myingress.yaml
  ```


7. Curl the Ingress subdomain to access your app. Example: `curl <domain>:<ingressPort>`



## Path routing annotations


The Ingress controller routes traffic to the paths that back-end apps listen on. With path routing annotations, you can configure how the Ingress controller routes traffic to your apps.


### External services (`proxy-external-service`)


Add path definitions to external services, such as services hosted in IBM Cloud.


**Description**

Add path definitions to external services. Use this annotation only when your app operates on an external service instead of a back-end service, and you want to route requests to that external service through the Ingress subdomain or custom subdomain that you specify. When you use this annotation to create an external service route, only `client-max-body-size`, `proxy-read-timeout`, `proxy-connect-timeout`, and `proxy-buffering` annotations are supported in conjunction. Any other annotations are not supported in conjunction with `proxy-external-service`.

You cannot specify multiple hosts for a single service and path.


Looking to forward requests to the IP address of your external service instead of routing requests through the Ingress controller? See "Exposing external apps through a Kubernetes endpoint".


**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/proxy-external-service: "path=<mypath> external-svc=https:<external_service> host=<ingress_subdomain>"
spec:
  rules:
  - host: <ingress_subdomain>
```


|Annotation field|Value|
|----------------|-----|
| `path` | Replace `<mypath>` with the path that the external service listens on. |
| `external-svc` | Replace `<external_service>` with the external service to be called. For example, `https://<myservice>.<region>.appdomain.com`. |
| `host` | Replace `<ingress_subdomain>` with the Ingress subdomain for your cluster or the custom domain that you set up. |

### Location modifier (`location-modifier`)


Modify the way the Ingress controller matches the request URI against the app path.


**Description**

By default, Ingress controllers process the paths that apps listen on as prefixes. When an Ingress controller receives a request to an app, the Ingress controller checks the Ingress resource for a path (as a prefix) that matches the beginning of the request URI. If a match is found, the request is forwarded to the IP address of the pod where the app is deployed.

The `location-modifier` annotation changes the way the Ingress controller searches for matches by modifying the location block configuration. The location block determines how requests are handled for the app path.

To handle regular expression (regex) paths, this annotation is required.


|Modifier|Description|
|--------|-----------|
| `=` | The equal sign modifier causes the Ingress controller to select exact matches only. When an exact match is found, the search stops and the matching path is selected.<br>For example, if your app listens on `/tea`, the Ingress controller selects only exact `/tea` paths when matching a request to your app. |
| `~` | The tilde modifier causes the Ingress controller to process paths as case-sensitive regex paths during matching.<br>For example, if your app listens on `/coffee`, the Ingress controller can select `/ab/coffee` or `/123/coffee` paths when matching a request to your app even though the paths are not explicitly set for your app. |
| `~*` | The tilde modifier that is followed by an asterisk modifier causes the Ingress controller to process paths as case-insensitive regex paths during matching.<br>For example, if your app listens on `/coffee`, the Ingress controller can select `/ab/Coffee` or `/123/COFFEE` paths when matching a request to your app even though the paths are not explicitly set for your app. |
| `^~` | The carat followed by a tilde modifier causes the Ingress controller to select the best non-regex match instead of a regex path. |
{: caption="Supported modifiers" caption-side="top"}

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/location-modifier: "modifier='<location_modifier>' serviceName=<myservice1>;modifier='<location_modifier>' serviceName=<myservice2>"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mysecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: myservice
          servicePort: 80
```


|Annotation field|Value|
|----------------|-----|
| `modifier` | Replace `<location_modifier>` with the location modifier you want to use for the path. Supported modifiers are `'='`, `'~'`, `'~\*'`, and `'^~'`. You must surround the modifiers in single quotes. |
| `serviceName` | Replace `<myservice>` with the name of the Kubernetes service you created for your app. |

### Rewrite paths (`rewrite-path`)


Route incoming network traffic on an Ingress controller domain path to a different path that your back-end app listens on.


**Description**

Your Ingress controller domain routes incoming network traffic on `mykubecluster.us-south.containers.appdomain.cloud/beans` to your app. Your app listens on `/coffee`, instead of `/beans`. To forward incoming network traffic to your app, add the rewrite annotation to your Ingress resource configuration file. The rewrite annotation ensures that incoming network traffic on `/beans` is forwarded to your app by using the `/coffee` path. When including multiple services, use only a semi-colon (;) with no space before or after the semi-colon to separate them.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/rewrite-path: "serviceName=<myservice1> rewrite=<target_path1>;serviceName=<myservice2> rewrite=<target_path2>"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mysecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /beans
        backend:
          serviceName: myservice1
          servicePort: 80
```


|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name of the Kubernetes service that you created for your app. |
| `rewrite` | Replace `<target_path>` with the path that your app listens on. Incoming network traffic on the Ingress controller domain is forwarded to the Kubernetes service by using this path. Most apps do not listen on a specific path, but use the root path and a specific port. In the example for `mykubecluster.us-south.containers.appdomain.cloud/beans`, the rewrite path is `/coffee`. Note: If you apply this file and the URL shows a `404` response, your backend app might be listening on a path that ends in `/`. Try adding a trailing `/` to this rewrite field, then reapply the file and try the URL again. |

## Proxy buffer annotations


The Ingress controller acts as a proxy between your back-end app and the client web browser. With proxy buffer annotations, you can configure how data is buffered on your Ingress controller when you send or receive data packets.


### Large client header buffers (`large-client-header-buffers`)


Set the maximum number and size of buffers that read large client request headers.


**Description**

Buffers that read large client request headers are allocated only by demand: If a connection is transitioned into the keepalive state after the end-of-request processing, these buffers are released. By default, there are `4` buffers and buffer size is equal to `8K` bytes. If a request line exceeds the set maximum size of one buffer, the `414 Request-URI Too Large` HTTP error is returned to the client. Additionally, if a request header field exceeds the set maximum size of one buffer, the `400 Bad Request` error is returned to the client. You can adjust the maximum number and size of buffers that are used for reading large client request headers.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: myingress
 annotations:
   ingress.bluemix.net/large-client-header-buffers: "number=<number> size=<size>"
spec:
 tls:
 - hosts:
   - mydomain
   secretName: mytlssecret
 rules:
 - host: mydomain
   http:
     paths:
     - path: /
       backend:
         serviceName: myservice
         servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `<number>` | The maximum number of buffers that should be allocated to read large client request header. For example, to set it to 4, define `4`. |
| `<size>` | The maximum size of buffers that read large client request header. For example, to set it to 16 kilobytes, define `16k`. The size must end with a `k` for kilobyte or `m` for megabyte. |

### Client response data buffering (`proxy-buffering`)


Use the buffer annotation to disable the storage of response data on the Ingress controller while the data is sent to the client.


**Description**

The Ingress controller acts as a proxy between your back-end app and the client web browser. When a response is sent from the back-end app to the client, the response data is buffered on the Ingress controller by default. The Ingress controller proxies the client response and starts sending the response to the client at the client's pace. After all data from the back-end app is received by the Ingress controller, the connection to the back-end app is closed. The connection from the Ingress controller to the client remains open until the client receives all data.

If buffering of response data on the Ingress controller is disabled, data is immediately sent from the Ingress controller to the client. The client must be able to handle incoming data at the pace of the Ingress controller. If the client is too slow, the upstream connection remains open until the client can catch up.

Response data buffering on the Ingress controller is enabled by default.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: myingress
 annotations:
   ingress.bluemix.net/proxy-buffering: "enabled=false serviceName=<myservice1>"
spec:
 tls:
 - hosts:
   - mydomain
   secretName: mytlssecret
 rules:
 - host: mydomain
   http:
     paths:
     - path: /
       backend:
         serviceName: myservice
         servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `enabled` | To disable response data buffering on the Ingress controller, set to `false`. |
| `serviceName` | Replace <em>`<myservice1>`</em> with the name of the Kubernetes service that you created for your app. Separate multiple services with a semi-colon (;). This field is optional. If you do not specify a service name, then all services use this annotation. |

### Proxy buffers (`proxy-buffers`)


Configure the number and size of proxy buffers for the Ingress controller.


**Description**

Set the number and size of the buffers that read a response for a single connection from the proxied server. The configuration is applied to all of the services in the Ingress subdomain unless a service is specified. For example, if a configuration such as `serviceName=SERVICE number=2 size=1k` is specified, 1k is applied to the service. If a configuration such as `number=2 size=1k` is specified, 1k is applied to all of the services in the Ingress subdomain. Tip: If you get the error message `upstream sent too big header while reading response header from upstream`, the upstream server in your back end sent a header size that is larger than the default limit. Increase the size for both `proxy-buffers` and `proxy-buffer-size`.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: proxy-ingress
 annotations:
   ingress.bluemix.net/proxy-buffers: "serviceName=<myservice> number=<number_of_buffers> size=<size>"
spec:
 tls:
 - hosts:
   - mydomain
   secretName: mytlssecret
 rules:
 - host: mydomain
   http:
     paths:
     - path: /
       backend:
         serviceName: myservice
         servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name for a service to apply proxy-buffers. |
| `number` | Replace `<number_of_buffers>` with a number, such as `2`. |
| `size` | Replace `<size>` with the size of each buffer in kilobytes (k or K), such as `1K`. |

### Proxy buffer size (`proxy-buffer-size`)


Configure the size of the proxy buffer that reads the first part of the response.


**Description**

Set the size of the buffer that reads the first part of the response that is received from the proxied server. This part of the response usually contains a small response header. The configuration is applied to all of the services in the Ingress subdomain unless a service is specified. For example, if a configuration such as `serviceName=SERVICE size=1k` is specified, 1k is applied to the service. If a configuration such as `size=1k` is specified, 1k is applied to all of the services in the Ingress subdomain.

If you get the error message `upstream sent too big header while reading response header from upstream`, the upstream server in your back end sent a header size that is larger than the default limit. Increase the size for both `proxy-buffer-size` and `proxy-buffers`.


**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: proxy-ingress
 annotations:
   ingress.bluemix.net/proxy-buffer-size: "serviceName=<myservice> size=<size>"
spec:
 tls:
 - hosts:
   - mydomain
   secretName: mytlssecret
 rules:
 - host: mydomain
   http:
     paths:
     - path: /
       backend:
         serviceName: myservice
         servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name of a service to apply proxy-buffers-size. |
| `size` | Replace `<size>` with the size of each buffer in kilobytes (k or K), such as `1K`. To calculate the proper size, you can check out [this blog post](https://www.getpagespeed.com/server-setup/nginx/tuning-proxy_buffer_size-in-nginx). |

### Proxy busy buffers size (`proxy-busy-buffers-size`)


Configure the size of proxy buffers that can be busy.


**Description**

Limit the size of any buffers that are sending a response to the client while the response is not yet fully read. In the meantime, the rest of the buffers can read the response and, if needed, buffer part of the response to a temporary file. The configuration is applied to all of the services in the Ingress subdomain unless a service is specified. For example, if a configuration such as `serviceName=SERVICE size=1k` is specified, 1k is applied to the service. If a configuration such as `size=1k` is specified, 1k is applied to all of the services in the Ingress subdomain.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: proxy-ingress
 annotations:
   ingress.bluemix.net/proxy-busy-buffers-size: "serviceName=<myservice> size=<size>"
spec:
 tls:
 - hosts:
   - mydomain
   secretName: mytlssecret
 rules:
 - host: mydomain
   http:
     paths:
     - path: /
       backend:
         serviceName: myservice
         servicePort: 8080
         ```


|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name of a service to apply proxy-busy-buffers-size. |
| `size` | Replace `<size>` with the size of each buffer in kilobytes (k or K), such as `1K`. |

## Request and response annotations


Use request and response annotations to add or remove header information from the client and server requests, and to change the size of the body that the client can send.


### Add server port to host header (`add-host-port`)


Add a server port to the client request before the request is forwarded to your back-end app.


**Description**

Add the `:server_port` to the host header of a client request before forwarding the request to your back-end app.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: myingress
 annotations:
   ingress.bluemix.net/add-host-port: "enabled=true serviceName=<myservice>"
spec:
 tls:
 - hosts:
   - mydomain
   secretName: mytlssecret
 rules:
 - host: mydomain
   http:
     paths:
     - path: /
       backend:
         serviceName: myservice
         servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `enabled` | Set to `true` to add `:server_port` to the host header of requests. |
| `serviceName` | Replace <em>`<myservice>`</em> with the name of the Kubernetes service that you created for your app. Separate multiple services with a semi-colon (;). This field is optional. If you do not specify a service name, then all services use this annotation. |

### Additional client request or response header (`proxy-add-headers`, `response-add-headers`)


Add extra header information to a client request before sending the request to the back-end app or to a client response before sending the response to the client.


**Description**

The Ingress controller acts as a proxy between the client app and your back-end app. Client requests that are sent to the Ingress controller are processed (proxied) and put into a new request that is then sent to your back-end app. Similarly, back-end app responses that are sent to the Ingress controller are processed (proxied) and put into a new response that is then sent to the client. Proxying a request or response removes HTTP header information, such as the username, that was initially sent from the client or back-end app.

If your back-end app requires HTTP header information, you can use the `proxy-add-headers` annotation to add header information to the client request before the request is forwarded by the Ingress controller to the back-end app. If the client web app requires HTTP header information, you can use the `response-add-headers` annotation to add header information to the response before the response is forwarded by the Ingress controller to the client web app.<br>



The `response-add-headers` annotation does not support global headers for all services. To add a header for all service responses at a server level, you can use the `server-snippets` annotation:

```yaml
annotations:
  ingress.bluemix.net/server-snippets: |
    add_header <header1> <value1>;
```



**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/proxy-add-headers: |
      serviceName=<myservice1> {
      <header1> <value1>;
      <header2> <value2>;
      }
      serviceName=<myservice2> {
      <header3> <value3>;
      }
    ingress.bluemix.net/response-add-headers: |
      serviceName=<myservice1> {
      <header1>:<value1>;
      <header2>:<value2>;
      }
      serviceName=<myservice2> {
      <header3>:<value3>;
      }
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /service1_path
        backend:
          serviceName: <myservice1>
          servicePort: 8080
      - path: /service2_path
        backend:
          serviceName: <myservice2>
          servicePort: 80
```


|Annotation field|Value|
|----------------|-----|
| `service_name` | Replace `<myservice>` with the name of the Kubernetes service that you created for your app. |
| `<header>` | The key of the header information to add to the client request or client response. |
| `<value>` | The value of the header information to add to the client request or client response. |

### Client response header removal (`response-remove-headers`)


Remove header information that is included in the client response from the back-end end app before the response is sent to the client.


**Description**

The Ingress controller acts as a proxy between your back-end app and the client web browser. Client responses from the back-end app that are sent to the Ingress controller are processed (proxied), and put into a new response that is then sent from the Ingress controller to the client web browser. Although proxying a response removes http header information that was initially sent from the back-end app, this process might not remove all back-end app specific headers. Remove header information from a client response before the response is forwarded from the Ingress controller to the client web browser.

**Sample Ingress resource YAML**


```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/response-remove-headers: |
      serviceName=<myservice1> {
      "<header1>";
      "<header2>";
      }
      serviceName=<myservice2> {
      "<header3>";
      }
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /service1_path
        backend:
          serviceName: <myservice1>
          servicePort: 8080
      - path: /service2_path
        backend:
          serviceName: <myservice2>
          servicePort: 80
```


|Annotation field|Value|
|----------------|-----|
| `service_name` | Replace `<myservice>` with the name of the Kubernetes service that you created for your app. |
| `<header>` | The key of the header to remove from the client response. |

### Client request body size (`client-max-body-size`)


Set the maximum size of the body that the client can send as part of a request.


**Description**

To maintain the expected performance, the maximum client request body size is set to 1 megabyte. When a client request with a body size over the limit is sent to the Ingress controller, and the client does not allow data to be divided, the Ingress controller returns a 413 (Request Entity Too Large) HTTP response to the client. A connection between the client and the Ingress controller is not possible until the size of the request body is reduced. When the client allows data to be split up into multiple chunks, data is divided into packages of 1 megabyte and sent to the Ingress controller.

You might want to increase the maximum body size because you expect client requests with a body size that is greater than 1 megabyte. For example, you want your client to be able to upload large files. Increasing the maximum request body size might impact the performance of your Ingress controller because the connection to the client must stay open until the request is received.

Some client web browsers cannot display the 413 HTTP response message properly.


**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: myingress
 annotations:
   ingress.bluemix.net/client-max-body-size: "serviceName=<myservice> size=<size>; size=<size>"
spec:
 tls:
 - hosts:
   - mydomain
   secretName: mytlssecret
 rules:
 - host: mydomain
   http:
     paths:
     - path: /
       backend:
         serviceName: myservice
         servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `serviceName` | Optional: To apply a client max body size to a specific service, replace `<myservice>` with the name of the service. If you do not specify a service name, the size is applied to all services. In the example YAML, the format `"serviceName=<myservice> size=<size>; size=<size>"` applies the first size to the `myservice` service and applies the second size to all other services.|
| `size` | Replace `<size>` with the maximum size of the client response body. For example, to set the maximum size to 200 megabytes, define `200m`. You can set the size to 0 to disable the check of the client request body size. |

## Service limit annotations


With service limit annotations, you can change the default request processing rate and the number of connections that can come from a single IP address.


### Global rate limits (`global-rate-limit`)


Limit the request processing rate and number of connections per a defined key for all services.


**Description**

For all services, limit the request processing rate and the number of connections per a defined key that are coming from a single IP address for all paths of the selected back ends.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/global-rate-limit: "key=<key> rate=<rate> conn=<number-of-connections>"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: myservice
          servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `key` | Supported values are `location`, `$http_` headers, and `$uri`. To set a global limit for incoming requests based on the zone or service, use `key=location`. To set a global limit for incoming requests based on the header, use `X-USER-ID key=$http_x_user_id`. |
| `rate` | Replace `<rate>` with the processing rate. Enter a value as a rate per second (r/s) or rate per minute (r/m). Example: `50r/m`. |
| `conn` | Replace `<number-of-connections>` with the number of connections. |

### Service rate limits (`service-rate-limit`)


Limit the request processing rate and the number of connections for specific services.


**Description**

For specific services, limit the request processing rate and the number of connections per a defined key that are coming from a single IP address for all paths of the selected back ends.

**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/service-rate-limit: "serviceName=<myservice> key=<key> rate=<rate> conn=<number_of_connections>"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: myservice
          servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `serviceName` | Replace `<myservice>` with the name of the service for which you want to limit the processing rate. |
| `key` | Supported values are `location`, `$http_` headers, and `$uri`. To set a global limit for incoming requests based on the zone or service, use `key=location`. To set a global limit for incoming requests based on the header, use `X-USER-ID key=$http_x_user_id`. |
| `rate` | Replace `<rate>` with the processing rate. To define a rate per second, use r/s: `10r/s`. To define a rate per minute, use r/m: `50r/m`. |
| `conn` | Replace `<number-of-connections>` with the number of connections. |

### App ID Authentication (`appid-auth`)


Use IBM Cloud App ID to authenticate with your app.


**Description**

Authenticate web or API HTTP/HTTPS requests with App ID.

If you set the request type to web, a web request that contains an App ID access token is validated. If token validation fails, the web request is rejected. If the request does not contain an access token, then the request is redirected to the App ID login page. For App ID web authentication to work, cookies must be enabled in the user's browser.

If you set the request type to api, an API request that contains an App ID access token is validated. If the request does not contain an access token, a 401: Unauthorized error message is returned to the user.

For security reasons, App ID authentication supports only back ends with TLS/SSL enabled.


**Usage**

Because the app uses App ID for authentication, you must provision an App ID instance, configure the instance with valid redirect URIs, and generate a bind secret by binding the instance to your cluster.

1. Choose an existing or create a new App ID instance.
  * To use an existing instance, ensure that the service instance name doesn't contain spaces. To remove spaces, select the more options menu next to the name of your service instance and select **Rename service**.
  * To provision a [new App ID instance](https://cloud.ibm.com/catalog/services/app-id):
      1. Replace the auto-filled **Service name** with your own unique name for the service instance. The service instance name can't contain spaces.
      2. Choose the same region that your cluster is deployed in.
      3. Click **Create**.

2. Add redirect URLs for your app. A redirect URL is the callback endpoint of your app. To prevent phishing attacks, IBM Cloud App ID validates the request URL against the allowlist of redirect URLs.
  1. In the App ID management console, navigate to **Manage Authentication**.
  2. In the **Identity providers** tab, make sure that you have an Identity Provider selected. If no Identity Provider is selected, the user will not be authenticated but will be issued an access token for anonymous access to the app.
  3. In the **Authentication settings** tab, add redirect URLs for your app in the format `http://<hostname>/<app_path>/appid_callback` or `https://<hostname>/<app_path>/appid_callback`.

    IBM Cloud App ID offers a logout function: If `/logout` exists in your IBM Cloud App ID path, cookies are removed and the user is sent back to the login page. To use this function, you must append `/appid_logout` to your domain in the format `https://<hostname>/<app_path>/appid_logout` and include this URL in the redirect URLs list.


3. Bind the App ID service instance to your cluster. The command creates a service key for the service instance, or you can include the `--key` flag to use existing service key credentials.
  ```
  ibmcloud ks cluster service bind --cluster <cluster_name_or_ID> --namespace <namespace> --service <service_instance_name> [--key <service_instance_key>]
  ```

  When the service is successfully added to your cluster, a cluster secret is created that holds the credentials of your service instance. Example CLI output:
  ```
  ibmcloud ks cluster service bind --cluster mycluster --namespace mynamespace --service appid1
  Binding service instance to namespace...
  OK
  Namespace:    mynamespace
  Secret name:  binding-<service_instance_name>
  ```


4. Get the secret that was created in your cluster namespace.
  ```
  kubectl get secrets --namespace=<namespace>
  ```


5. Use the bind secret and the cluster namespace to add the `appid-auth` annotation to your Ingress resource.

When you use the bind secret in the `appid-auth` annotation, the secret is cached by the Ingress controller. If you change the App ID service binding, the new secret for App ID that is generated is not used by the Ingress controller. You must restart your Ingress controller pods to pick up the new secret.


**Sample Ingress resource YAML**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myingress
  annotations:
    ingress.bluemix.net/appid-auth: "bindSecret=<bind_secret> namespace=<namespace> requestType=<request_type> serviceName=<myservice> idToken=true"
spec:
  tls:
  - hosts:
    - mydomain
    secretName: mytlssecret
  rules:
  - host: mydomain
    http:
      paths:
      - path: /
        backend:
          serviceName: myservice
          servicePort: 8080
```


|Annotation field|Value|
|----------------|-----|
| `bindSecret` | Replace <em>`<bind_secret>`</em> with the Kubernetes secret, which stores the bind secret for your App ID service instance. |
| `namespace` | Replace <em>`<namespace>`</em> with the namespace of the bind secret. This field defaults to the `default` namespace. |
| `requestType` | Replace <em>`<request_type>`</em> with the type of request you want to send to App ID. Accepted values are `web` or `api`. The default is `api`. |
| `serviceName` | Replace <em>`<myservice>`</em> with the name of the Kubernetes service that you created for your app. This field is required. Specify only one service name per service path that you define in the resource file. |
| `idToken=true` | Optional: The Liberty OIDC client is unable to parse both the access and the identity token at the same time. When working with Liberty, set this value to false so that the identity token is not sent to the Liberty server. |

## Opening non-default ports in the Ingress controller

1. Edit the YAML file for the `ibm-cloud-provider-ingress-cm` configmap.
```
kubectl edit cm ibm-cloud-provider-ingress-cm -n kube-system
```

2. Add a `data` section and specify the public ports `80`, `443`, and any other ports you want to expose separated by a semi-colon (;). By default, ports 80 and 443 are open. If you want to keep 80 and 443 open, you must also include them in addition to any other ports you specify in the `public-ports` field. Any port that is not specified is closed. If you enabled a private Ingress controller, you must also specify any ports that you want to keep open in the `private-ports` field.

Example that keeps ports `80`, `443`, and `9443` open:
```yaml
apiVersion: v1
data:
  public-ports: "80;443;9443"
kind: ConfigMap
metadata:
  name: ibm-cloud-provider-ingress-cm
  namespace: kube-system
```

3. Save the configuration file.

4. Verify that the configmap changes were applied. The changes are applied to your Ingress controllers automatically.
```
kubectl get cm ibm-cloud-provider-ingress-cm -n kube-system -o yaml
```

5. Optional:
  * Access an app via a non-standard TCP port that you opened by using the `tcp-ports` annotation.
  * Change the default ports for HTTP (port 80) and HTTPS (port 443) network traffic to a port that you opened by using the `custom-port` annotation.


## Increasing the restart readiness check time for Ingress controller pods

Increase the amount of time that Ingress controller pods have to parse large Ingress resource files when the Ingress controller pods restart.

When an Ingress controller pod restarts, such as after an update is applied, a readiness check prevents the Ingress controller pod from attempting to route traffic requests until all of the Ingress resource files are parsed. This readiness check prevents request loss when Ingress controller pods restart. By default, the readiness check waits 15 seconds after the pod restarts to start checking whether all Ingress files are parsed. If all files are parsed 15 seconds after the pod restarts, the Ingress controller pod begins to route traffic requests again. If all files are not parsed 15 seconds after the pod restarts, the pod does not route traffic, and the readiness check continues to check every 15 seconds for a maximum timeout of 5 minutes. After 5 minutes, the Ingress controller pod begins to route traffic.

If you have very large Ingress resource files, it might take longer than 5 minutes for all of the files to be parsed. You can change the default values for the readiness check interval rate and for the total maximum readiness check timeout by adding the `ingress-resource-creation-rate` and `ingress-resource-timeout` settings to the `ibm-cloud-provider-ingress-cm` configmap.

1. Edit the configuration file for the `ibm-cloud-provider-ingress-cm` configmap resource.
```
kubectl edit cm ibm-cloud-provider-ingress-cm -n kube-system
```

2. In the **data** section, add the `ingress-resource-creation-rate` and `ingress-resource-timeout` settings. Values can be formatted as seconds (`s`) and minutes (`m`). Example:
 ```yaml
 apiVersion: v1
 data:
   ingress-resource-creation-rate: 1m
   ingress-resource-timeout: 6m
   keep-alive: 8s
   private-ports: 80;443
   public-ports: 80;443
 ```

3. Save the configuration file.

4. Verify that the configmap changes were applied. The changes are applied to your Ingress controllers automatically.
```
kubectl get cm ibm-cloud-provider-ingress-cm -n kube-system -o yaml
```

## Preserving the source IP address


By default, the source IP addresses of client requests are not preserved by the Ingress controller. To preserve source IP addresses, you can enable the PROXY protocol in VPC clusters or change the `externalTrafficPolicy` in classic clusters.


### Enabling the PROXY protocol in VPC clusters


To preserve the source IP address of the client request in a VPC cluster, you can enable the [NGINX PROXY protocol](https://docs.nginx.com/nginx/admin-guide/load-balancer/using-proxy-protocol/) for all load balancers that expose Ingress controllers in your cluster.

The PROXY protocol enables load balancers to pass client connection information that is contained in headers on the client request, including the client IP address, the proxy server IP address, and both port numbers, to Ingress controllers.

1. Enable the PROXY protocol. After you run this command, new load balancers are created with the updated PROXY protocol configuration. Two unused IP addresses for each load balancer must be available in each subnet during the load balancer recreation. After these load balancers are created, the existing Ingress controller load balancers are deleted. This load balancer recreation process might cause service disruptions.
```
ibmcloud ks ingress lb proxy-protocol enable --cluster <cluster_name_or_ID>
```

2. Confirm that the PROXY protocol is enabled for the load balancers that expose Ingress controllers in your cluster.
```
ibmcloud ks ingress lb get --cluster <cluster_name_or_ID>
```


3. To later disable the PROXY protocol, you can run the following command:
```
ibmcloud ks ingress lb proxy-protocol disable --cluster <cluster_name_or_ID>
```


### Changing the `externalTrafficPolicy` in classic clusters


Preserve the source IP address for client requests in a classic cluster.


By default, the source IP address of the client request is not preserved. When a client request to your app is sent to your cluster, the request is routed to a pod for the load balancer service that exposes the Ingress controller. If no app pod exists on the same worker node as the load balancer service pod, the load balancer forwards the request to an app pod on a different worker node. The source IP address of the package is changed to the public IP address of the worker node where the app pod runs.

To preserve the original source IP address of the client request, you can enable [source IP preservation](https://kubernetes.io/docs/tutorials/services/source-ip/#source-ip-for-services-with-typeloadbalancer). Preserving the client’s IP is useful, for example, when app servers have to apply security and access-control policies.

Note: When source IP preservation is enabled, load balancers shift from forwarding traffic to an app pod on a different worker node to an app pod on the same worker node. Your apps might experience downtime during this shift.

**Before you begin**: If you configured edge nodes in your cluster, Ingress controller pods are deployed to edge nodes and can only forward traffic to app pods that are also deployed to those edge nodes. Ensure that you have [at least three edge worker nodes per zone](cloud.ibm.com/docs/containers?topic=containers-edge#edge_nodes).

1. Enable source IP preservation.
  1. Get the name of the service that exposes the Ingress controller.
      ```
      kubectl get svc -n kube-system
      ```


  2. Open the YAML for the service that exposes the Ingress controller.
      ```
      kubectl edit svc <svc> -n kube-system
      ```

  3. Under **`spec`**, change the value of **`externalTrafficPolicy`** from `Cluster` to `Local`.

  4. Save and close the configuration file.


2. Verify that the source IP is being preserved in your Ingress controller pods logs.
  1. Get the ID of a pod for the Ingress controller that you modified.
      ```
      kubectl get pods -n kube-system
      ```


  2. Open the logs for that Ingress controller pod. Verify that the IP address for the `client` field is the client request IP address instead of the load balancer service IP address.
      ```
      kubectl logs <Ingress controller_pod_ID> nginx-ingress -n kube-system
      ```


3. Now, when you look up the headers for the requests that are sent to your back-end app, you can see the client IP address in the `x-forwarded-for` header.

4. If you no longer want to preserve the source IP, you can revert the changes that you made to the service.

## Configuring SSL protocols and SSL ciphers at the HTTP level


Enable SSL protocols and ciphers at the global HTTP level by editing the `ibm-cloud-provider-ingress-cm` configmap.


For example, if you still have legacy clients that require TLS 1.0 or 1.1 support, you must manually enable these TLS versions to override the default setting of TLS 1.2 and TLS 1.3 only. For more information about how to see the TLS versions that your clients use to access your apps, see this [{{site.data.keyword.cloud_notm}} blog post](https://www.ibm.com/cloud/blog/ibm-cloud-kubernetes-service-alb-update-tls-1-0-and-1-1-disabled-by-default).

When you specify the enabled protocols for all hosts, the TLSv1.1 and TLSv1.2 parameters (1.1.13, 1.0.12) work only when OpenSSL 1.0.1 or higher is used. The TLSv1.3 parameter (1.13.0) works only when OpenSSL 1.1.1 built with TLSv1.3 support is used.
{: note}

To edit the configmap to enable SSL protocols and ciphers:

1. Edit the configuration file for the `ibm-cloud-provider-ingress-cm` configmap resource.

  ```
  kubectl edit cm ibm-cloud-provider-ingress-cm -n kube-system
  ```


2. Add the SSL protocols and ciphers. Format ciphers according to the [OpenSSL library cipher list format](https://www.openssl.org/docs/man1.0.2/man1/ciphers.html).

 ```yaml
 apiVersion: v1
 data:
   ssl-protocols: "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"
   ssl-ciphers: "HIGH:!aNULL:!MD5:!CAMELLIA:!AESCCM:!ECDH+CHACHA20"
 kind: ConfigMap
 metadata:
   name: ibm-cloud-provider-ingress-cm
   namespace: kube-system
 ```


3. Save the configuration file.

4. Verify that the configmap changes were applied. The changes are applied to your Ingress controllers automatically.

 ```
 kubectl get cm ibm-cloud-provider-ingress-cm -n kube-system -o yaml
 ```

## Adding Ingress controller socket listeners for each NGINX worker process


Increase the number of socket listeners from one socket listener for each Ingress controller to one socket listener for each NGINX worker process for that Ingress controller by using the `reuse-port` Ingress directive.


When the `reuse-port` option is disabled, a single listening socket notifies an Ingress controller about incoming connections, and all NGINX worker processes for that Ingress controller attempt to take the connection. But when `reuse-port` is enabled, one socket listener exists for each worker process. Instead of each worker process attempting to take the connection, the Linux kernel determines which available socket listener gets the connection. Lock contention between workers is reduced, which can improve performance. For more information about the benefits and drawbacks of the `reuse-port` directive, see [this NGINX blog post](https://www.nginx.com/blog/socket-sharding-nginx-release-1-9-1/).

1. Edit the configuration file for the `ibm-cloud-provider-ingress-cm` configmap resource.
    ```
    kubectl edit cm ibm-cloud-provider-ingress-cm -n kube-system
    ```


2. In the `data` section, add `reuse-port: "true"`. Example:
   ```yaml
   apiVersion: v1
   data:
     private-ports: 80;443;9443
     public-ports: 80;443
     reuse-port: "true"
   ...
   ```


3. Save the configuration file.

4. Verify that the configmap changes were applied. The changes are applied to your Ingress controllers automatically.

   ```
   kubectl get cm ibm-cloud-provider-ingress-cm -n kube-system -o yaml
   ```


## Enabling log buffering and flush timeout


By default, the Ingress controller logs each request as it arrives. If you have an environment that is heavily used, logging each request as it arrives can greatly increase disk I/O utilization. To avoid continuous disk I/O, you can enable log buffering and flush timeout for the Ingress controller by editing the `ibm-cloud-provider-ingress-cm` Ingress configmap. When buffering is enabled, instead of performing a separate write operation for each log entry, the Ingress controller buffers a series of entries and writes them to the file together in a single operation.


1. Create and edit the configuration file for the `ibm-cloud-provider-ingress-cm` configmap resource.

    ```
    kubectl edit cm ibm-cloud-provider-ingress-cm -n kube-system
    ```


2. Edit the configmap.
    1. Enable log buffering by adding the `access-log-buffering` field and setting it to `"true"`.

    2. Set the threshold for when the Ingress controller should write buffered contents to the log.
        * Buffer size: Add the `buffer` field and set it to how much log memory can be held in the buffer before the Ingress controller writes the buffered contents to the log file. For example, if the default value of `100KB` is used, the Ingress controller writes buffer contents to the log file every time the buffer reaches 100KB of log content.
        * Time interval: Add the `flush` field and set it to how often the Ingress controller should write to the log file. For example, if the default value of `5m` is used, the Ingress controller writes buffer contents to the log file once every 5 minutes.
        * Time interval or buffer size: When both `flush` and `buffer` are set, the Ingress controller writes buffer content to the log file based on whichever threshold parameter is met first.

      ```yaml
      apiVersion: v1
      kind: ConfigMap
      data:
        access-log-buffering: "true"
        flush-interval: "5m"
        buffer-size: "100KB"
      metadata:
        name: ibm-cloud-provider-ingress-cm
        ...
      ```


3. Save the configuration file.

4. Verify that the logs for an Ingress controller now contain buffered content that is written according to the memory size or time interval you set.

   ```
   kubectl logs -n kube-system <svc> -c nginx-ingress
   ```


## Changing the number or duration of keepalive connections


Keepalive connections can have a major impact on performance by reducing the CPU and network usage that is needed to open and close connections. To optimize the performance of your Ingress controllers, you can change the maximum number of keepalive connections between the Ingress controller and the client and how long the keepalive connections can last.


1. Edit the configuration file for the `ibm-cloud-provider-ingress-cm` configmap resource.

    ```
    kubectl edit cm ibm-cloud-provider-ingress-cm -n kube-system
    ```


2. Change the values of `keep-alive-requests` and `keep-alive`.
    * `keep-alive-requests`: The number of keepalive client connections that can stay open to the Ingress controller. The default is `4096`.
    * `keep-alive`: The timeout, in seconds, during which the keepalive client connection stays open to the Ingress controller. The default is `8s`.
   ```yaml
   apiVersion: v1
   data:
     keep-alive-requests: "4096"
     keep-alive: "8s"
   kind: ConfigMap
   metadata:
     name: ibm-cloud-provider-ingress-cm
     namespace: kube-system
   ```


3. Save the configuration file.

4. Verify that the configmap changes were applied. The changes are applied to your Ingress controllers automatically.

   ```
   kubectl get cm ibm-cloud-provider-ingress-cm -n kube-system -o yaml
   ```


## Changing the pending connections backlog


You can decrease the default backlog setting for how many pending connections can wait in the server queue.


In the `ibm-cloud-provider-ingress-cm` Ingress configmap, the `backlog` field sets the maximum number of pending connections that can wait in the server queue. By default, `backlog` is set to `32768`. You can override the default by editing the Ingress configmap.

1. Edit the configuration file for the `ibm-cloud-provider-ingress-cm` configmap resource.

    ```
    kubectl edit cm ibm-cloud-provider-ingress-cm -n kube-system
    ```


2. Change the value of `backlog` from `32768` to a lower value. The value must be equal to or lesser than 32768.

   ```yaml
   apiVersion: v1
   data:
     backlog: "32768"
   kind: ConfigMap
   metadata:
     name: ibm-cloud-provider-ingress-cm
     namespace: kube-system
   ```


3. Save the configuration file.

4. Verify that the configmap changes were applied. The changes are applied to your Ingress controllers automatically.

   ```
   kubectl get cm ibm-cloud-provider-ingress-cm -n kube-system -o yaml
   ```
