# Configuring optional settings

Set up additional configurations and enable optional settings for the Ingress controller.

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
  * Access an app via a non-standard TCP port that you opened by using the [`tcp-ports` annotation](/docs/annotations.md#tcp-ports-tcp-ports).
  * Change the default ports for HTTP (port 80) and HTTPS (port 443) network traffic to a port that you opened by using the [`custom-port` annotation](/docs/annotations.md#custom-http-and-https-ports-custom-port).

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

**Before you begin**: If you configured edge nodes in your cluster, Ingress controller pods are deployed to edge nodes and can only forward traffic to app pods that are also deployed to those edge nodes. Ensure that you have [at least three edge worker nodes per zone](https://cloud.ibm.com/docs/containers?topic=containers-edge#edge_nodes).

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
