# Docker and Kubernetes

Two facts decide every container setup:

1. **Sets belong to a network namespace.** nginx sees the sets of the namespace
   it runs in.
2. **The helper needs `CAP_NET_ADMIN`** in that namespace. nginx's workers drop
   every capability.

## Docker

=== "Use the host's sets"

    The usual case: fail2ban or CrowdSec on the host fills the sets.

    ```bash
    docker run -d --cap-add NET_ADMIN --network host \
        -v "$PWD/sundew.conf:/etc/nginx/conf.d/sundew.conf:ro" \
        ghcr.io/jan-krueger/sundew:latest
    ```

=== "The container's own sets"

    The container's namespace starts with no sets, and nginx refuses to start
    until they exist. Create them before nginx in a derived image; the official
    nginx image runs `/docker-entrypoint.d/*.sh` first:

    ```dockerfile title="Dockerfile"
    FROM ghcr.io/jan-krueger/sundew:latest
    RUN apt-get update && apt-get install -y --no-install-recommends ipset \
     && rm -rf /var/lib/apt/lists/*
    COPY --chmod=0755 10-ipsets.sh /docker-entrypoint.d/
    ```

    ```sh title="10-ipsets.sh"
    #!/bin/sh
    ipset -exist create bad_guys hash:ip timeout 86400
    ```

    ```bash
    docker run -d --cap-add NET_ADMIN -p 80:80 my-nginx
    ```

    Fill the set from inside the container, for example
    `docker exec <container> ipset add bad_guys 192.0.2.1`.

nginx as the container's PID 1 works; `--init` is not needed.

## Kubernetes

Containers in a pod share its network namespace, so an init container can
create the sets and a sidecar can keep them filled.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  initContainers:
    - name: ipsets
      image: alpine:3.24
      command: ["sh", "-c", "apk add --no-cache ipset && ipset -exist create bad_guys hash:ip timeout 86400"]
      securityContext:
        capabilities: { add: ["NET_ADMIN"] }
  containers:
    - name: nginx
      image: ghcr.io/jan-krueger/sundew:latest
      securityContext:
        capabilities: { add: ["NET_ADMIN"] }
      volumeMounts:
        - { name: conf, mountPath: /etc/nginx/conf.d/sundew.conf, subPath: sundew.conf }
  volumes:
    - name: conf
      configMap: { name: sundew }
```

- With `hostNetwork: true` the pod uses the node's sets instead, and needs no
  init container.
- Behind an ingress or a cloud load balancer, configure realip as in
  [Behind a CDN or load balancer](behind-a-proxy.md).
- Not supported: running nginx without root inside the container (for example
  `runAsNonRoot: true` with an unprivileged image). The master must be root to
  start the helper.
