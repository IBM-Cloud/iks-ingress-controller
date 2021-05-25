# syntax = docker/dockerfile:1.0-experimental
ARG BASE_IMAGE
FROM $BASE_IMAGE


ARG REPO_SOURCE_URL
ARG BUILD_URL
LABEL compliance.owner="ibm-containers-ingress"
LABEL razee.io/source-url=$REPO_SOURCE_URL
LABEL razee.io/build-url=$BUILD_URL

ENV razee.io/source-url=$REPO_SOURCE_URL
ENV razee.io/build-url=$BUILD_URL

RUN --mount=type=bind,target=/tmp/nginx-controller,source=nginx-controller,readwrite apt-get update && \ 
        apt-get install -y ca-certificates && \
        /bin/bash -c 'source /tmp/nginx-controller/ubuntu-info && \
        cp /etc/apt/sources.list /tmp/source.list && \
        sed -i "s,http://archive.ubuntu.com/ubuntu/,[trusted=yes] ${UBUNTU_REPO}," /etc/apt/sources.list && \
        /tmp/nginx-controller/build.sh' && \
        cp /tmp/source.list /etc/apt/sources.list && \
        rm /tmp/source.list 

# forward nginx access and error logs to stdout and stderr of the ingress
# controller process
RUN ln -sf /proc/1/fd/1 /var/log/nginx/access.log \
        && ln -sf /proc/1/fd/2 /var/log/nginx/error.log

COPY ./nginx-controller/nginx-ingress ./nginx-controller/nginx/ingress.server.tmpl ./nginx-controller/nginx/stream.tmpl ./nginx-controller/nginx/ingress.tmpl ./nginx-controller/nginx/nginx.conf.tmpl ./nginx-controller/nginx/ingress.frontend.tmpl ./nginx-controller/nginx/ingress.backend.tmpl ./nginx-controller/nginx/index.html.tmpl ./nginx-controller/nginx/default.conf.tmpl ./nginx-controller/nginx/utility.lua.tmpl ./nginx-controller/parser/annotations.json ./nginx-controller/internal/errors.json /

COPY ./nginx-controller/nginx/crossdomain.xml /usr/share/nginx/xml/

ENTRYPOINT ["/nginx-ingress"]
