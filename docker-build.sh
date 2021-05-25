#!/bin/bash -e

echo "export UBUNTU_REPO=http://archive.ubuntu.com/ubuntu/" > ./nginx-controller/ubuntu-info
echo "export GH_LINK=https://github.com" >> ./nginx-controller/ubuntu-info
echo "export NGINX_LINK=http://nginx.org/download" >> ./nginx-controller/ubuntu-info
echo "export NGINX_GOODIES_LINK=https://bitbucket.org/nginx-goodies/nginx-sticky-module-ng" >> ./nginx-controller/ubuntu-info

# show local images
docker images

docker build --progress=plain --build-arg BASE_IMAGE="${BASE_IMAGE}" --build-arg REPO_SOURCE_URL="${REPO_SOURCE_URL}" --build-arg BUILD_URL="${BUILD_URL}" -t ${FULL_IMAGE_NAME}:${IMAGE_TAG} .
