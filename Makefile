GOPRIVATE := github.com
GONOPROXY := github.com
GO111MODULE := on

all: container
# This is to test if jenkins job will create multiple images
#VERSION = 0.7.0
#TAG = $(VERSION)
PREFIX = ingress
IMAGE_TAG ?= test
IMAGE_NAME ?= ingress
FULL_IMAGE_NAME ?= ibm-cloud-kubernetes/${IMAGE_NAME}

BASE_IMG_REGISTRY ?=
BASE_IMAGE ?= $(BASE_IMG_REGISTRY)ubuntu:18.04

SHELL := /usr/bin/env bash
OSS_FILES := Dockerfile go.mod
LINT_VERSION?="1.32.2"
NANCY_VERSION?=1.0.15
NANCY_ARGS?="-o json"

export

.PHONY: install-golangci
install-golangci:
if ! which golangci-lint >/dev/null || [[ "$$(golangci-lint --version)" != *${LINT_VERSION}* ]]; then \
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v${LINT_VERSION}; \
fi

nginx-ingress:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags "-s -w" -o nginx-controller/nginx-ingress nginx-controller/main.go

.PHONY: lint
lintall: install-golangci gofmt govet golint gosec

.PHONY: gosec
gosec:
	golangci-lint run --disable-all --enable=gosec

.PHONY: golint
golint:
	golangci-lint run --disable-all --enable=golint

.PHONY: govet
govet:
	golangci-lint run --disable-all --enable=govet

.PHONY: gofmt
gofmt:
	golangci-lint run --disable-all --enable=gofmt

.PHONY: dofmt
dofmt:
	golangci-lint run --disable-all --enable=gofmt --fix

.PHONY: test
test:
	go test ./...

.PHONY: clean
clean:
	rm -f nginx-ingress

.PHONY: container
container: dep nginx-ingress
	sudo -E BASE_IMAGE=$(BASE_IMAGE) -Eu ${USER} ./docker-build.sh

.PHONY: dep
dep:
	go mod tidy

.PHONY: list-go-deps
list-go-deps: 
	go version -m nginx-controller/nginx-ingress | awk '{printf "{\"Path\": \"%s\", \"Version\": \"%s\"}\n", $$2, $$3}'

.PHONY: dep-check
dep-check: nginx-ingress
	make --quiet list-go-deps | docker run --rm -i sonatypecommunity/nancy:v$(NANCY_VERSION) sleuth

