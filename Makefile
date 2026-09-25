GO ?= go
IMAGE ?= ghcr.io/andreabedini/cilium-clat:latest

.PHONY: all build generate test test-bpf test-netns image vet clean

all: build

## build: static plugin binary in bin/
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o bin/cilium-clat ./cmd/cilium-clat

## generate: recompile bpf/clat.c with clang via bpf2go (commit the output)
generate:
	$(GO) generate ./internal/clat/

vet:
	$(GO) vet ./...

## test: unit tests; the BPF_PROG_TEST_RUN tests skip without CAP_BPF
test:
	$(GO) test ./...

## test-bpf: BPF_PROG_TEST_RUN tests as root (verifier + packet oracle)
test-bpf:
	sudo --preserve-env=GOPATH,GOMODCACHE,GOFLAGS,GOCACHE,HOME $(GO) test -v -run 'Egress|Ingress|RoundTrip' ./internal/clat/

## test-netns: three-netns integration test as root, needs bin/cilium-clat
test-netns: build
	sudo BIN=$(CURDIR)/bin/cilium-clat hack/netns-test.sh

image:
	docker build -f deploy/Dockerfile -t $(IMAGE) .

clean:
	rm -rf bin
