# Build context: repository root.
#   docker build -f deploy/Dockerfile -t ghcr.io/andreabedini/cilium-clat:latest .
# The BPF object is committed (internal/clat/clat_bpfel.o), so the image build
# needs no clang. Run `make generate` after editing bpf/clat.c.
FROM docker.io/library/golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /cilium-clat ./cmd/cilium-clat

FROM docker.io/library/alpine:3.22
COPY --from=build /cilium-clat /cilium-clat
