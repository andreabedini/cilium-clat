package clat

// The BPF object is compiled with clang and embedded through bpf2go. The
// generated files are committed so that `go build` does not need clang.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cflags "-O2 -g -Wall -Wextra -Werror" -go-package clat clat ../../bpf/clat.c -- -I../../bpf/include
