package clat

// The BPF object is compiled with clang and embedded through bpf2go. The
// generated files are committed so that `go build` does not need clang.
//
// The multiarch include directories cover Debian and Ubuntu, where the asm/
// kernel headers live under /usr/include/<triplet>; clang ignores the ones
// that do not exist.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cflags "-O2 -g -Wall -Wextra -Werror" -go-package clat clat ../../bpf/clat.c -- -I../../bpf/include -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu
