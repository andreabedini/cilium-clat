module github.com/andreabedini/cilium-clat

go 1.26

require (
	github.com/cilium/ebpf v0.22.0
	github.com/containernetworking/cni v1.3.1
	github.com/containernetworking/plugins v1.9.1
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.43.0
)

require github.com/vishvananda/netns v0.0.5 // indirect
