//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I." tracepoint tracepoint.c -- -target bpf

package main

import "C"
