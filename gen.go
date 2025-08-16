package main

import "C"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux tracepoint tracepoint.c
