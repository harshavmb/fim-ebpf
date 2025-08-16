package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// event matches the C struct in your BPF program
type event struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
}

func main() {
	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load the pre-compiled BPF program
	objs := tracepointObjects{}
	if err := loadTracepointObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Populate the target filename map (critical part)
	targetFilename := "/tmp/testfile\x00" // Null-terminated
	var filenameBuf [256]byte
	copy(filenameBuf[:], targetFilename)

	key := uint32(0)
	if err := objs.TargetFilenameMap.Put(key, filenameBuf); err != nil {
		log.Fatalf("putting target filename in map: %v", err)
	}

	// Attach the tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	// Set up perf event reader
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %v", err)
	}
	defer rd.Close()

	log.Println("Monitoring for openat() syscalls to /tmp/testfile...")

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from perf reader: %v", err)
				continue
			}

			if len(record.RawSample) < int(unsafe.Sizeof(event{})) {
				log.Printf("invalid sample size: %d", len(record.RawSample))
				continue
			}

			var e event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("parsing event: %v", err)
				continue
			}

			// Convert byte arrays to strings
			comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
			filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

			log.Printf("PID: %d, UID: %d, CMD: %s, FILE: %s",
				e.Pid, e.Uid, comm, filename)
		}
	}()

	<-sig
	log.Println("Shutting down...")
}
