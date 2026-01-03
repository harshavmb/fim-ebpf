package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v3"
)

type Config struct {
	MonitoredFiles []string `yaml:"monitored_files"`
	IgnoreActions  []string `yaml:"ignore_actions"`
	IgnoreUsers    []string `yaml:"ignore_users"`
}

type event struct {
	Pid          uint32
	Uid          uint32
	Euid         uint32
	Loginuid     uint32
	FilenameHash uint32
	Comm         [16]byte
	Filename     [256]byte
	Flags        uint32
	EventType    uint32
}

// simpleHash implements the same DJB2-like hash as the eBPF C code.
func simpleHash(filename string) uint32 {
	hash := uint32(5381)
	for _, c := range []byte(filename) {
		hash = ((hash << 5) + hash) + uint32(c) // hash * 33 + c
	}
	return hash
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}

func parseUint32(s string) (uint32, error) {
	var n uint32
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func isReadOperation(flags uint32) bool {
	return (flags & (syscall.O_WRONLY | syscall.O_RDWR)) == 0
}

func main() {
	cfg, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := tracepointObjects{}
	if err := loadTracepointObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	// Populate filename hashes
	for _, file := range cfg.MonitoredFiles {
		hash := simpleHash(file)
		val := uint32(1) // Just a marker
		if err := objs.TargetHashesMap.Put(hash, val); err != nil {
			log.Fatalf("Failed to add hash for %s: %v", file, err)
		}

		// Add basename hash to capture relative accesses (e.g. open("file") when in /etc)
		base := filepath.Base(file)
		if base != file {
			baseHash := simpleHash(base)
			if err := objs.TargetHashesMap.Put(baseHash, val); err != nil {
				log.Printf("Failed to add basename hash for %s: %v", base, err)
			}
		}
	}

	// Populate ignored UIDs
	for _, username := range cfg.IgnoreUsers {
		u, err := user.Lookup(username)
		if err != nil {
			log.Printf("Warning: user %s not found", username)
			continue
		}
		uid, err := parseUint32(u.Uid)
		if err != nil {
			log.Fatalf("Failed to parse UID for %s: %v", u.Uid, err)
		}

		if err := objs.IgnoreUidsMap.Put(uid, uint32(1)); err != nil {
			log.Printf("Failed to ignore UID %d: %v", uid, err)
		}
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tp.Close()

	tpUnlink, err := link.Tracepoint("syscalls", "sys_enter_unlink", objs.TraceUnlink, nil)
	if err != nil {
		// sys_enter_unlink might not exist on all architectures (e.g., arm64 uses unlinkat)
		// so we just log it as info/debug rather than a warning if it's missing.
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("Note: sys_enter_unlink not available: %v", err)
		}
	} else {
		defer tpUnlink.Close()
	}

	tpUnlinkat, err := link.Tracepoint("syscalls", "sys_enter_unlinkat", objs.TraceUnlinkat, nil)
	if err != nil {
		log.Printf("Warning: failed to attach sys_enter_unlinkat: %v", err)
	} else {
		defer tpUnlinkat.Close()
	}

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("Reading event: %v", err)
				continue
			}

			var e event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("Decoding event: %v", err)
				continue
			}

			// Final verification in userspace
			matched := false
			currentFile := string(bytes.TrimRight(e.Filename[:], "\x00"))

			// Resolve relative path
			resolvedFile := currentFile
			if !filepath.IsAbs(currentFile) {
				// Get CWD for the pid
				cwdLink := fmt.Sprintf("/proc/%d/cwd", e.Pid)
				cwd, err := os.Readlink(cwdLink)
				if err == nil {
					resolvedFile = filepath.Join(cwd, currentFile)
				}
			}

			for _, file := range cfg.MonitoredFiles {
				if resolvedFile == file || currentFile == file {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}

			// Skip ignored actions
			if e.EventType == 0 && isReadOperation(e.Flags) && contains(cfg.IgnoreActions, "read") {
				continue
			}

			// Get username from UID
			currentUsername := "unknown"
			if e.Uid == 0 {
				currentUsername = "root"
			} else if user, err := user.LookupId(fmt.Sprintf("%d", e.Uid)); err == nil {
				currentUsername = user.Username
			}

			// With this more robust version:
			userInfo := fmt.Sprintf("%d (%s)", e.Uid, currentUsername)
			// 4294967295 is AUDIT_UID_UNSET ((u32)-1)
			if e.Loginuid != 4294967295 && e.Uid != e.Loginuid {
				loginUser, err := user.LookupId(fmt.Sprintf("%d", e.Loginuid))
				loginUsername := "unknown"
				if err == nil {
					loginUsername = loginUser.Username
				}
				userInfo = fmt.Sprintf("%d (%s) [Login: %d (%s)]",
					e.Uid, currentUsername, e.Loginuid, loginUsername)
			}

			action := "OPEN"
			if e.EventType == 1 {
				action = "DELETE"
			}

			log.Printf("Event: PID=%d UID=%d (%s) CMD=%s FILE=%s ACTION=%s FLAGS=%08x",
				e.Pid,
				e.Uid,
				userInfo,
				string(bytes.TrimRight(e.Comm[:], "\x00")),
				string(bytes.TrimRight(e.Filename[:], "\x00")),
				action,
				e.Flags,
			)
		}
	}()

	log.Println("Monitoring started. Ctrl+C to exit.")
	<-sig
	log.Println("Shutting down...")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
