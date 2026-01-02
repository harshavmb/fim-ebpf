#include "vmlinux.h"

//#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
//#include <linux/sched.h>

struct sys_enter_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long args[6];
};

struct event {
    __u32 pid;
    __u32 uid;
    __u32 euid;
    __u32 loginuid;
    __u32 filename_hash;  // Hash of filename for matching
    char comm[16];
    char filename[256];   // Full filename for userspace verification
    __u32 flags;
    __u32 event_type;     // 0: OPEN, 1: UNLINK
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));  // Stores filename hashes
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 32);
} target_hashes_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));  // UIDs to ignore
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 16);
} ignore_uids_map SEC(".maps");

// Simple hash function that the verifier can understand
static inline __u32 simple_hash(const char *str) {
    __u32 hash = 5381;
    for (int i = 0; i < 256 && str[i] != '\0'; i++) {
        hash = ((hash << 5) + hash) + str[i];  // hash * 33 + c
    }
    return hash;
}

static inline int handle_event(struct sys_enter_args *ctx, const char *filename_ptr, __u32 flags, __u32 type) {
    struct event e = {};
    long ret;
    
    // Read filename
    ret = bpf_probe_read_user_str(e.filename, sizeof(e.filename), (void *)filename_ptr);
    if (ret <= 0) return 0;

    // Debug: Print every filename accessed
    bpf_printk("file accessed: %s", e.filename);

    // Calculate filename hash
    e.filename_hash = simple_hash(e.filename);

    // Check if hash matches any monitored files
    __u32 *match = bpf_map_lookup_elem(&target_hashes_map, &e.filename_hash);
    if (!match) return 0;

    // Get UID information
    __u64 uid_gid = bpf_get_current_uid_gid();
    e.uid = uid_gid;
    e.euid = (uid_gid >> 32);
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    
    if (parent) {
        e.loginuid = BPF_CORE_READ(parent, loginuid.val);
    } else {
        e.loginuid = 4294967295; // AUDIT_UID_UNSET
    }

    bpf_printk("BPF DEBUG: pid=%d uid=%d euid=%d loginuid=%d", e.pid, e.uid, e.euid, e.loginuid);
    
    // Check ignored UIDs
    // 1. If the original user (loginuid) is ignored, ignore the event.
    __u32 *ignore_login = bpf_map_lookup_elem(&ignore_uids_map, &e.loginuid);
    if (ignore_login) return 0;

    // 2. If the effective user (uid) is ignored, we need to check if it's a sudo action.
    __u32 *ignore_uid = bpf_map_lookup_elem(&ignore_uids_map, &e.uid);
    if (ignore_uid) {
        // If loginuid is unset or same as uid, it's a direct action by the ignored user -> Ignore.
        // If loginuid is different and valid (and not ignored, checked above), it's likely sudo -> Capture.
        if (e.loginuid == 4294967295 || e.loginuid == e.uid) {
            return 0;
        }
    }

    // Get process info
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    e.flags = flags;
    e.event_type = type;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct sys_enter_args *ctx) {
    return handle_event(ctx, (const char *)ctx->args[1], (__u32)ctx->args[2], 0);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct sys_enter_args *ctx) {
    return handle_event(ctx, (const char *)ctx->args[1], (__u32)ctx->args[2], 1);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct sys_enter_args *ctx) {
    return handle_event(ctx, (const char *)ctx->args[0], 0, 1);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";