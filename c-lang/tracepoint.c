#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct sys_enter_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long args[6];
};

struct event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, 256);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_RDONLY_PROG);  // Critical: Makes map read-only for BPF programs
} target_filename_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct sys_enter_args *ctx)
{
    struct event e = {};
    char *target_filename;
    int key = 0;
    
    // Read filename from syscall arguments
    bpf_probe_read_user_str(e.filename, sizeof(e.filename), (void *)ctx->args[1]);

    // Get target filename from map
    target_filename = bpf_map_lookup_elem(&target_filename_map, &key);
    if (!target_filename) {
        return 0;
    }
    
    // Compare filenames - now safe because map is read-only
    for (int i = 0; i < sizeof(e.filename); i++) {
        if (e.filename[i] != target_filename[i]) {
            return 0;  // No match
        }
        if (e.filename[i] == 0 || target_filename[i] == 0) {
            break;  // End of string
        }
    }

    // If we get here, filenames match
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";