#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(int));
    __uint(value_size, 256); // Max filename length
    __uint(max_entries, 1);
} target_filename_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct sys_enter_args *ctx)
{
    int zero = 0;
    char *target = bpf_map_lookup_elem(&target_filename_map, &zero);
    if (!target) {
        return 0;
    }

    struct event e = {};
    long ret;
    
    // Read filename safely
    ret = bpf_probe_read_user_str(e.filename, sizeof(e.filename), (void *)ctx->args[1]);
    if (ret <= 0) {
        return 0;
    }

    // Compare strings properly
    for (int i = 0; i < sizeof(e.filename); i++) {
        if (e.filename[i] != target[i]) {
            return 0;
        }
        // Stop at null terminator
        if (e.filename[i] == '\0') {
            break;
        }
    }

    // Fill event data
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    
    // Submit event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";