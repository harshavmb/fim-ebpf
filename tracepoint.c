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
    __u32 parent_hash;    // Hash of the parent directory (if matched via inode)
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

struct dedup_key {
    __u32 pid;
    __u32 file_hash;
};

struct inode_key {
    __u32 dev;
    __u32 pad; // Explicit padding to match Go struct and ensure 16-byte alignment
    __u64 ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct dedup_key));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1024);
} dedup_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct inode_key));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);
} monitored_inodes_map SEC(".maps");

#define AT_FDCWD -100

static inline int handle_event(struct sys_enter_args *ctx, int dfd, const char *filename_ptr, __u32 flags, __u32 type) {
    struct event e = {};
    long ret;
    
    // Read filename
    ret = bpf_probe_read_user_str(e.filename, sizeof(e.filename), (void *)filename_ptr);
    if (ret <= 0) return 0;

    // Calculate filename hash and check prefixes for directory monitoring
    __u32 hash = 5381;
    int matched = 0;
    
    #pragma unroll
    for (int i = 0; i < 256; i++) {
        unsigned char c = (unsigned char)e.filename[i];
        if (c == '\0') {
            // End of string. Check full hash.
            __u32 *match = bpf_map_lookup_elem(&target_hashes_map, &hash);
            if (match) matched = 1;
            break;
        }
        
        if (c == '/') {
            // Check if the prefix (directory) is monitored
            // Note: hash currently contains the hash of the string up to (but not including) this slash
            // e.g. for "/tmp/file", at first slash, hash is hash("").
            // at second slash, hash is hash("/tmp").
            
            // Special case for root directory "/"
            if (i == 0) {
                // For root, we need to include the slash in the hash check
                // But we haven't updated 'hash' with '/' yet.
                // Let's update it temporarily or just handle it.
                // Actually, standard DJB2: hash = ((hash << 5) + hash) + c;
                __u32 root_hash = ((hash << 5) + hash) + '/';
                __u32 *match = bpf_map_lookup_elem(&target_hashes_map, &root_hash);
                if (match) matched = 1;
            } else {
                // For other directories, we check the hash accumulated so far (without the trailing slash)
                // e.g. "/tmp"
                __u32 *match = bpf_map_lookup_elem(&target_hashes_map, &hash);
                if (match) matched = 1;
            }
        }
        
        hash = ((hash << 5) + hash) + c;
    }
    
    e.filename_hash = hash;

    // Check if the full filename is monitored (exact match)
    if (!matched) {
        __u32 *match = bpf_map_lookup_elem(&target_hashes_map, &hash);
        if (match) matched = 1;
    }

    // If not matched by path, check if we are in a monitored directory (CWD)
    // Only for relative paths and when using AT_FDCWD
    if (!matched && e.filename[0] != '/') {
        if (dfd == AT_FDCWD) {
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            // Walk task->fs->pwd.dentry->d_inode
            struct fs_struct *fs = BPF_CORE_READ(task, fs);
            if (fs) {
                struct path pwd = BPF_CORE_READ(fs, pwd);
                struct dentry *dentry = pwd.dentry;
                struct inode *inode = BPF_CORE_READ(dentry, d_inode);
                struct super_block *sb = BPF_CORE_READ(inode, i_sb);
                
                struct inode_key ikey = {};
                ikey.ino = BPF_CORE_READ(inode, i_ino);
                ikey.dev = BPF_CORE_READ(sb, s_dev);

                __u32 *match = bpf_map_lookup_elem(&monitored_inodes_map, &ikey);
                if (match) {
                    matched = 1;
                    e.parent_hash = *match; // Store the hash of the parent directory

                }
            }
        }
    }

    if (!matched) return 0;

    // Deduplication logic
    struct dedup_key dkey = {};
    dkey.pid = bpf_get_current_pid_tgid() >> 32;
    dkey.file_hash = e.filename_hash;
    
    __u64 ts = bpf_ktime_get_ns();
    __u64 *last_ts = bpf_map_lookup_elem(&dedup_map, &dkey);
    
    if (last_ts) {
        if (ts - *last_ts < 1000000000) { // 1 second threshold
            return 0;
        }
    }
    bpf_map_update_elem(&dedup_map, &dkey, &ts, BPF_ANY);

    // Get UID information
    __u64 uid_gid = bpf_get_current_uid_gid();
    e.uid = uid_gid;
    e.euid = (uid_gid >> 32);
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // Read loginuid from the task itself, not parent
    e.loginuid = BPF_CORE_READ(task, loginuid.val);

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

    bpf_printk("BPF DEBUG: Sending event pid=%d file=%s", e.pid, e.filename);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct sys_enter_args *ctx) {
    return handle_event(ctx, (int)ctx->args[0], (const char *)ctx->args[1], (__u32)ctx->args[2], 0);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct sys_enter_args *ctx) {
    // openat2(int dfd, const char *filename, struct open_how *how, size_t size)
    // args[0] = dfd, args[1] = filename
    return handle_event(ctx, (int)ctx->args[0], (const char *)ctx->args[1], 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct sys_enter_args *ctx) {
    return handle_event(ctx, (int)ctx->args[0], (const char *)ctx->args[1], (__u32)ctx->args[2], 1);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct sys_enter_args *ctx) {
    return handle_event(ctx, AT_FDCWD, (const char *)ctx->args[0], 0, 1);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";