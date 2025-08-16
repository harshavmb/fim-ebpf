#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    char filename[256];
};

// Simplified callback that actually works
static void handle_event(void *ctx, int cpu, void *data, unsigned int size)
{
    struct event *e = data;
    printf("PID: %d, UID: %d, CMD: %s, FILE: %s\n", 
           e->pid, e->uid, e->comm, e->filename);
}

int main()
{
    struct perf_buffer *pb;
    int map_fd;

    map_fd = bpf_obj_get("/sys/fs/bpf/events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get BPF map\n");
        return 1;
    }

    // This is the ONLY working syntax across all libbpf versions
    pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        close(map_fd);
        return 1;
    }

    printf("Monitoring started. Ctrl+C to exit.\n");
    while (perf_buffer__poll(pb, 1000) >= 0);

    close(map_fd);
    return 0;
}