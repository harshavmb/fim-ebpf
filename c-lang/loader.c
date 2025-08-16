#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <string.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct bpf_map *target_map;
    int err;
    const char *target_filename = "/tmp/testfile";
    int key = 0;
    char value[256] = {0};
    
    strncpy(value, target_filename, sizeof(value) - 1);
    
    obj = bpf_object__open_file("tracepoint.o", NULL);
    if (!obj) {
        fprintf(stderr, "Error opening BPF object\n");
        return 1;
    }
    
    // Clean up any existing maps first
    bpf_object__unpin_maps(obj, "/sys/fs/bpf");
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object\n");
        return 1;
    }
    
    target_map = bpf_object__find_map_by_name(obj, "target_filename_map");
    if (!target_map) {
        fprintf(stderr, "Error finding target_filename_map\n");
        bpf_object__close(obj);
        return 1;
    }
    
    err = bpf_map__update_elem(target_map, &key, sizeof(key), value, sizeof(value), BPF_ANY);
    if (err) {
        fprintf(stderr, "Error populating target_filename_map\n");
        bpf_object__close(obj);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "trace_openat");
    if (!prog) {
        fprintf(stderr, "Error finding BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Error attaching BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    err = bpf_object__pin_maps(obj, "/sys/fs/bpf");
    if (err) {
        fprintf(stderr, "Error pinning BPF maps\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }
    
    printf("BPF program loaded and maps pinned. Press Ctrl+C to exit.\n");
    
    pause(); 
    
    bpf_object__unpin_maps(obj, "/sys/fs/bpf");
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}