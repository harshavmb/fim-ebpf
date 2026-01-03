# FIM-eBPF: File Integrity Monitoring with eBPF

A lightweight eBPF program to monitor file creation and modification events on Linux. This tool leverages eBPF (Extended Berkeley Packet Filter) to trace file operations directly from the kernel, providing high-performance monitoring with minimal overhead.

## Features

- **Kernel-level Monitoring**: Traces file operations (`touch`, `nano`, etc.) directly from the kernel.
- **CO-RE Support**: Designed to work with Compile Once – Run Everywhere (CO-RE) on kernels that support it (Kernel 5.x+).
- **Configurable Filtering**: Filter events by file path, action, or user via a simple YAML configuration.
- **Directory Monitoring**: Supports monitoring entire directories recursively. Any file accessed within a monitored directory (e.g., `/tmp`) will be tracked.
- **Low Noise**: Filters events in the kernel before they reach userspace, reducing overhead.
- **Path Resolution**: Handles both absolute and relative paths (e.g., `cd /tmp; touch file`) correctly by tracking directory inodes in the kernel.

## Prerequisites

- **Linux Kernel 5.x or higher**: Required for CO-RE support (e.g., RHEL 9, Ubuntu 20.04+, etc.).
- **Root Privileges**: eBPF programs require root access to load into the kernel.

## Installation

You can download the latest binaries from the [Releases](https://github.com/harshavmb/fim-ebpf/releases) page.

### Building from Source

To build the project yourself, you need Go installed.

```bash
# Clone the repository
git clone https://github.com/harshavmb/fim-ebpf.git
cd fim-ebpf

# Build the binary
go build -o fim-ebpf .
```

## Usage

1.  Create a `config.yaml` file in the same directory as the binary (or modify the existing one).

    ```yaml
    monitored_files:
      - /tmp/testfile
      - /etc/passwd
      - /etc/shadow
      - /tmp ## monitor the entire directory
    ignore_actions:
      - read
      - stat
    ignore_users:
      - root
    ```

2.  Run the binary with root privileges:

    ```bash
    sudo ./fim-ebpf
    ```

### Example Output

```text
2025/08/18 07:22:09 Monitoring started. Ctrl+C to exit.
2025/08/18 07:22:37 Event: PID=1745080 UID=6087179 (6087179 (harsha)) CMD=touch FILE=/tmp/testfile FLAGS=00000941 ## actual user
2025/08/18 07:22:54 Event: PID=1745108 UID=0 (0 (root) [Login: 6087179 (harsha)]) CMD=touch FILE=/tmp/testfile FLAGS=00000941 ## even after sudo
2026/01/03 18:55:56 Event: PID=3718310 UID=1002 (1002 (harsha)) CMD=touch FILE=/tmp/testfile ACTION=OPEN FLAGS=00000941 ## monitoring files in a dir
```

## Architecture

The project uses [cilium/ebpf](https://github.com/cilium/ebpf) for loading and interacting with the eBPF program. The eBPF code runs in the kernel and sends events to the userspace Go program via a ring buffer.