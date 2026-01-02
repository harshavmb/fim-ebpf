# FIM-eBPF: File Integrity Monitoring with eBPF

A lightweight eBPF program to monitor file creation and modification events on Linux. This tool leverages eBPF (Extended Berkeley Packet Filter) to trace file operations directly from the kernel, providing high-performance monitoring with minimal overhead.

## Features

- **Kernel-level Monitoring**: Traces file operations (`touch`, `nano`, etc.) directly from the kernel.
- **CO-RE Support**: Designed to work with Compile Once – Run Everywhere (CO-RE) on kernels that support it (Kernel 5.x+).
- **Configurable Filtering**: Filter events by file path, action, or user via a simple YAML configuration.
- **Low Noise**: Filters events in the kernel before they reach userspace, reducing overhead.

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
2025/08/18 07:22:09 Warning: user backupuser not found
2025/08/18 07:22:09 Warning: user harsha not found
2025/08/18 07:22:09 Monitoring started. Ctrl+C to exit.
2025/08/18 07:22:37 Event: PID=1745080 UID=6087179 (6087179 (harsha)) CMD=touch FILE=/tmp/testfile FLAGS=00000941 ## actual user
2025/08/18 07:22:54 Event: PID=1745108 UID=0 (0 (root) [Login: 6087179 (harsha)]) CMD=touch FILE=/tmp/testfile FLAGS=00000941 ## even after sudo
```

## Architecture

The project uses [cilium/ebpf](https://github.com/cilium/ebpf) for loading and interacting with the eBPF program. The eBPF code runs in the kernel and sends events to the userspace Go program via a ring buffer.
