<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="images/bpftrace_Full_Logo-White.svg"/>
    <img alt="bpftrace" src="images/bpftrace_Full_Logo-Black.svg" width="60%"/>
  </picture>
</p>

[![Build Status](https://github.com/bpftrace/bpftrace/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/bpftrace/bpftrace/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/bpftrace/bpftrace)](https://github.com/bpftrace/bpftrace/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/bpftrace/bpftrace/blob/master/LICENSE)

bpftrace is a high-level tracing language for Linux. It leverages [eBPF](https://ebpf.io/what-is-ebpf/) to provide powerful, efficient tracing capabilities with minimal overhead.
bpftrace uses LLVM as a backend to compile scripts to eBPF-bytecode and makes use of [libbpf](https://github.com/libbpf/libbpf) for interacting with the Linux BPF subsystem, including [kernel dynamic tracing (kprobes)](https://bpftrace.org/docs#kprobes--kretprobes), [user-level dynamic tracing (uprobes)](https://bpftrace.org/docs#uprobes--uretprobes), [tracepoints](https://bpftrace.org/docs#tracepoints), and more.
The bpftrace language is inspired by awk, C, and predecessor tracers such as DTrace and SystemTap.

## Quick Start

Get started with bpftrace in just a few minutes! You can usually install it using your distribution's [package manager](https://pkgs.org/search/?q=bpftrace).

> [!WARNING]
> When using a distribution package, be sure to verify `bpftrace --version` when referencing documentation.

| Distribution | Command |
|--------------|---------|
| [Ubuntu](https://packages.ubuntu.com/search?keywords=bpftrace) | `sudo apt-get install bpftrace` |
| [Fedora](https://packages.fedoraproject.org/pkgs/bpftrace/bpftrace/) | `sudo dnf install bpftrace` |
| [Debian](https://tracker.debian.org/pkg/bpftrace) | `sudo apt-get install bpftrace` |
| [Arch Linux](https://archlinux.org/packages/extra/x86_64/bpftrace/) | `sudo pacman -S bpftrace` |
| [Alpine](https://pkgs.alpinelinux.org/packages?name=bpftrace) | `sudo apk add bpftrace` |
| [openSUSE](https://software.opensuse.org/package/bpftrace) | `sudo zypper install bpftrace` |
| [Gentoo](https://packages.gentoo.org/packages/dev-util/bpftrace) | `sudo emerge bpftrace` |
| [AppImage (latest release)](https://github.com/bpftrace/bpftrace/releases/latest)| Download, unzip and run |
| [AppImage (nightly)](https://github.com/bpftrace/bpftrace/actions/workflows/binary.yml?query=branch%3Amaster) | Download for [X86_64](https://nightly.link/bpftrace/bpftrace/workflows/binary/master/bpftrace-X64.zip) or [AMD64](https://nightly.link/bpftrace/bpftrace/workflows/binary/master/bpftrace-ARM64.zip) |

For building from source, see the [Installation](#installation) section below.

### Examples

bpftrace supports multiple probe types for comprehensive observability.

<p align="center">
  <picture>
    <img alt="bpftrace" src="images/bpftrace_probes_2018.png" border=0 width=700/>
  </picture>
</p>

| Description | Command |
|-------------|---------|
| Files opened | `bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args.filename)); }'` |
| Syscall counts | `bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'` |
| Read bytes | `bpftrace -e 'tracepoint:syscalls:sys_exit_read /args.ret/ { @[comm] = sum(args.ret); }'` |
| Read size distribution | `bpftrace -e 'tracepoint:syscalls:sys_exit_read { @[comm] = hist(args.ret); }'` |
| Disk I/O size | `bpftrace -e 'tracepoint:block:block_rq_issue { printf("%d %s %d\n", pid, comm, args.bytes); }'` |
| Process sleeps | `bpftrace -e 'kprobe:do_nanosleep { printf("sleep by %s\n", comm); }'` |
| Read sizes by process | `bpftrace -e 'kretprobe:vfs_read { @bytes = hist(retval); }'` |
| Context switches | `bpftrace -e 'rawtracepoint:sched_switch { printf("%d -> %d\n", args->prev_pid, args->next_pid); }'` |
| TCP data attempted | `bpftrace -e 'fentry:tcp_sendmsg { @bytes = hist(args.size); }'` |
| TCP data sent | `bpftrace -e 'fexit:tcp_sendmsg { @bytes = hist(retval); }'` |
| Shell reading input | `bpftrace -e 'uprobe:/bin/bash:readline { printf("readline called by %d\n", pid); }'` |
| Shell commands read | `bpftrace -e 'uretprobe:/bin/bash:readline { printf("read: %s\n", str(retval)); }'` |
| MySQL queries started | `bpftrace -e 'usdt:/usr/sbin/mysqld:mysql:query__start { printf("%s\n", str(arg0)); }'` |
| Count page faults | `bpftrace -e 'software:faults:1 { @[pid] = count(); }'` |
| Sample CPU migrations | `bpftrace -e 'software:cpu-migrations:1 { @[pid] = count(); }'` |
| Sample cache misses | `bpftrace -e 'hardware:cache-misses:1000000 { @[comm, pid] = count(); }'` |
| Count CPU cycles | `bpftrace -e 'hardware:cpu-cycles:1000000 { @[comm] = count(); }'` |
| Sample user stacks | `bpftrace -e 'profile:hz:99 /pid == 189/ { @[ustack] = count(); }'` |
| Sample kernel stacks | `bpftrace -e 'profile:hz:99 { @[kstack] = count(); }'` |
| Syscall rates | `bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @ = count(); } interval:s:1 { print(@); clear(@); }` |
| Watch an address | `bpftrace -e 'watchpoint:0x12345678:8:w { printf("write at %p by %s\n", arg0, comm); }'` |

## Documentation

**Visit [bpftrace.org](https://bpftrace.org/)** for comprehensive documentation, tutorials, and examples!

If you've installed a distribution package, you should also be able to use `man bpftrace` to view the manual page for the command line tool.

- 🚀 [Tutorial & One-Liners](https://bpftrace.org/tutorial-one-liners) - Start here! Learn through examples
- 🤓 [Hands-on Lab](https://bpftrace.org/hol/intro) - Self-directed exercises
- 📖 [Reference Guide](https://bpftrace.org/docs) - Complete language documentation
- 🎓 [Video Resources](https://bpftrace.org/videos) - Talks and presentations
- 🛠️ [Example Tools](tools/README.md) - Scripts for common tasks
- 🦆 [Migration Guide](docs/migration_guide.md) - Upgrading from older versions

## Contributing

See our [Contributing Guide](CONTRIBUTING.md) for details on how to contribute, and our [Governance](GOVERNANCE.md) document for details on how the project is run.

If you have tools that you'd like to submit, please contribute to the [user-tools repository](https://github.com/bpftrace/user-tools/blob/master/CONTRIBUTING.md).

## Installation

For minimum kernel version requirements, see our [dependency support policy](docs/dependency_support.md#linux-kernel). Your kernel should be built with the necessary BPF options enabled. Verify this by running the `check_kernel_features` script from the `scripts` directory.

bpftrace also uses [git submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules), so ensure they are initialized when checking out the code. See [dependency support](docs/dependency_support.md) for details.

```bash
git clone --recurse-submodules https://github.com/bpftrace/bpftrace
cd bpftrace
```

Optionally, bpftrace provides a [Nix](https://nixos.org/nix/) [flake](https://wiki.nixos.org/wiki/Flakes), which is recommended for building and testing.

```
nix develop
```

For a suitable build environment without Nix, see our regularly exercised Dockerfiles for detailed build examples:
- [Ubuntu](https://github.com/bpftrace/bpftrace/blob/master/docker/Dockerfile.ubuntu)
- [Fedora](https://github.com/bpftrace/bpftrace/blob/master/docker/Dockerfile.fedora)
- [Debian](https://github.com/bpftrace/bpftrace/blob/master/docker/Dockerfile.debian)

If all dependencies are installed correctly, you should be able to configure and build using [CMake](https://cmake.org).

```bash
cmake -DCMAKE_BUILD_TYPE=Release -B build .
make -C build -j$(nproc)
```

<details>
<summary>Troubleshooting</summary>

**Kernel Lockdown:** If your system has kernel lockdown enabled (often with Secure Boot), bpftrace will be blocked. To disable:
- Disable Secure Boot in UEFI, or
- Run `sudo mokutil --disable-validation` and reboot, or
- Temporarily lift lockdown with `SysRQ+x` (until next boot)
</details>

## Community & Support

bpftrace is built and maintained by a diverse community of contributors, users, and organizations who rely on it for production tracing and debugging.

**Get help:**
- 💬 [GitHub Discussions](https://github.com/bpftrace/bpftrace/discussions) - Ask questions and share knowledge
- 🐛 [Issue Tracker](https://github.com/bpftrace/bpftrace/issues) - Report bugs and request features
- 📅 [Monthly Office Hours](https://docs.google.com/document/d/1nt010RfL4s4gydhCPSJ-Z5mnFMFuD4NrcpVmUcyvu2E/edit?usp=sharing) - Open to everyone
