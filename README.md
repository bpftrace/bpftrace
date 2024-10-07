# bpftrace

[![Build Status](https://github.com/bpftrace/bpftrace/workflows/CI/badge.svg?branch=master)](https://github.com/bpftrace/bpftrace/actions?query=workflow%3ACI+branch%3Amaster)
[![IRC#bpftrace](https://img.shields.io/badge/IRC-bpftrace-blue.svg)](https://webchat.oftc.net/?channels=bpftrace)
[![CodeQL](https://github.com/bpftrace/bpftrace/actions/workflows/codeql.yml/badge.svg)](https://github.com/bpftrace/bpftrace/actions/workflows/codeql.yml)

bpftrace is a high-level tracing language for Linux. bpftrace uses LLVM as a backend to compile scripts to [eBPF](https://ebpf.io/what-is-ebpf/)-bytecode and makes use of [libbpf](https://github.com/libbpf/libbpf) and [bcc](https://github.com/iovisor/bcc) for interacting with the Linux BPF subsystem, as well as existing Linux tracing capabilities: kernel dynamic tracing (kprobes), user-level dynamic tracing (uprobes), tracepoints, etc. The bpftrace language is inspired by awk, C, and predecessor tracers such as DTrace and SystemTap. bpftrace was created by [Alastair Robertson](https://github.com/ajor).

- [How to Install and Build](INSTALL.md)
- [Manual / Reference Guide](man/adoc/bpftrace.adoc)
- [Tutorial](docs/tutorial_one_liners.md)
- [Example One-Liners](#example-one-liners)
- [Videos](#videos)
- [Tools](tools/README.md)
- [Contribute](#contribute)
- [Development](#development)
- [Support](#support)
- [Migration guide](docs/migration_guide.md)
- [Probe types](#probe-types)
- [Plugins](#plugins)
- [License](#license)

## Example One-Liners

The following one-liners demonstrate different capabilities:

```
# Files opened by thread name
bpftrace -e 'tracepoint:syscalls:sys_enter_open { printf("%s %s\n", comm, str(args->filename)); }'

# Syscall count by thread name
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

# Read bytes by thread name:
bpftrace -e 'tracepoint:syscalls:sys_exit_read /args->ret/ { @[comm] = sum(args->ret); }'

# Read size distribution by thread name:
bpftrace -e 'tracepoint:syscalls:sys_exit_read { @[comm] = hist(args->ret); }'

# Show per-second syscall rates:
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @ = count(); } interval:s:1 { print(@); clear(@); }'

# Trace disk size by PID and thread name
bpftrace -e 'tracepoint:block:block_rq_issue { printf("%d %s %d\n", pid, comm, args->bytes); }'

# Count page faults by thread name
bpftrace -e 'software:faults:1 { @[comm] = count(); }'

# Count LLC cache misses by thread name and PID (uses PMCs):
bpftrace -e 'hardware:cache-misses:1000000 { @[comm, pid] = count(); }'

# Profile user-level stacks at 99 Hertz for PID 189:
bpftrace -e 'profile:hz:99 /pid == 189/ { @[ustack] = count(); }'

# Files opened in the root cgroup-v2
bpftrace -e 'tracepoint:syscalls:sys_enter_openat /cgroup == cgroupid("/sys/fs/cgroup/unified/mycg")/ { printf("%s\n", str(args->filename)); }'
```

More powerful scripts can easily be constructed. See [Tools](tools/README.md) for examples.

## Videos

Note: some of the content in these videos may be out of date, the current [reference guide](man/adoc/bpftrace.adoc) is the source of truth.

- [Making bpftrace more powerful - 2023](https://www.youtube.com/watch?v=19RZ7b6AZJ0)
- [Bpftrace Recipes: 5 Real Problems Solved - 2023](https://www.youtube.com/watch?v=wMtArNjRYXU)
- [Linux tracing made simpler with bpftrace - 2022](https://www.youtube.com/watch?v=gSxntAO2Iys)
- [Ahead-of-time compiled bpftrace programs - 2021](https://www.youtube.com/watch?v=C2n2i__YCcI)
- [Getting Started with BPF observability - 2021](https://www.youtube.com/watch?v=bGAVrtb_tFs)
- [bpftrace internals - 2020](https://www.youtube.com/watch?v=nDY4iC_ekQY&t=1477s)
- [Using bpftrace with Performance Co-Pilot & Grafana - 2020](https://www.youtube.com/watch?v=ZiGTbItyJyg)
- [An introduction to bpftrace tracing language - 2020](https://www.youtube.com/watch?v=93aHXYqZmU0)

## Contribute

Contributions are welcome! Please see the [development section](#development) below for more information. For new bpftrace tools, please add them to the new [user-tools repository](https://github.com/bpftrace/user-tools/blob/master/CONTRIBUTING.md). The tools that exist in this repository are a small collection curated by the bpftrace maintainers.

* Bug reports and feature requests: [Issue Tracker](https://github.com/bpftrace/bpftrace/issues)

* Development IRC: #bpftrace at irc.oftc.net

* [Good first issues](https://github.com/bpftrace/bpftrace/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)

## Development

* [Coding Guidelines](docs/coding_guidelines.md)
* [Development Guide](docs/developers.md)
* [Development Roadmap](https://docs.google.com/document/d/17729Rlyo1xzlJObzHpFLDzeCVgvwRh0ktAmMEJLK-EU/edit)
* [Fuzzing](docs/fuzzing.md)
* [Nix](docs/nix.md)
* [Release Process](docs/release_process.md)
* [Tests](tests/README.md)

## Support

For additional help / discussion, please use our [discussions](https://github.com/bpftrace/bpftrace/discussions) page.

We are also holding regular [office hours](https://docs.google.com/document/d/1nt010RfL4s4gydhCPSJ-Z5mnFMFuD4NrcpVmUcyvu2E/edit?usp=sharing) open to the public.

## Probe types
<center><a href="images/bpftrace_probes_2018.png"><img src="images/bpftrace_probes_2018.png" border=0 width=700></a></center>

See the [Manual](man/adoc/bpftrace.adoc) for more details.

## Plugins

bpftrace has several plugins/definitions, integrating the syntax into your editor.
<!--- Feel free to add your own plugins below, in alphabetical order -->

- [Emacs](https://gitlab.com/jgkamat/bpftrace-mode)
- [Vim](https://github.com/mmarchini/bpftrace.vim)
- [VS Code](https://github.com/bolinfest/bpftrace-vscode)

## License

Copyright 2019 Alastair Robertson

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
