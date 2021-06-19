# bpftrace

[![Build Status](https://github.com/iovisor/bpftrace/workflows/CI/badge.svg?branch=master)](https://github.com/iovisor/bpftrace/actions?query=workflow%3ACI+branch%3Amaster)
[![IRC#bpftrace](https://img.shields.io/badge/IRC-bpftrace-blue.svg)](https://webchat.oftc.net/?channels=bpftrace)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/iovisor/bpftrace.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/iovisor/bpftrace/alerts/)

bpftrace is a high-level tracing language for Linux enhanced Berkeley Packet Filter (eBPF) available in recent Linux kernels (4.x). bpftrace uses LLVM as a backend to compile scripts to BPF-bytecode and makes use of [BCC](https://github.com/iovisor/bcc) for interacting with the Linux BPF system, as well as existing Linux tracing capabilities: kernel dynamic tracing (kprobes), user-level dynamic tracing (uprobes), and tracepoints. The bpftrace language is inspired by awk and C, and predecessor tracers such as DTrace and SystemTap. bpftrace was created by [Alastair Robertson](https://github.com/ajor).

To learn more about bpftrace, see the [Reference Guide](docs/reference_guide.md) and [One-Liner Tutorial](docs/tutorial_one_liners.md).

## One-Liners

The following one-liners demonstrate different capabilities:

```
# Files opened by process
bpftrace -e 'tracepoint:syscalls:sys_enter_open { printf("%s %s\n", comm, str(args->filename)); }'

# Syscall count by program
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

# Read bytes by process:
bpftrace -e 'tracepoint:syscalls:sys_exit_read /args->ret/ { @[comm] = sum(args->ret); }'

# Read size distribution by process:
bpftrace -e 'tracepoint:syscalls:sys_exit_read { @[comm] = hist(args->ret); }'

# Show per-second syscall rates:
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @ = count(); } interval:s:1 { print(@); clear(@); }'

# Trace disk size by process
bpftrace -e 'tracepoint:block:block_rq_issue { printf("%d %s %d\n", pid, comm, args->bytes); }'

# Count page faults by process
bpftrace -e 'software:faults:1 { @[comm] = count(); }'

# Count LLC cache misses by process name and PID (uses PMCs):
bpftrace -e 'hardware:cache-misses:1000000 { @[comm, pid] = count(); }'

# Profile user-level stacks at 99 Hertz, for PID 189:
bpftrace -e 'profile:hz:99 /pid == 189/ { @[ustack] = count(); }'

# Files opened, for processes in the root cgroup-v2
bpftrace -e 'tracepoint:syscalls:sys_enter_openat /cgroup == cgroupid("/sys/fs/cgroup/unified/mycg")/ { printf("%s\n", str(args->filename)); }'
```

More powerful scripts can easily be constructed. See [Tools](tools) for examples.

## Install

For build and install instructions, see [INSTALL.md](INSTALL.md).

## Tools

bpftrace contains various tools, which also serve as examples of programming in the bpftrace language.

- tools/[bashreadline.bt](tools/bashreadline.bt): Print entered bash commands system wide. [Examples](tools/bashreadline_example.txt).
- tools/[biolatency.bt](tools/biolatency.bt): Block I/O latency as a histogram. [Examples](tools/biolatency_example.txt).
- tools/[biosnoop.bt](tools/biosnoop.bt): Block I/O tracing tool, showing per I/O latency. [Examples](tools/biosnoop_example.txt).
- tools/[biostacks.bt](tools/biostacks.bt): Show disk I/O latency with initialization stacks. [Examples](tools/biostacks_example.txt).
- tools/[bitesize.bt](tools/bitesize.bt): Show disk I/O size as a histogram. [Examples](tools/bitesize_example.txt).
- tools/[capable.bt](tools/capable.bt): Trace security capability checks. [Examples](tools/capable_example.txt).
- tools/[cpuwalk.bt](tools/cpuwalk.bt): Sample which CPUs are executing processes. [Examples](tools/cpuwalk_example.txt).
- tools/[dcsnoop.bt](tools/dcsnoop.bt): Trace directory entry cache (dcache) lookups. [Examples](tools/dcsnoop_example.txt).
- tools/[execsnoop.bt](tools/execsnoop.bt): Trace new processes via exec() syscalls. [Examples](tools/execsnoop_example.txt).
- tools/[gethostlatency.bt](tools/gethostlatency.bt): Show latency for getaddrinfo/gethostbyname[2] calls. [Examples](tools/gethostlatency_example.txt).
- tools/[killsnoop.bt](tools/killsnoop.bt): Trace signals issued by the kill() syscall. [Examples](tools/killsnoop_example.txt).
- tools/[loads.bt](tools/loads.bt): Print load averages. [Examples](tools/loads_example.txt).
- tools/[mdflush.bt](tools/mdflush.bt): Trace md flush events. [Examples](tools/mdflush_example.txt).
- tools/[naptime.bt](tools/naptime.bt): Show voluntary sleep calls. [Examples](tools/naptime_example.txt).
- tools/[opensnoop.bt](tools/opensnoop.bt): Trace open() syscalls showing filenames. [Examples](tools/opensnoop_example.txt).
- tools/[oomkill.bt](tools/oomkill.bt): Trace OOM killer. [Examples](tools/oomkill_example.txt).
- tools/[pidpersec.bt](tools/pidpersec.bt): Count new processes (via fork). [Examples](tools/pidpersec_example.txt).
- tools/[runqlat.bt](tools/runqlat.bt): CPU scheduler run queue latency as a histogram. [Examples](tools/runqlat_example.txt).
- tools/[runqlen.bt](tools/runqlen.bt): CPU scheduler run queue length as a histogram. [Examples](tools/runqlen_example.txt).
- tools/[setuids.bt](tools/setuids.bt): Trace the setuid syscalls: privilege escalation. [Examples](tools/setuids_example.txt).
- tools/[statsnoop.bt](tools/statsnoop.bt): Trace stat() syscalls for general debugging. [Examples](tools/statsnoop_example.txt).
- tools/[swapin.bt](tools/swapin.bt): Show swapins by process. [Examples](tools/swapin_example.txt).
- tools/[syncsnoop.bt](tools/syncsnoop.bt): Trace sync() variety of syscalls. [Examples](tools/syncsnoop_example.txt).
- tools/[syscount.bt](tools/syscount.bt): Count system calls. [Examples](tools/syscount_example.txt).
- tools/[tcpaccept.bt](tools/tcpaccept.bt): Trace TCP passive connections (accept()). [Examples](tools/tcpaccept_example.txt).
- tools/[tcpconnect.bt](tools/tcpconnect.bt): Trace TCP active connections (connect()). [Examples](tools/tcpconnect_example.txt).
- tools/[tcpdrop.bt](tools/tcpdrop.bt): Trace kernel-based TCP packet drops with details. [Examples](tools/tcpdrop_example.txt).
- tools/[tcplife.bt](tools/tcplife.bt): Trace TCP session lifespans with connection details. [Examples](tools/tcplife_example.txt).
- tools/[tcpretrans.bt](tools/tcpretrans.bt): Trace TCP retransmits. [Examples](tools/tcpretrans_example.txt).
- tools/[tcpsynbl.bt](tools/tcpsynbl.bt): Show TCP SYN backlog as a histogram. [Examples](tools/tcpsynbl_example.txt).
- tools/[threadsnoop.bt](tools/threadsnoop.bt): List new thread creation. [Examples](tools/threadsnoop_example.txt).
- tools/[vfscount.bt](tools/vfscount.bt): Count VFS calls. [Examples](tools/vfscount_example.txt).
- tools/[vfsstat.bt](tools/vfsstat.bt): Count some VFS calls, with per-second summaries. [Examples](tools/vfsstat_example.txt).
- tools/[writeback.bt](tools/writeback.bt): Trace file system writeback events with details. [Examples](tools/writeback_example.txt).
- tools/[xfsdist.bt](tools/xfsdist.bt): Summarize XFS operation latency distribution as a histogram. [Examples](tools/xfsdist_example.txt).

For more eBPF observability tools, see [bcc tools](https://github.com/iovisor/bcc#tools).

## Probe types
<center><a href="images/bpftrace_probes_2018.png"><img src="images/bpftrace_probes_2018.png" border=0 width=700></a></center>

See the [Reference Guide](docs/reference_guide.md) for more detail.

## Support

For additional help / discussion, please use our [discussions](https://github.com/iovisor/bpftrace/discussions) page.

## Contributing

* Have ideas for new bpftrace tools? [CONTRIBUTING-TOOLS.md](CONTRIBUTING-TOOLS.md)

* Bugs reports and feature requests: [Issue Tracker](https://github.com/iovisor/bpftrace/issues)

* bpftrace development IRC: #bpftrace at irc.oftc.net

## Development

For development and testing a [Vagrantfile](Vagrantfile) is available.

Make sure you have the `vbguest` plugin installed, it is required to correctly
install the shared file system driver on the ubuntu boxes:

```
$ vagrant plugin install vagrant-vbguest
```

Start VM:

```
$ vagrant status
$ vagrant up $YOUR_CHOICE
$ vagrant ssh $YOUR_CHOICE
```

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
