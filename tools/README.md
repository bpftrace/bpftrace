# Tools

These tools are a small collection curated by the bpftrace maintainers that have been battle-tested and are packaged with bpftrace. We're currently building a set of [community tools](https://github.com/bpftrace/user-tools), which is now accepting [contributions](https://github.com/bpftrace/user-tools/blob/master/CONTRIBUTING.md).

[Read more about how tools get added to this repository](../CONTRIBUTING-TOOLS.md).

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
- tools/[ssllatency.bt](tools/ssllatency.bt): Summarize SSL/TLS handshake latency as a histogram. [Examples](tools/ssllatency_example.txt)
- tools/[sslsnoop.bt](tools/sslsnoop.bt): Trace SSL/TLS handshake, showing latency and return value. [Examples](tools/sslsnoop_example.txt)
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
- tools/[undump.bt](tools/undump.bt): Capture UNIX domain socket packages. [Examples](tools/undump_example.txt).
- tools/[vfscount.bt](tools/vfscount.bt): Count VFS calls. [Examples](tools/vfscount_example.txt).
- tools/[vfsstat.bt](tools/vfsstat.bt): Count some VFS calls, with per-second summaries. [Examples](tools/vfsstat_example.txt).
- tools/[writeback.bt](tools/writeback.bt): Trace file system writeback events with details. [Examples](tools/writeback_example.txt).
- tools/[xfsdist.bt](tools/xfsdist.bt): Summarize XFS operation latency distribution as a histogram. [Examples](tools/xfsdist_example.txt).

For more eBPF observability tools, see [bcc tools](https://github.com/iovisor/bcc#tools).