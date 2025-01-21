# Tools

These tools are a small collection curated by the bpftrace maintainers that have been battle-tested and are packaged with bpftrace. We're currently building a set of [community tools](https://github.com/bpftrace/user-tools), which is now accepting [contributions](https://github.com/bpftrace/user-tools/blob/master/CONTRIBUTING.md).

[Read more about how tools get added to this repository](../CONTRIBUTING-TOOLS.md).

- tools/[bashreadline.bt](bashreadline.bt) - Print entered bash commands system wide. [Examples](bashreadline_example.txt).
- tools/[biolatency.bt](biolatency.bt) - Block I/O latency as a histogram. [Examples](biolatency_example.txt).
- tools/[biosnoop.bt](biosnoop.bt) - Block I/O tracing tool, showing per I/O latency. [Examples](biosnoop_example.txt).
- tools/[biostacks.bt](biostacks.bt) - Show disk I/O latency with initialization stacks. [Examples](biostacks_example.txt).
- tools/[bitesize.bt](bitesize.bt) - Show disk I/O size as a histogram. [Examples](bitesize_example.txt).
- tools/[capable.bt](capable.bt) - Trace security capability checks. [Examples](capable_example.txt).
- tools/[cpuwalk.bt](cpuwalk.bt) - Sample which CPUs are executing processes. [Examples](cpuwalk_example.txt).
- tools/[dcsnoop.bt](dcsnoop.bt) - Trace directory entry cache (dcache) lookups. [Examples](dcsnoop_example.txt).
- tools/[execsnoop.bt](execsnoop.bt) - Trace new processes via exec() syscalls. [Examples](execsnoop_example.txt).
- tools/[gethostlatency.bt](gethostlatency.bt) - Show latency for getaddrinfo/gethostbyname[2] calls. [Examples](gethostlatency_example.txt).
- tools/[killsnoop.bt](killsnoop.bt) - Trace signals issued by the kill() syscall. [Examples](killsnoop_example.txt).
- tools/[loads.bt](loads.bt) - Print load averages. [Examples](loads_example.txt).
- tools/[mdflush.bt](mdflush.bt) - Trace md flush events. [Examples](mdflush_example.txt).
- tools/[naptime.bt](naptime.bt) - Show voluntary sleep calls. [Examples](naptime_example.txt).
- tools/[opensnoop.bt](opensnoop.bt) - Trace open() syscalls showing filenames. [Examples](opensnoop_example.txt).
- tools/[oomkill.bt](oomkill.bt) - Trace OOM killer. [Examples](oomkill_example.txt).
- tools/[pidpersec.bt](pidpersec.bt) - Count new processes (via fork). [Examples](pidpersec_example.txt).
- tools/[runqlat.bt](runqlat.bt) - CPU scheduler run queue latency as a histogram. [Examples](runqlat_example.txt).
- tools/[runqlen.bt](runqlen.bt) - CPU scheduler run queue length as a histogram. [Examples](runqlen_example.txt).
- tools/[setuids.bt](setuids.bt) - Trace the setuid syscalls: privilege escalation. [Examples](setuids_example.txt).
- tools/[ssllatency.bt](ssllatency.bt) - Summarize SSL/TLS handshake latency as a histogram. [Examples](ssllatency_example.txt)
- tools/[sslsnoop.bt](sslsnoop.bt) - Trace SSL/TLS handshake, showing latency and return value. [Examples](sslsnoop_example.txt)
- tools/[statsnoop.bt](statsnoop.bt) - Trace stat() syscalls for general debugging. [Examples](statsnoop_example.txt).
- tools/[swapin.bt](swapin.bt) - Show swapins by process. [Examples](swapin_example.txt).
- tools/[syncsnoop.bt](syncsnoop.bt) - Trace sync() variety of syscalls. [Examples](syncsnoop_example.txt).
- tools/[syscount.bt](syscount.bt) - Count system calls. [Examples](syscount_example.txt).
- tools/[tcpaccept.bt](tcpaccept.bt) - Trace TCP passive connections (accept()). [Examples](tcpaccept_example.txt).
- tools/[tcpconnect.bt](tcpconnect.bt) - Trace TCP active connections (connect()). [Examples](tcpconnect_example.txt).
- tools/[tcpdrop.bt](tcpdrop.bt) - Trace kernel-based TCP packet drops with details. [Examples](tcpdrop_example.txt).
- tools/[tcplife.bt](tcplife.bt) - Trace TCP session lifespans with connection details. [Examples](tcplife_example.txt).
- tools/[tcpretrans.bt](tcpretrans.bt) - Trace TCP retransmits. [Examples](tcpretrans_example.txt).
- tools/[tcpsynbl.bt](tcpsynbl.bt) - Show TCP SYN backlog as a histogram. [Examples](tcpsynbl_example.txt).
- tools/[threadsnoop.bt](threadsnoop.bt) - List new thread creation. [Examples](threadsnoop_example.txt).
- tools/[undump.bt](undump.bt) - Capture UNIX domain socket packages. [Examples](undump_example.txt).
- tools/[vfscount.bt](vfscount.bt) - Count VFS calls. [Examples](vfscount_example.txt).
- tools/[vfsstat.bt](vfsstat.bt) - Count some VFS calls, with per-second summaries. [Examples](vfsstat_example.txt).
- tools/[writeback.bt](writeback.bt) - Trace file system writeback events with details. [Examples](writeback_example.txt).
- tools/[xfsdist.bt](xfsdist.bt) - Summarize XFS operation latency distribution as a histogram. [Examples](xfsdist_example.txt).

For more eBPF observability tools, see [bcc tools](https://github.com/iovisor/bcc#tools).
