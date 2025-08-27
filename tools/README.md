# Tools

These tools are a small collection curated by the bpftrace maintainers that have been battle-tested and are packaged with bpftrace. We're currently building a set of [community tools](https://github.com/bpftrace/user-tools), which is now accepting [contributions](https://github.com/bpftrace/user-tools/blob/master/CONTRIBUTING.md).

[Read more about how tools get added to THIS repository](../CONTRIBUTING-TOOLS.md).

### Versioned Tools

- [0.23 tools](https://github.com/bpftrace/bpftrace/tree/release/0.23.x/tools)
- [0.22 tools](https://github.com/bpftrace/bpftrace/tree/release/0.22.x/tools)
- [0.21 tools](https://github.com/bpftrace/bpftrace/tree/release/0.21.x/tools)
- [0.20 tools](https://github.com/bpftrace/bpftrace/tree/release/0.20.x/tools)

---

These tools may be updated to use features available in a yet-to-be-released version of bpftrace.
If they are not working on your version of bpftrace, use the links above to get a compatible version of the tool.

- tools/[bashreadline.bt](bashreadline.bt) - Print entered bash commands system wide.
- tools/[biolatency.bt](biolatency.bt) - Block I/O latency as a histogram.
- tools/[biosnoop.bt](biosnoop.bt) - Block I/O tracing tool, showing per I/O latency.
- tools/[biostacks.bt](biostacks.bt) - Show disk I/O latency with initialization stacks.
- tools/[bitesize.bt](bitesize.bt) - Show disk I/O size as a histogram.
- tools/[capable.bt](capable.bt) - Trace security capability checks.
- tools/[cpuwalk.bt](cpuwalk.bt) - Sample which CPUs are executing processes.
- tools/[dcsnoop.bt](dcsnoop.bt) - Trace directory entry cache (dcache) lookups.
- tools/[execsnoop.bt](execsnoop.bt) - Trace new processes via exec() syscalls.
- tools/[gethostlatency.bt](gethostlatency.bt) - Show latency for getaddrinfo/gethostbyname[2] calls.
- tools/[killsnoop.bt](killsnoop.bt) - Trace signals issued by the kill() syscall.
- tools/[loads.bt](loads.bt) - Print load averages.
- tools/[mdflush.bt](mdflush.bt) - Trace md flush events.
- tools/[naptime.bt](naptime.bt) - Show voluntary sleep calls.
- tools/[opensnoop.bt](opensnoop.bt) - Trace open() syscalls showing filenames.
- tools/[oomkill.bt](oomkill.bt) - Trace OOM killer.
- tools/[pidpersec.bt](pidpersec.bt) - Count new processes (via fork).
- tools/[runqlat.bt](runqlat.bt) - CPU scheduler run queue latency as a histogram.
- tools/[runqlen.bt](runqlen.bt) - CPU scheduler run queue length as a histogram.
- tools/[setuids.bt](setuids.bt) - Trace the setuid syscalls: privilege escalation.
- tools/[ssllatency.bt](ssllatency.bt) - Summarize SSL/TLS handshake latency as a histogram.
- tools/[sslsnoop.bt](sslsnoop.bt) - Trace SSL/TLS handshake, showing latency and return value.
- tools/[statsnoop.bt](statsnoop.bt) - Trace stat() syscalls for general debugging.
- tools/[swapin.bt](swapin.bt) - Show swapins by process.
- tools/[syncsnoop.bt](syncsnoop.bt) - Trace sync() variety of syscalls.
- tools/[syscount.bt](syscount.bt) - Count system calls.
- tools/[tcpaccept.bt](tcpaccept.bt) - Trace TCP passive connections (accept()).
- tools/[tcpconnect.bt](tcpconnect.bt) - Trace TCP active connections (connect()).
- tools/[tcpdrop.bt](tcpdrop.bt) - Trace kernel-based TCP packet drops with details.
- tools/[tcplife.bt](tcplife.bt) - Trace TCP session lifespans with connection details.
- tools/[tcpretrans.bt](tcpretrans.bt) - Trace TCP retransmits.
- tools/[tcpsynbl.bt](tcpsynbl.bt) - Show TCP SYN backlog as a histogram.
- tools/[threadsnoop.bt](threadsnoop.bt) - List new thread creation.
- tools/[undump.bt](undump.bt) - Capture UNIX domain socket packages.
- tools/[vfscount.bt](vfscount.bt) - Count VFS calls.
- tools/[vfsstat.bt](vfsstat.bt) - Count some VFS calls, with per-second summaries.
- tools/[writeback.bt](writeback.bt) - Trace file system writeback events with details.
- tools/[xfsdist.bt](xfsdist.bt) - Summarize XFS operation latency distribution as a histogram.

For more eBPF observability tools, see [bcc tools](https://github.com/iovisor/bcc#tools).
