# BPFtrace

BPFtrace is a [DTrace](http://dtrace.org)-style dynamic tracing tool for linux, based on the extended BPF capabilities available in recent Linux kernels. BPFtrace uses [LLVM](http://llvm.org) as a backend to compile scripts to BPF-bytecode and makes use of [BCC](https://github.com/iovisor/bcc) for interacting with the Linux BPF system.

For instructions on building BPFtrace, see [INSTALL.md](INSTALL.md)

## Examples

Produce a histogram of amount of time (in nanoseconds) spent in the `read()` system call:
```
kprobe:sys_read
{
  @start[tid] = nsecs;
}

kretprobe:sys_read / @start[tid] /
{
  @times = quantize(nsecs - @start[tid]);
  @start[tid] = delete();
}
```
```
Running... press Ctrl-C to stop
^C

@start[9134]: 6465933686812

@times:
[0, 1]                 0 |                                                    |
[2, 4)                 0 |                                                    |
[4, 8)                 0 |                                                    |
[8, 16)                0 |                                                    |
[16, 32)               0 |                                                    |
[32, 64)               0 |                                                    |
[64, 128)              0 |                                                    |
[128, 256)             0 |                                                    |
[256, 512)           326 |@                                                   |
[512, 1k)           7715 |@@@@@@@@@@@@@@@@@@@@@@@@@@                          |
[1k, 2k)           15306 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[2k, 4k)             609 |@@                                                  |
[4k, 8k)             611 |@@                                                  |
[8k, 16k)            438 |@                                                   |
[16k, 32k)            59 |                                                    |
[32k, 64k)            36 |                                                    |
[64k, 128k)            5 |                                                    |
```

Record the names of files that any bash process opens:
```
kprobe:sys_open / comm == "bash" /
{
  @[str(arg0)] = count()
}
```
```
Running... press Ctrl-C to stop
^C

@[/usr/lib/libnsl.so.1]: 1
@[/etc/passwd]: 1
@[/usr/lib/libnss_nis.so.2]: 1
@[/usr/lib/libreadline.so.7]: 1
@[/dev/tty]: 1
@[/usr/lib/libncursesw.so.6]: 1
@[/etc/ld.so.cache]: 3
...
```

Record where malloc is called from for a particular process ID (userland stack tracing will try to resolve symbols in the future):
```
uprobe:/lib/libc-2.25.so:malloc / pid == 15201 /
{
  @[ustack] = count()
}
```
```
Running... press Ctrl-C to stop
^C

@[
0x7fe223fdff40
0x40058a
0x7fe223f8343a
0x82e258d4c544155
]: 271276
@[
0x7fe223fdff40
0x40058f
0x7fe223f8343a
0x82e258d4c544155
]: 135637
```

## Probe types

### kprobes
Attach a BPFtrace script to a kernel function, to be executed when that function is called:

`kprobe:sys_read { ... }`

### uprobes
Attach script to a userland function:

`uprobe:/bin/bash:readline { ... }`

### tracepoints
Attach script to a statically defined tracepoint in the kernel:

`tracepoint:sched:sched_switch { ... }`

Tracepoints are guaranteed to be stable between kernel versions, unlike kprobes.

### Multiple attachment points
More than one function/tracepoint can be specified for a single probe:

`kprobe:sys_read,kprobe:sys_write { ... }`

### Wildcards
Some probe types allow wildcards to be used when attaching a probe:

`kprobe:SyS_* { ... }`

## Builtins
The following variables and functions are available for use in bpftrace scripts:

Variables:
- `pid` - Process ID (kernel tgid)
- `tid` - Thread ID (kernel pid)
- `uid` - User ID
- `gid` - Group ID
- `nsecs` - Nanosecond timestamp
- `cpu` - Processor ID
- `comm` - Process name
- `stack` - Kernel stack trace
- `ustack` - User stack trace
- `arg0`, `arg1`, ... etc. - Arguments to the function being traced
- `retval` - Return value from function being traced
- `func` - Name of the function currently being traced

Functions:
- `quantize(int n)` - produce a log2 histogram of values of `n`
- `count()` - count the number of times this function is called
- `delete()` - delete the map element this is assigned to
- `str(char *s)` - returns the string pointed to by `s`
- `printf(char *fmt, ...)` - write to stdout
