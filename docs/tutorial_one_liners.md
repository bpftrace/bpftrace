# The bpftrace One-Liner Tutorial

This teaches you bpftrace for Linux in 12 easy lessons, where each lesson is a one-liner you can try running. This series of one-liners introduces concepts which are summarized as bullet points. For a full reference to bpftrace, see the [Reference Guide](reference_guide.md)

Contributed by Brendan Gregg, Netflix (2018), based on his FreeBSD [DTrace Tutorial](https://wiki.freebsd.org/DTrace/Tutorial).

# Lesson 1. Listing Probes

```
bpftrace -l 'tracepoint:syscalls:sys_enter_*'
```

"bpftrace -l" lists all probes, and a search term can be added.

- A probe is an instrumentation point for capturing event data.
- The supplied search term will do partial matches, and wildcards (file globbing) can be used.
- "bpftrace -l" can also be piped to grep(1) for full regular expression searching.

# Lesson 2. Hello World

```
# bpftrace -e 'BEGIN { printf("hello world\n"); }'
Attaching 1 probe...
hello world
^C
```

This prints a welcome message. Run it, then hit Ctrl-C to end.

- The word `BEGIN` is a special probe that fires at the start of the program (like awk's BEGIN). You can use it to set variables and print headers.
- An action can be associated with probes, in { }. This example calls printf() when the probe fires.

# Lesson 3. File Opens

```
# bpftrace -e 'tracepoint:syscalls:sys_enter_open { printf("%s %s\n", comm, str(args->filename)); }'
Attaching 1 probe...
snmp-pass /proc/cpuinfo
snmp-pass /proc/stat
snmpd /proc/net/dev
snmpd /proc/net/if_inet6
^C
```

This traces file opens as they happen, and we're printing the process name and pathname.

- It begins with the probe `tracepoint:syscalls:sys_enter_open`: this is the tracepoint probe type (kernel static tracing), and is instrumenting when the open() syscall begins (is entered). Tracepoints are preferred over kprobes (kernel dynamic tracing, introduced in lesson 6), since tracepoints have stable API.
- `comm` is a builtin variable that has the current process's name. Other similar builtins include pid and tid.
- `arg0` is a builtin variable containing the first probe argument, the meaning of which is defined by the probe type. For `kprobe`, it is the first argument to the function. Other arguments can be accessed as arg1, ..., argN. The sys_open() arguments are: const char *pathname, int flags, mode_t mode (see the open(2) man page). So, arg0 is the pathname pointer.
- `str()` turns a pointer into the string it points to.

# Lesson 4. Syscall Counts By Process

```
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
Attaching 1 probe...
^C

@[bpftrace]: 6
@[systemd]: 24
@[snmp-pass]: 96
@[sshd]: 125
```

This summarizes syscalls by process name, printing a report on Ctrl-C.

- @: This denotes a special variable type called a map, which can store and summarize data in different ways. You can add an optional variable name after the @, eg "@num", either to improve readability, or to differentiate between more than one map.
- []: The optional brackets allow a key to be set for the map, much like an associative array.
- count(): This is a map function – the way it is populated. count() counts the number of times it is called. Since this is saved by comm, the result is a frequency count of system calls by process name.

Maps are automatically printed when bpftrace ends (eg, via Ctrl-C).

# Lesson 5. Distribution of read() Bytes

```
# bpftrace -e 'tracepoint:syscalls:sys_exit_read /pid == 18644/ { @bytes = hist(args->ret); }'
Attaching 1 probe...
^C

@bytes:
[0, 1]                12 |@@@@@@@@@@@@@@@@@@@@                                |
[2, 4)                18 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     |
[4, 8)                 0 |                                                    |
[8, 16)                0 |                                                    |
[16, 32)               0 |                                                    |
[32, 64)              30 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[64, 128)             19 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                    |
[128, 256)             1 |@
```

This summarizes the return value of the sys_read() kernel function for PID 18644, printing it as a histogram.

- /.../: This is a filter (aka predicate), which acts as a filter for the action. The action is only executed if the filtered expression is true, in this case, only for the process ID 18644. Boolean operators are supported ("&&", "||").
- retval: This is the return value of the function. For sys_read(), this is either -1 (error) or the number of bytes successfully read.
- @: This is a map similar to the previous lesson, but without any keys ([]) this time, and the name "bytes" which decorates the output.
- hist(): This is a map function which summarizes the argument as a power-of-2 histogram. The output shows rows that begin with interval notation, where, for example `[128, 256)` means that the value is: 128 <= value < 256. The next number is the count of occurrences, and then an ASCII histogram is printed to visualize that count. The histogram can be used to study multi-modal distributions.
- Other map functions include lhist() (linear hist), count(), sum(), avg(), min(), and max().

# Lesson 6. Kernel Dynamic Tracing of read() Bytes

```
# bpftrace -e 'kretprobe:vfs_read { @bytes = lhist(retval, 0, 2000, 200); }'
Attaching 1 probe...
^C

@bytes:
(...,0]                0 |                                                    |
[0, 200)              66 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[200, 400)             2 |@                                                   |
[400, 600)             3 |@@                                                  |
[600, 800)             0 |                                                    |
[800, 1000)            5 |@@@                                                 |
[1000, 1200)           0 |                                                    |
[1200, 1400)           0 |                                                    |
[1400, 1600)           0 |                                                    |
[1600, 1800)           0 |                                                    |
[1800, 2000)           0 |                                                    |
[2000,...)            39 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                      |
```

Summarize read() bytes as a linear histogram, and traced using kernel dynamic tracing.

- It begins with the probe `kretprobe:vfs_read`: this is the kretprobe probe type (kernel dynamic tracing of function returns) instrumenting the `vfs_read()` kernel function. There is also the kprobe probe type (shown in the next lesson), to instrument when functions begin execution (are entered). These are powerful probe types, letting you trace tens of thousands of different kernel functions. However, these are "unstable" probe types: since they can trace any kernel function, there is no guarantee that your kprobe/kretprobe will work between kernel versions, as the function names, arguments, return values, and roles may change. Also, since it is tracing the raw kernel, you'll need to browse the kernel source to understand what these probes, arguments, and return values, mean.
- lhist(): this is a linear histogram, where the arguments are: value, min, max, step. The first argument (`retval`) of vfs_read() is the return value: the number of bytes read.

# Lesson 7. Timing read()s

```
# bpftrace -e 'kprobe:vfs_read { @start[tid] = nsecs; } kretprobe:vfs_read /@start[tid]/ { @ns[comm] = hist(nsecs - @start[tid]); delete(@start[tid]); }'
Attaching 2 probes...

[...]
@ns[snmp-pass]:
[0, 1]                 0 |                                                    |
[2, 4)                 0 |                                                    |
[4, 8)                 0 |                                                    |
[8, 16)                0 |                                                    |
[16, 32)               0 |                                                    |
[32, 64)               0 |                                                    |
[64, 128)              0 |                                                    |
[128, 256)             0 |                                                    |
[256, 512)            27 |@@@@@@@@@                                           |
[512, 1k)            125 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       |
[1k, 2k)              22 |@@@@@@@                                             |
[2k, 4k)               1 |                                                    |
[4k, 8k)              10 |@@@                                                 |
[8k, 16k)              1 |                                                    |
[16k, 32k)             3 |@                                                   |
[32k, 64k)           144 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[64k, 128k)            7 |@@                                                  |
[128k, 256k)          28 |@@@@@@@@@@                                          |
[256k, 512k)           2 |                                                    |
[512k, 1M)             3 |@                                                   |
[1M, 2M)               1 |                                                    |
```

Summarize the time spent in read(), in nanoseconds, as a histogram, by process name.

- @start[tid]: This uses the thread ID as a key. There may be many reads in-flight, and we want to store a start timestamp to each. How? We could construct a unique identifier for each read, and use that as the key. But because kernel threads can only be executing one syscall at a time, we can use the thread ID as the unique identifier, as each thread cannot be executing more than one.
- nsecs: Nanoseconds since boot. This is a high resolution timestamp counter than can be used to time events.
- /@start[tid]/: This filter checks that the start time was seen and recorded. Without this filter, this program may be launched during a read and only catch the end, resulting in a time calculation of now - zero, instead of now - start.

- delete(@start[tid]): this frees the variable.

# Lesson 8. Count Process-Level Events

```
# bpftrace -e 'tracepoint:sched:sched* { @[probe] = count(); } interval:s:5 { exit(); }'
Attaching 25 probes...
@[tracepoint:sched:sched_wakeup_new]: 1
@[tracepoint:sched:sched_process_fork]: 1
@[tracepoint:sched:sched_process_exec]: 1
@[tracepoint:sched:sched_process_exit]: 1
@[tracepoint:sched:sched_process_free]: 2
@[tracepoint:sched:sched_process_wait]: 7
@[tracepoint:sched:sched_wake_idle_without_ipi]: 53
@[tracepoint:sched:sched_stat_runtime]: 212
@[tracepoint:sched:sched_wakeup]: 253
@[tracepoint:sched:sched_waking]: 253
@[tracepoint:sched:sched_switch]: 510
```

Count process-level events for five seconds, printing a summary.

- sched: The `sched` probe category has high-level scheduler and process events, such as fork, exec, and context switch.
- name: The full name of the probe.
- interval:s:5: This is a probe that fires once every 5 seconds, on one CPU only. It is used for creating script-level intervals or timeouts.
- exit(): This exits bpftrace.

# Lesson 9. Profile On-CPU Kernel Stacks

```
# bpftrace -e 'profile:hz:99 { @[stack] = count(); }'
Attaching 1 probe...
^C

[...]
@[
filemap_map_pages+181
__handle_mm_fault+2905
handle_mm_fault+250
__do_page_fault+599
async_page_fault+69
]: 12
[...]
@[
cpuidle_enter_state+164
do_idle+390
cpu_startup_entry+111
start_secondary+423
secondary_startup_64+165
]: 22122
```

Profile kernel stacks at 99 Hertz, printing a frequency count.

- profile:hz:99: This fires on all CPUs at 99 Hertz. Why 99 and not 100 or 1000? We want frequent enough to catch both the big and small picture of execution, but not too frequent as to perturb performance. 100 Hertz is enough. But we don't want 100 exactly, as sampling may occur in lockstep with other timed activities, hence 99.
- stack: Returns the kernel stack trace. This is used as a key for the map, so that it can be frequency counted. The output of this is ideal to be visualized as a flame graph. There is also `ustack` for the user-level stack trace.

# Lesson 10. Scheduler Tracing

```
# bpftrace -e 'tracepoint:sched:sched_switch { @[stack] = count(); }'
^C
[...]

@[
__schedule+697
__schedule+697
schedule+50
schedule_timeout+365
xfsaild+274
kthread+248
ret_from_fork+53
]: 73
@[
__schedule+697
__schedule+697
schedule_idle+40
do_idle+356
cpu_startup_entry+111
start_secondary+423
secondary_startup_64+165
]: 305
```

This counts stack traces that led to context switching (off-CPU) events. The above output has been truncated to show the last two only.

- sched: The sched category has tracepoints for different kernel CPU scheduler events: sched_switch, sched_wakeup, sched_migrate_task, etc.
- sched_switch: This probe fires when a thread leaves CPU. This will be a blocking event: eg, waiting on I/O, a timer, paging/swapping, or a lock.
- stack: A kernel stack trace.
- sched_switch fires in thread context, so that the stack refers to the thread who is leaving. As you use other probe types, pay attention to context, as comm, pid, stack, etc, may not refer to the target of the probe.

# Lesson 11. Block I/O Tracing

```
# bpftrace -e 'tracepoint:block:block_rq_issue { @ = hist(args->bytes); }'
Attaching 1 probe...
^C

@:
[0, 1]                 1 |@@                                                  |
[2, 4)                 0 |                                                    |
[4, 8)                 0 |                                                    |
[8, 16)                0 |                                                    |
[16, 32)               0 |                                                    |
[32, 64)               0 |                                                    |
[64, 128)              0 |                                                    |
[128, 256)             0 |                                                    |
[256, 512)             0 |                                                    |
[512, 1K)              0 |                                                    |
[1K, 2K)               0 |                                                    |
[2K, 4K)               0 |                                                    |
[4K, 8K)              24 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[8K, 16K)              2 |@@@@                                                |
[16K, 32K)             6 |@@@@@@@@@@@@@                                       |
[32K, 64K)             5 |@@@@@@@@@@                                          |
[64K, 128K)            0 |                                                    |
[128K, 256K)           1 |@@                                                  |

```

Block I/O requests by size in bytes, as a histogram.

- tracepoint:block: The block category of tracepoints traces various block I/O (storage) events.
- block_rq_issue: This fires when an I/O is issued to the device.
- args->bytes: This is a member from the tracepoint block_rq_issue arguments which shows the size in bytes.

The context of this probe is important: this fires when the I/O is issued to the device. This often happens in process context, where builtins like comm will show you the process name, but it can also happen from kernel context (eg, readahead) when the pid and comm will not show the application you expect.

# Lesson 12. Kernel Struct Tracing

```
# cat path.bt
#include <linux/path.h>
#include <linux/dcache.h>

kprobe:vfs_open
{
	printf("open path: %s\n", str(((path *)arg0)->dentry->d_name.name));
}

# bpftrace path.bt
Attaching 1 probe...
open path: dev
open path: if_inet6
open path: retrans_time_ms
[...]
```

This uses kernel dynamic tracing of the vfs_open() function, which has a (struct path *) as the first argument.

- kprobe: As mentioned earlier, this is the kernel dynamic tracing probe type, which traces the entry of kernel functions (use kretprobe to trace their returns).
- ((path *)arg0)->dentry->d_name.name: this casts arg0 as path *, then dereferences dentry, etc.
- #include: these were necessary to include struct definitions for path and dentry.

The kernel struct support is currently the same as bcc, making use of kernel headers. This means that many structs are available, but not everything, and sometimes it might be necessary to manually include a struct. For an example of this, see the [dcsnoop tool](../tools/dcsnoop.bt), which includes a portion of struct nameidata manually as it wasn't in the available headers. In the future, bpftrace will use the newer Linux BTF support, so that all structs are available.

At this point you understand much of bpftrace, and can begin to use and write powerful one-liners. See the [Reference Guide](reference_guide.md) for more capabilities.
