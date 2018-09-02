# bpftrace Reference Guide

For a reference summary, see the [README.md](../README.md) for the sections on [Probe types](../README.md#probe-types) and [Builtins](../README.md#builtins).

This is a work in progress. If something is missing or incomplete, check the bpftrace source to see if these docs are just out of date. And if you find something, please file an issue or pull request to update these docs.

## Contents

- [Terminology](#terminology)
- [Language](#language)
    - [1. `{...}`: Action Blocks](#1--action-blocks)
    - [2. `/.../`: Filtering](#2--filtering)
    - [3. `//`, `/*`: Comments](#3---comments)
    - [4. `->`: C Struct Navigation](#4---c-struct-navigation)
- [Probes](#probes)
    - [1. `kprobe`/`kretprobe`: Dynamic Tracing, Kernel-Level](#1-kprobekretprobe-dynamic-tracing-kernel-level)
    - [2. `kprobe`/`kretprobe`: Dynamic Tracing, Kernel-Level Arguments](#2-kprobekretprobe-dynamic-tracing-kernel-level-arguments)
    - [3. `uprobe`/`uretprobe`: Dynamic Tracing, User-Level](#3-uprobeuretprobe-dynamic-tracing-user-level)
    - [4. `uprobe`/`uretprobe`: Dynamic Tracing, User-Level Arguments](#4-uprobeuretprobe-dynamic-tracing-user-level-arguments)
    - [5. `tracepoint`: Static Tracing, Kernel-Level](#5-tracepoint-static-tracing-kernel-level)
    - [6. `tracepoint`: Static Tracing, Kernel-Level Arguments](#6-tracepoint-static-tracing-kernel-level-arguments)
    - [7. `usdt`: Static Tracing, User-Level](#7-usdt-static-tracing-user-level)
    - [8. `usdt`: Static Tracing, User-Level Arguments](#8-usdt-static-tracing-user-level-arguments)
    - [9. `profile`: Timed Sampling Events](#9-profile-timed-sampling-events)
    - [10. `software`: Pre-defined Software Events](#10-software-pre-defined-software-events)
    - [11. `hardware`: Pre-defined Hardware Events](#11-hardware-pre-defined-hardware-events)
- [Variables](#variables)
    - [1. Builtins](#1-builtins)
    - [2. `@`, `$`: Basic Variables](#2---basic-variables)
    - [3. `@[]`: Associative Arrays](#3--associative-arrays)
    - [4. `count()`: Frequency Counting](#4-count-frequency-counting)
    - [5. `hist()`, `lhist()`: Histograms](#5-hist-lhist-histograms)
    - [6. `nsecs`: Timestamps and Time Deltas](#6-nsecs-timestamps-and-time-deltas)
    - [7. `stack`: Stack Traces, Kernel](#7-stack-stack-traces-kernel)
    - [8. `ustack`: Stack Traces, User](#8-ustack-stack-traces-user)
- [Functions](#functions)
    - [1. Builtins](#1-builtins2)
    - [2. `printf()`: Print Formatted](#2-printf-print-formatted)
    - [3. `time()`: Time](#3-time-time)
    - [4. `join()`: Join](#4-join-join)
    - [5. `str()`: Strings](#5-str-strings)
    - [6. `sym()`: Symbol Resolution, Kernel-Level](#6-str-symbol-resolution-kernel-level)
    - [7. `usym()`: Symbol Resolution, User-Level](#7-usym-symbol-resolution-user-level)
    - [8. `reg()`: Registers](#8-reg-registers)
    - [9. `exit()`: Exit](#9-exit-exit)
- [Map Functions](#map-functions)
    - [1. Builtins](#1-builtins3)
    - [2. `count()`: Count](#2-count-count)
    - [3. `sum()`: Sum](#3-sum-sum)
    - [4. `avg()`: Average](#4-avg-average)
    - [5. `min()`: Minimum](#5-min-minimum)
    - [6. `max()`: Maximum](#6-max-maximum)
    - [7. `stats()`: Stats](#7-stats-stats)
    - [8. `hist()`: Log2 Histogram](#8-hist-log2-histogram)
    - [9. `lhist()`: Linear Histogram](#9-lhist-linear-histogram)
    - [10. `print()`: Print Map](#10-print-print-map)
- [Output](#output)
    - [1. `printf()`: Per-Event Output](#1-printf-per-event-output)
    - [2. `interval`: Interval Output](#2-interval-interval-output)
    - [3. `hist()`, `printf()`: Histogram Printing](#3-hist-printf-histogram-printing)
- [Errors](#errors)

# Terminology

Term | Description
---- | -----------
BPF | Berkely Packet Filter: a kernel technology originally developed for optimizing the processing of packet filters (eg, tcpdump expressions)
eBPF | Enhanced BPF: a kernel technology that extends BPF so that it can execute more generic programs on any events, such as the bpftrace programs listed below. It makes use of the BPF sandboxed virtual machine environment. Also note that eBPF is often just referred to as BPF.
probe | An instrumentation point in software or hardware, that generates events that can execute bpftrace programs.
static tracing | Hard-coded instrumentation points in code. Since these are fixed, they may be provided as part of a stable API, and documented.
dynamic tracing | Also known as dynamic instrumentation, this is a technology that can instrument any software event, such as function calls and returns, by live modification of instruction text. Target software usually does not need special capabilities to support dynamic tracing, other than a symbol table that bpftrace can read. Since this instruments all software text, it is not considered a stable API, and the target functions may not be documented outside of their source code.
tracepoints | A Linux kernel technology for providing static tracing.
kprobes | A Linux kernel technology for providing dynamic tracing of kernel functions.
uprobes | A Linux kernel technology for providing dynamic tracing of user-level functions.
USDT | User Statically-Defined Tracing: static tracing points for user-level software. Some applications support USDT.
BPF map | A BPF memory object, which is used by bpftrace to create many higher-level objects.

# Language

## 1. `{...}`: Action Blocks

Syntax: `probe[,probe,...] /filter/ { action }`

A bpftrace program can have multiple action blocks. The filter is optional.

Example:

```
# bpftrace -e 'kprobe:do_sys_open { printf("opening: %s\n", str(arg1)); }'
Attaching 1 probe...
opening: /proc/cpuinfo
opening: /proc/stat
opening: /proc/diskstats
opening: /proc/stat
opening: /proc/vmstat
[...]
```

This is a one-liner invocation of bpftrace. The probe is `kprobe:do_sys_open`. When that probe "fires" (the instrumentation event occurred) the action will be executed, which consists of a `print()` statement. Explanations of the probe and action are in the sections that follow.

## 2. `/.../`: Filtering

Syntax: `/filter/`

Filters (also known as predicates) can be added after probe names. The probe still fires, but it will skip the action unless the filter is true.

Examples:

```
# bpftrace -e 'kprobe:sys_read /arg2 < 16/ { printf("small read: %d byte buffer\n", arg2); }'
Attaching 1 probe...
small read: 8 byte buffer
small read: 8 byte buffer
small read: 8 byte buffer
small read: 8 byte buffer
small read: 8 byte buffer
small read: 12 byte buffer
^C
```

```
# bpftrace -e 'kprobe:sys_read /comm == "bash"/ { printf("read by %s\n", comm); }'
Attaching 1 probe...
read by bash
read by bash
read by bash
read by bash
^C
```

## 3. `//`, `/*`: Comments

Syntax

```
// single-line comment

/*
 * multi-line comment
 */
```

These can be used in bpftrace scripts to document your code.

## 4. `->`: C Struct Navigation

**TODO**: see issue [#31](https://github.com/iovisor/bpftrace/issues/31)

Future example:

```
bpftrace -e 'kprobe:sys_nanosleep { printf("secs: %d\n", arg0->tv_nsec); }
```

or

```
bpftrace -e 'kprobe:sys_nanosleep { printf("secs: %d\n", ((struct timespec *)arg0)->tv_nsec); }'
```

# Probes

- `kprobe` - kernel function start
- `kretprobe` - kernel function return
- `uprobe` - user-level function start
- `uretprobe` - user-level function return
- `tracepoint` - kernel static tracepoints
- `profile` - timed sampling

Some probe types allow wildcards to match multiple probes, eg, `kprobe:SyS_*`.

## 1. `kprobe`/`kretprobe`: Dynamic Tracing, Kernel-Level

Syntax:

```
kprobe:function_name
kretprobe:function_name
```

These use kprobes (a Linux kernel capability). `kprobe` instruments the beginning of a function's execution, and `kretprobe` instruments the end (its return).

Examples:

```
# bpftrace -e 'kprobe:sys_nanosleep { printf("sleep by %d\n", tid); }'
Attaching 1 probe...
sleep by 1396
sleep by 3669
sleep by 1396
sleep by 27662
sleep by 3669
^C
```

## 2. `kprobe`/`kretprobe`: Dynamic Tracing, Kernel-Level Arguments

Syntax: `arg0, arg1, ..., argN`

Arguments can be accessed via these variables names. arg0 is the first argument.

Examples:

```
# bpftrace -e 'kprobe:do_sys_open { printf("opening: %s\n", str(arg1)); }'
Attaching 1 probe...
opening: /proc/cpuinfo
opening: /proc/stat
opening: /proc/diskstats
opening: /proc/stat
opening: /proc/vmstat
[...]
```

```
# bpftrace -e 'kprobe:do_sys_open { printf("open flags: %d\n", arg2); }'
Attaching 1 probe...
open flags: 557056
open flags: 32768
open flags: 32768
open flags: 32768
[...]
```

```
# bpftrace -e 'kretprobe:do_sys_open { printf("returned: %d\n", retval); }'
Attaching 1 probe...
returned: 8
returned: 21
returned: -2
returned: 21
[...]
```

## 3. `uprobe`/`uretprobe`: Dynamic Tracing, User-Level

Syntax:

```
uprobe:library_name:function_name
uretprobe:library_name:function_name
```

These use uprobes (a Linux kernel capability). `uprobe` instruments the beginning of a user-level function's execution, and `uretprobe` instruments the end (its return).

Examples:

```
# bpftrace -e 'uretprobe:/bin/bash:readline { printf("read a line\n"); }'
Attaching 1 probe...
read a line
read a line
read a line
read a line
^C
```

## 4. `uprobe`/`uretprobe`: Dynamic Tracing, User-Level Arguments

Syntax: `arg0, arg1, ..., argN`

Arguments can be accessed via these variables names. arg0 is the first argument.

Examples:

```
# bpftrace -e 'uprobe:/bin/bash:readline { printf("arg0: %d\n", arg0); }'
Attaching 1 probe...
arg0: 19755784
arg0: 19755016
arg0: 19755784
^C
```

```
# bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libc-2.23.so:fopen { printf("fopen: %s\n", str(arg0)); }'
Attaching 1 probe...
fopen: /proc/filesystems
fopen: /usr/share/locale/locale.alias
fopen: /proc/self/mountinfo
^C
```

```
# bpftrace -e 'uretprobe:/bin/bash:readline { printf("readline: \"%s\"\n", str(retval)); }'
Attaching 1 probe...
readline: "echo hi"
readline: "ls -l"
readline: "date"
readline: "uname -r"
^C
```

## 5. `tracepoint`: Static Tracing, Kernel-Level

Syntax: `tracepoint:name`

These use tracepoints (a Linux kernel capability).

```
# bpftrace -e 'tracepoint:block:block_rq_insert { printf("block I/O created by %d\n", tid); }'
Attaching 1 probe...
block I/O created by 28922
block I/O created by 3949
block I/O created by 883
block I/O created by 28941
block I/O created by 28941
block I/O created by 28941
[...]
```

## 6. `tracepoint`: Static Tracing, Kernel-Level Arguments

**TODO**: see issue [#32](https://github.com/iovisor/bpftrace/issues/32)

Future examples:

```
bpftrace -e 'tracepoint:block:block_rq_insert { printf("sectors: %d\n", args->nr_sector); }'
```

## 7. `usdt`: Static Tracing, User-Level

Syntax:

```
usdt:binary_path:probe_name
usdt:library_path:probe_name
```

Examples:

```
# bpftrace -e 'usdt:/root/tick:loop { printf("hi\n"); }'
Attaching 1 probe...
hi
hi
hi
hi
hi
^C
```

## 8. `usdt`: Static Tracing, User-Level Arguments

**TODO**: see issue [#33](https://github.com/iovisor/bpftrace/issues/33)

Future example:

```
bpftrace -e 'usdt:pthread:pthread_create /arg4 != 0/ { printf("created thread\n"); }'
```

## 9. `profile`: Timed Sampling Events

Syntax:

```
profile:hz:rate
profile:s:rate
profile:ms:rate
profile:us:rate
```

These operating using perf_events (a Linux kernel facility), which is also used by the `perf` command).

Examples:

```
# bpftrace -e 'profile:hz:99 { @[tid] = count(); }'
Attaching 1 probe...
^C

@[32586]: 98
@[0]: 579
```

## 10. `software`: Pre-defined Software Events

Syntax:

```
software:event_name:count
software:event_name:
```

These are the pre-defined software events provided by the Linux kernel, as commonly traced via the perf utility. They are similar to tracepoints, but there is only about a dozen of these, and they are documented in the perf\_event\_open(2) man page. The event names are:

- `cpu-clock` or `cpu`
- `task-clock`
- `page-faults` or `faults`
- `context-switches` or `cs`
- `cpu-migrations`
- `minor-faults`
- `major-faults`
- `alignment-faults`
- `emulation-faults`
- `dummy`
- `bpf-output`

The count is the trigger for the probe, which will fire once for every count events. If the count is not provided, a default is used.

Examples:

```
# bpftrace -e 'software:faults:100 { @[comm] = count(); }'
Attaching 1 probe...
^C

@[ls]: 1
@[pager]: 2
@[locale]: 2
@[preconv]: 2
@[sh]: 3
@[tbl]: 3
@[bash]: 4
@[groff]: 5
@[grotty]: 7
@[sleep]: 9
@[nroff]: 12
@[troff]: 18
@[man]: 97
```

This roughly counts who is causing page faults, by sampling the process name for every one in one hundred faults.

## 11. `hardware`: Pre-defined Hardware Events

Syntax:

```
hardware:event_name:count
hardware:event_name:
```

These are the pre-defined hardware events provided by the Linux kernel, as commonly traced by the perf utility. They are implemented using performance monitoring counters (PMCs): hardware resources on the processor. There are about ten of these, and they are documented in the perf\_event\_open(2) man page. The event names are:

- `cpu-cycles` or `cycles`
- `instructions`
- `cache-references`
- `cache-misses`
- `branch-instructions` or `branches`
- `bus-cycles`
- `frontend-stalls`
- `backend-stalls`
- `ref-cycles`

The count is the trigger for the probe, which will fire once for every count events. If the count is not provided, a default is used.

Examples:

```
bpftrace -e 'hardware:cache-misses:1000000 { @[pid] = count(); }'
```

That would fire once for every 1000000 cache misses. This usually indicates the last level cache (LLC).

# Variables

## 1. Builtins

- `pid` - Process ID (kernel tgid)
- `tid` - Thread ID (kernel pid)
- `uid` - User ID
- `gid` - Group ID
- `nsecs` - Nanosecond timestamp
- `cpu` - Processor ID
- `comm` - Process name
- `stack` - Kernel stack trace
- `ustack` - User stack trace
- `arg0`, `arg1`, ..., `argN`. - Arguments to the traced function
- `retval` - Return value from traced function
- `func` - Name of the traced function
- `name` - Full name of the probe
- `curtask` - Current task struct as a u64
- `rand` - Random number as a u32

Many of these are discussed in other sections (use search).

## 2. `@`, `$`: Basic variables

Syntax:

```
@global_name
@thread_local_variable_name[tid]
$scratch_name
```

bpftrace supports global & per-thread variables (via BPF maps), and scratch variables.

Examples:

### 2.1. Global

Syntax: `@name`

For example, `@start`:

```
# bpftrace -e 'BEGIN { @start = nsecs; }
    kprobe:sys_nanosleep /@start != 0/ { printf("at %d ms: sleep\n", (nsecs - @start) / 1000000); }'
Attaching 2 probes...
at 437 ms: sleep
at 647 ms: sleep
at 1098 ms: sleep
at 1438 ms: sleep
at 1648 ms: sleep
^C

@start: 4064438886907216
```

### 2.2. Per-Thread:

These can be implemented as an associative array keyed on the thread ID. For example, `@start[tid]`:

```
# bpftrace -e 'kprobe:sys_nanosleep { @start[tid] = nsecs; }
    kretprobe:sys_nanosleep /@start[tid] != 0/ { printf("slept for %d ms\n", (nsecs - @start[tid]) / 1000000); delete(@start[tid]); }'
Attaching 2 probes...
slept for 1000 ms
slept for 1000 ms
slept for 1000 ms
slept for 1009 ms
slept for 2002 ms
[...]
```

### 2.3. Scratch:

Syntax: `$name`

For example, `$delta`:

```
# bpftrace -e 'kprobe:sys_nanosleep { @start[tid] = nsecs; }
    kretprobe:sys_nanosleep /@start[tid] != 0/ { $delta = nsecs - @start[tid]; printf("slept for %d ms\n", $delta / 1000000); delete(@start[tid]); }'
Attaching 2 probes...
slept for 1000 ms
slept for 1000 ms
slept for 1000 ms
```

## 3. `@[]`: Associative Arrays

Syntax: `@associative_array_name[key_name] = value`

These are implemented using BPF maps.

For example, `@start[tid]`:

```
# bpftrace -e 'kprobe:sys_nanosleep { @start[tid] = nsecs; }
    kretprobe:sys_nanosleep /@start[tid] != 0/ { printf("slept for %d ms\n", (nsecs - @start[tid]) / 1000000); delete(@start[tid]); }'
Attaching 2 probes...
slept for 1000 ms
slept for 1000 ms
slept for 1000 ms
[...]
```

## 4. `count()`: Frequency Counting

This is provided by the count() function: see the [Count](#2-count) section.

## 5. `hist()`, `lhist()`: Histograms

These are provided by the hist() and lhist() functions. See the [Log2 Histogram](#8-log2-histogram) and [Linear Histogram](#9-linear-histogram) sections.

## 6. `nsecs`: Timestamps and Time Deltas

Syntax: `nsecs`

These are implemented using bpf_ktime_get_ns().

Examples:

```
# bpftrace -e 'BEGIN { @start = nsecs; }
    kprobe:sys_nanosleep /@start != 0/ { printf("at %d ms: sleep\n", (nsecs - @start) / 1000000); }'
Attaching 2 probes...
at 437 ms: sleep
at 647 ms: sleep
at 1098 ms: sleep
at 1438 ms: sleep
^C
```

## 7. `stack`: Stack Traces, Kernel

Syntax: `stack`

These are implemented using BPF stack maps.

Examples:

```
# bpftrace -e 'kprobe:ip_output { @[stack] = count(); }'
Attaching 1 probe...
[...]
@[
ip_output+1
tcp_transmit_skb+1308
tcp_write_xmit+482
tcp_release_cb+225
release_sock+64
tcp_sendmsg+49
sock_sendmsg+48
sock_write_iter+135
__vfs_write+247
vfs_write+179
sys_write+82
entry_SYSCALL_64_fastpath+30
]: 1708
@[
ip_output+1
tcp_transmit_skb+1308
tcp_write_xmit+482
__tcp_push_pending_frames+45
tcp_sendmsg_locked+2637
tcp_sendmsg+39
sock_sendmsg+48
sock_write_iter+135
__vfs_write+247
vfs_write+179
sys_write+82
entry_SYSCALL_64_fastpath+30
]: 9048
@[
ip_output+1
tcp_transmit_skb+1308
tcp_write_xmit+482
tcp_tasklet_func+348
tasklet_action+241
__do_softirq+239
irq_exit+174
do_IRQ+74
ret_from_intr+0
cpuidle_enter_state+159
do_idle+389
cpu_startup_entry+111
start_secondary+398
secondary_startup_64+165
]: 11430
```

## 8. `ustack`: Stack Traces, User

Syntax: `ustack`

These are implemented using BPF stack maps.

Examples:

```
# bpftrace -e 'kprobe:do_sys_open /comm == "bash"/ { @[ustack] = count(); }'
Attaching 1 probe...
^C

@[
__open_nocancel+65
command_word_completion_function+3604
rl_completion_matches+370
bash_default_completion+540
attempt_shell_completion+2092
gen_completion_matches+82
rl_complete_internal+288
rl_complete+145
_rl_dispatch_subseq+647
_rl_dispatch+44
readline_internal_char+479
readline_internal_charloop+22
readline_internal+23
readline+91
yy_readline_get+152
yy_readline_get+429
yy_getc+13
shell_getc+469
read_token+251
yylex+192
yyparse+777
parse_command+126
read_command+207
reader_loop+391
main+2409
__libc_start_main+231
0x61ce258d4c544155
]: 9
@[
__open_nocancel+65
command_word_completion_function+3604
rl_completion_matches+370
bash_default_completion+540
attempt_shell_completion+2092
gen_completion_matches+82
rl_complete_internal+288
rl_complete+89
_rl_dispatch_subseq+647
_rl_dispatch+44
readline_internal_char+479
readline_internal_charloop+22
readline_internal+23
readline+91
yy_readline_get+152
yy_readline_get+429
yy_getc+13
shell_getc+469
read_token+251
yylex+192
yyparse+777
parse_command+126
read_command+207
reader_loop+391
main+2409
__libc_start_main+231
0x61ce258d4c544155
]: 18
```

Note that for this example to work, bash had to be recompiled with frame pointers.

# Functions

## 1. Builtins

- `printf(char *fmt, ...)` - Print formatted
- `time(char *fmt)` - Print formatted time
- `join(char *arr[])` - Print the array
- `str(char *s)` - Returns the string pointed to by s
- `sym(void *p)` - Resolve kernel address
- `usym(void *p)` - Resolve user space address (incomplete)
- `reg(char *name)` - Returns the value stored in the named register
- `exit()` - Quit bpftrace

Some of these are asynchronous: the kernel queues the event, but some time later (milliseconds) it is processed in user-space. The asynchronous actions are: <tt>printf()</tt>, <tt>time()</tt>, and <tt>join()</tt>. Both <tt>sym()</tt> and <tt>usym()</tt>, as well as the variables <tt>stack</tt> and </tt>ustack</tt>, record addresses synchronously, but then do symbol translation asynchronously.

A selection of these are discussed in the following sections.

## 2. `printf()`: Printing

Syntax: `printf(fmt, args)`

This behaves like printf() from C and other languages, with a limited set of format characters. Example:

```
# bpftrace -e 'kprobe:sys_execve { printf("%s called %s\n", comm, str(arg0)); }'
Attaching 1 probe...
bash called /bin/ls
bash called /usr/bin/man
man called /apps/nflx-bash-utils/bin/preconv
man called /usr/local/sbin/preconv
man called /usr/local/bin/preconv
man called /usr/sbin/preconv
man called /usr/bin/preconv
man called /apps/nflx-bash-utils/bin/tbl
[...]
```

## 3. `time()`: Time

Syntax: `time(fmt)`

This prints the current time using the format string supported by libc `strftime(3)`.

```
# bpftrace -e 'kprobe:sys_nanosleep { time("%H:%M:%S"); }'
07:11:03
07:11:09
^C
```

If a format string is not provided, it defaults to "%H:%M:%S".

## 4. `join()`: Join

Syntax: `join(char *arr[])`

This joins the array of strings with a space character, and prints it out. This current version does not return a string, so it cannot be used as an argument in printf(). Example:

```
# bpftrace -e 'kprobe:sys_execve { join(arg1); }'
Attaching 1 probe...
ls --color=auto
man ls
preconv -e UTF-8
preconv -e UTF-8
preconv -e UTF-8
preconv -e UTF-8
preconv -e UTF-8
tbl
[...]
```

## 5. `str()`: Strings

Syntax: `str(char *s)`

Returns the string pointer to by s. This was used in the earlier printf() example, since arg0 to sys_execve() is <tt>const char *filename</tt>:

```
# bpftrace -e 'kprobe:sys_execve { printf("%s called %s\n", comm, str(arg0)); }'
Attaching 1 probe...
bash called /bin/ls
bash called /usr/bin/man
man called /apps/nflx-bash-utils/bin/preconv
man called /usr/local/sbin/preconv
man called /usr/local/bin/preconv
man called /usr/sbin/preconv
man called /usr/bin/preconv
man called /apps/nflx-bash-utils/bin/tbl
[...]
```

## 6. `sym()`: Symbol resolution, kernel-level

Syntax: `sym(addr)`

Examples:

```
# ./build/src/bpftrace -e 'kprobe:sys_nanosleep { printf("%s\n", sym(reg("ip"))); }'
Attaching 1 probe...
sys_nanosleep
sys_nanosleep
```

## 7. `usym()`: Symbol resolution, user-level

Syntax: `usym(addr)`

Examples:

```
# bpftrace -e 'uprobe:/bin/bash:readline { printf("%s\n", usym(reg("ip"))); }'
Attaching 1 probe...
readline
readline
readline
^C
```

## 8. `reg()`: Registers

Syntax: `reg(char *name)`

Examples:

```
# ./src/bpftrace -e 'kprobe:tcp_sendmsg { @[sym(reg("ip"))] = count(); }'
Attaching 1 probe...
^C

@[tcp_sendmsg]: 7
```

See src/arch/x86_64.cpp for the register name list.

## 9. `exit()`: Exit

Syntax: `exit()`

This exits bpftrace, and can be combined with an interval probe to record statistics for a certain duration. Example:

```
# bpftrace -e 'kprobe:do_sys_open { @opens = count(); } interval:s:1 { exit(); }'
Attaching 2 probes...
@opens: 119
```

# Map Functions

## 1. Builtins

- `count()` - Count the number of times this function is called
- `sum(int n)` - Sum the value
- `avg(int n)` - Average the value
- `min(int n)` - Record the minimum value seen
- `max(int n)` - Record the maximum value seen
- `stats(int n)` - Return the count, average, and total for this value
- `hist(int n)` - Produce a log2 histogram of values of n
- `lhist(int n, int min, int max, int step)` - Produce a linear histogram of values of n
- `delete(@x[key])` - Delete the map element passed in as an argument
- `print(@x[, top [, div]])` - Print the map, optionally the top entries only and with a divisor
- `clear(@x)` - Delete all keys from the map
- `zero(@x)` - Set all map values to zero

Some of these are asynchronous: the kernel queues the event, but some time later (milliseconds) it is processed in user-space. The asynchronous actions are: <tt>print()</tt>, <tt>clear()</tt>, and <tt>zero()</tt>.

## 2. `count()`: Count

Syntax: `@counter_name[optional_keys] = count()`

This is implemented using a BPF map.

For example, `@reads`:

```
# bpftrace -e 'kprobe:sys_read { @reads = count();  }'
Attaching 1 probe...
^C

@reads: 119
```

That shows there were 119 calls to sys_read() while tracing.

This next example includes the `comm` variable as a key, so that the value is broken down by each process name. For example, `@reads[comm]`:

```
# bpftrace -e 'kprobe:sys_read { @reads[comm] = count(); }'
Attaching 1 probe...
^C

@reads[sleep]: 4
@reads[bash]: 5
@reads[ls]: 7
@reads[snmp-pass]: 8
@reads[snmpd]: 14
@reads[sshd]: 14
```

## 3. `sum()`: Sum

Syntax: `@counter_name[optional_keys] = sum(value)`

This is implemented using a BPF map.

For example, `@bytes[comm]`:

```
# bpftrace -e 'kprobe:sys_read { @bytes[comm] = sum(arg2); }'
Attaching 1 probe...
^C

@bytes[bash]: 7
@bytes[sleep]: 4160
@bytes[ls]: 6208
@bytes[snmpd]: 20480
@bytes[snmp-pass]: 65536
@bytes[sshd]: 262144
```

That is summing requested bytes via the sys_read() kernel function, which is one of two possible entry points for the read syscall. To see actual bytes read:

```
# bpftrace -e 'kretprobe:sys_read /retval > 0/ { @bytes[comm] = sum(retval); }'
Attaching 1 probe...
^C

@bytes[bash]: 5
@bytes[sshd]: 1135
@bytes[systemd-journal]: 1699
@bytes[sleep]: 2496
@bytes[ls]: 4583
@bytes[snmpd]: 35549
@bytes[snmp-pass]: 55681
```

Now a filter is used to ensure the return value was positive before it is used in the sum(). The return value may be negative in cases of error, as is the case with other functions. Remember this whenever using sum() on a retval.

## 4. `avg()`: Average

Syntax: `@counter_name[optional_keys] = avg(value)`

This is implemented using a BPF map.

For example, `@bytes[comm]`:

```
# bpftrace -e 'kprobe:sys_read { @bytes[comm] = avg(arg2); }'
Attaching 1 probe...
^C

@bytes[bash]: 1
@bytes[sleep]: 832
@bytes[ls]: 886
@bytes[snmpd]: 1706
@bytes[snmp-pass]: 8192
@bytes[sshd]: 16384
```

This is averaging the requested read size.

## 5. `min()`: Minimum

Syntax: `@counter_name[optional_keys] = min(value)`

This is implemented using a BPF map.

For example, `@bytes[comm]`:

```
# bpftrace -e 'kprobe:sys_read { @bytes[comm] = min(arg2); }'
Attaching 1 probe...
^C

@bytes[bash]: 1
@bytes[systemd-journal]: 8
@bytes[snmpd]: 64
@bytes[ls]: 832
@bytes[sleep]: 832
@bytes[snmp-pass]: 8192
@bytes[sshd]: 16384
```

This shows the minimum value seen.

## 6. `max()`: Maximum

Syntax: `@counter_name[optional_keys] = max(value)`

This is implemented using a BPF map.

For example, `@bytes[comm]`:

```
# bpftrace -e 'kprobe:sys_read { @bytes[comm] = max(arg2); }'
Attaching 1 probe...
^C

@bytes[bash]: 1
@bytes[systemd-journal]: 8
@bytes[sleep]: 832
@bytes[ls]: 1024
@bytes[snmpd]: 4096
@bytes[snmp-pass]: 8192
@bytes[sshd]: 16384
```

This shows the maximum value seen.

## 7. `stats()`: Stats

Syntax: `@counter_name[optional_keys] = stats(value)`

This is implemented using a BPF map.

For example, `@bytes[comm]`:

```
# bpftrace -e 'kprobe:sys_read { @bytes[comm] = stats(arg2); }'
Attaching 1 probe...
^C

@bytes[bash]: count 7, average 1, total 7
@bytes[sleep]: count 5, average 832, total 4160
@bytes[ls]: count 7, average 886, total 6208
@bytes[snmpd]: count 18, average 1706, total 30718
@bytes[snmp-pass]: count 12, average 8192, total 98304
@bytes[sshd]: count 15, average 16384, total 245760
```

This stats() function returns three statistics: the count of events, the average for the argument value, and the total of the argument value. This is similar to using count(), avg(), and sum().

## 8. `hist()`: Log2 Histogram

Syntax:

```
@histogram_name[optional_key] = hist(value)
```

This is implemented using a BPF map.

Examples:

### 8.1. Power-Of-2:

```
# bpftrace -e 'kretprobe:sys_read { @bytes = hist(retval); }'
Attaching 1 probe...
^C

@bytes:
[0, 1]                 7 |@@@@@@@@@@@@@                                       |
[2, 4)                 3 |@@@@@                                               |
[4, 8)                 8 |@@@@@@@@@@@@@@                                      |
[8, 16)                9 |@@@@@@@@@@@@@@@@                                    |
[16, 32)               0 |                                                    |
[32, 64)               1 |@                                                   |
[64, 128)              1 |@                                                   |
[128, 256)             0 |                                                    |
[256, 512)             3 |@@@@@                                               |
[512, 1k)              0 |                                                    |
[1k, 2k)              12 |@@@@@@@@@@@@@@@@@@@@@@                              |
[2k, 4k)              28 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
```

### 8.2. Power-Of-2 By Key:

```
# bpftrace -e 'kretprobe:do_sys_open { @bytes[comm] = hist(retval); }'
Attaching 1 probe...
^C

@bytes[snmp-pass]:
[0, 1]                 0 |                                                    |
[2, 4)                 0 |                                                    |
[4, 8)                 6 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

@bytes[ls]:
[0, 1]                 0 |                                                    |
[2, 4)                 9 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

@bytes[snmpd]:
[0, 1]                 1 |@@@@                                                |
[2, 4)                 0 |                                                    |
[4, 8)                 0 |                                                    |
[8, 16)                4 |@@@@@@@@@@@@@@@@@@                                  |
[16, 32)              11 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
```

## 9. `lhist()`: Linear Histogram

Syntax:

```
@histogram_name[optional_key] = lhist(value, min, max, step)
```

This is implemented using a BPF map.

Examples:

```
# bpftrace -e 'kretprobe:sys_read { @bytes = lhist(retval, 0, 10000, 1000); }'
Attaching 1 probe...
^C

@bytes:
(...,0]                0 |                                                    |
[0, 1000)            480 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1000, 2000)          49 |@@@@@                                               |
[2000, 3000)          12 |@                                                   |
[3000, 4000)          39 |@@@@                                                |
[4000, 5000)         267 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@                        |
[5000, 6000)           0 |                                                    |
[6000, 7000)           0 |                                                    |
[7000, 8000)           0 |                                                    |
[8000, 9000)           0 |                                                    |
[9000, 10000)          0 |                                                    |
[10000,...)            0 |                                                    |
```

## 10. `print()`: Print Map

Syntax: ```print(@map [, top [, divisor]])```

The <tt>print()</tt> function will print a map, similar to the automatic printing when bpftrace ends. Two optional arguments can be provided: a top number, so that only the top number of entries are printed, and a divisor, which divides the value. A couple of examples will explain their use.

As an example of top, tracing the top 5 syscalls via kprobe:SyS_*:

```
# bpftrace -e 'kprobe:SyS_* { @[func] = count(); } END { print(@, 5); clear(@); }'
Attaching 345 probes...
^C
@[sys_write]: 1827
@[sys_newfstat]: 8401
@[sys_close]: 9608
@[sys_open]: 17453
@[sys_read]: 26353
```

The final <tt>clear()</tt> is used to prevent printing the map automatically on exit.

As an example of divisor, summing total time in SyS_read() by process name as milliseconds:

```
# bpftrace -e 'kprobe:SyS_read { @start[tid] = nsecs; } kretprobe:SyS_read /@start[tid]/ { @ms[pid] = sum(nsecs - @start[tid]); delete(@start[tid]); } END { print(@ms, 1, 1000000); clear(@ms); }'
```

This one-liner sums the SyS_read() durations as nanoseconds, and then does the division to milliseconds when printing. Without this capability, should one try to divide to milliseconds when summing (eg, <tt>sum((nsecs - @start[tid]) / 1000000)</tt>), the value would often be rounded to zero, and not accumulate as it should.

# Output

## 1. `printf()`: Per-Event Output

Syntax: `printf(char *format, arguments)`

Per-event details can be printed using `print()`.

Examples:

```
# bpftrace -e 'kprobe:sys_nanosleep { printf("sleep by %d\n", tid); }'
Attaching 1 probe...
sleep by 3669
sleep by 1396
sleep by 3669
sleep by 1396
[...]
```

## 2. `interval`: Interval output

Syntax: `interval:s:duration_seconds`

Examples:

```
# bpftrace -e 'kprobe:do_sys_open { @opens = @opens + 1; } interval:s:1 { printf("opens/sec: %d\n", @opens); @opens = 0; }'
Attaching 2 probes...
opens/sec: 16
opens/sec: 2
opens/sec: 3
opens/sec: 15
opens/sec: 8
opens/sec: 2
^C

@opens: 2
```

## 3. `hist()`, `print()`: Histogram Printing

Declared histograms are automatically printed out on program termination. See [5. Histograms](#5-histograms) for declarations.

Examples:

```
# bpftrace -e 'kretprobe:sys_read { @bytes = hist(retval); }'
Attaching 1 probe...
^C

@bytes:
[0, 1]                 7 |@@@@@@@@@@@@@                                       |
[2, 4)                 3 |@@@@@                                               |
[4, 8)                 8 |@@@@@@@@@@@@@@                                      |
[8, 16)                9 |@@@@@@@@@@@@@@@@                                    |
[16, 32)               0 |                                                    |
[32, 64)               1 |@                                                   |
[64, 128)              1 |@                                                   |
[128, 256)             0 |                                                    |
[256, 512)             3 |@@@@@                                               |
[512, 1k)              0 |                                                    |
[1k, 2k)              12 |@@@@@@@@@@@@@@@@@@@@@@                              |
[2k, 4k)              28 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
```

Histograms can also be printed on-demand, using the <tt>print()</tt> function. Eg:

<pre>
# bpftrace -e 'kretprobe:sys_read { @bytes = hist(retval); } interval:s:1 { print(@bytes); clear(@bytes); }'

[...]
</pre>


# Errors

## 1. Looks like the BPF stack limit of 512 bytes is exceeded

BPF programs that operate on many data items may hit this limit. There are a number of things you can try to stay within the limit:

1. Find ways to reduce the size of the data used in the program. Eg, avoid strings if they are unnecessary: use `pid` instead of `comm`. Use fewer map keys.
1. Split your program over multiple probes.
1. Check the status of the BPF stack limit in Linux (it may be increased in the future, maybe as a tuneabe).
1. (advanced): Run -d and examine the LLVM IR, and look for ways to optimize src/ast/codegen_llvm.cpp.
