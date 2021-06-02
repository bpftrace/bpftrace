# bpftrace Reference Guide

For a reference summary, see the [README.md](../README.md) for the sections on
[Probe types](../README.md#probe-types) as well as the [Probes](#probes), [Variable builtins](#1-builtins), and [Function builtins](#1-builtins-1) sections in this guide.

This is a work in progress. If something is missing, check the bpftrace source to see if these docs are
just out of date. And if you find something, please file an issue or pull request to update these docs.
Also, please keep these docs as terse as possible to maintain it's brevity (inspired by the 6-page awk
summary from page 106 of [v7vol2b.pdf](https://9p.io/7thEdMan/bswv7.html)). Leave longer examples and
discussion to other files in /docs, the /tools/\*\_examples.txt files, or blog posts and other articles.

## Contents

- [Terminology](#terminology)
- [Usage](#usage)
    - [1. Hello World](#1-hello-world)
    - [2. `-e 'program'`: One-Liners](#2--e-program-one-liners)
    - [3. `filename`: Program Files](#3-filename-program-files)
    - [4. `-l`: Listing Probes](#4--l-listing-probes)
    - [5. `-d`: Debug Output](#5--d-debug-output)
    - [6. `-v`: Verbose Output](#6--v-verbose-output)
    - [7. Preprocessor Options](#7-preprocessor-options)
    - [8. Other Options](#8-other-options)
    - [9. Environment Variables](#9-environment-variables)
    - [10. Clang Environment Variables](#10-clang-environment-variables)
- [Language](#language)
    - [1. `{...}`: Action Blocks](#1--action-blocks)
    - [2. `/.../`: Filtering](#2--filtering)
    - [3. `//`, `/*`: Comments](#3---comments)
    - [4. `->`: C Struct Navigation](#4---c-struct-navigation)
    - [5. `struct`: Struct Declaration](#5-struct-struct-declaration)
    - [6. `? :`: ternary operators](#6---ternary-operators)
    - [7. `if () {...} else {...}`: if-else statements](#7-if---else--if-else-statements)
    - [8. `unroll () {...}`: unroll](#8-unroll---unroll)
    - [9. `++ and --`: increment operators](#9--and----increment-operators)
    - [10. `[]`: Array access](#10--array-access)
    - [11. Integer casts](#11-integer-casts)
    - [12. Looping constructs](#12-looping-constructs)
    - [13. `return`: Terminate Early](#13-return-terminate-early)
    - [14. `( , )`: Tuples](#14----tuples)
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
    - [10. `interval`: Timed Output](#10-interval-timed-output)
    - [11. `software`: Pre-defined Software Events](#11-software-pre-defined-software-events)
    - [12. `hardware`: Pre-defined Hardware Events](#12-hardware-pre-defined-hardware-events)
    - [13. `BEGIN`/`END`: Built-in events](#13-beginend-built-in-events)
    - [14. `watchpoint`/`asyncwatchpoint`: Memory watchpoints](#14-watchpointasyncwatchpoint-memory-watchpoints)
    - [15. `kfunc`/`kretfunc`: Kernel Functions Tracing](#15-kfunckretfunc-kernel-functions-tracing)
    - [16. `kfunc`/`kretfunc`: Kernel Functions Tracing Arguments](#16-kfunckretfunc-kernel-functions-tracing-arguments)
    - [17. `iter`: Iterators Tracing ](#17-iter-iterators-tracing)
- [Variables](#variables)
    - [1. Builtins](#1-builtins)
    - [2. `@`, `$`: Basic Variables](#2---basic-variables)
    - [3. `@[]`: Associative Arrays](#3--associative-arrays)
    - [4. `count()`: Frequency Counting](#4-count-frequency-counting)
    - [5. `hist()`, `lhist()`: Histograms](#5-hist-lhist-histograms)
    - [6. `nsecs`: Timestamps and Time Deltas](#6-nsecs-timestamps-and-time-deltas)
    - [7. `kstack`: Stack Traces, Kernel](#7-kstack-stack-traces-kernel)
    - [8. `ustack`: Stack Traces, User](#8-ustack-stack-traces-user)
    - [9. `$1`, ..., `$N`, `$#`: Positional Parameters](#9-1--n--positional-parameters)
- [Functions](#functions)
    - [1. Builtins](#1-builtins-1)
    - [2. `printf()`: Print Formatted](#2-printf-Printing)
    - [3. `time()`: Time](#3-time-time)
    - [4. `join()`: Join](#4-join-join)
    - [5. `str()`: Strings](#5-str-strings)
    - [6. `ksym()`: Symbol Resolution, Kernel-Level](#6-ksym-symbol-resolution-kernel-level)
    - [7. `usym()`: Symbol Resolution, User-Level](#7-usym-symbol-resolution-user-level)
    - [8. `kaddr()`: Address Resolution, Kernel-Level](#8-kaddr-address-resolution-kernel-level)
    - [9. `uaddr()`: Address Resolution, User-Level](#9-uaddr-address-resolution-user-level)
    - [10. `reg()`: Registers](#10-reg-registers)
    - [11. `system()`: System](#11-system-system)
    - [12. `exit()`: Exit](#12-exit-exit)
    - [13. `cgroupid()`: Resolve cgroup ID](#13-cgroupid-resolve-cgroup-id)
    - [14. `ntop()`: Convert IP address data to text](#14-ntop-convert-ip-address-data-to-text)
    - [15. `kstack()`: Stack Traces, Kernel](#15-kstack-stack-traces-kernel)
    - [16. `ustack()`: Stack Traces, User](#16-ustack-stack-traces-user)
    - [17. `cat()`: Print file content](#17-cat-print-file-content)
    - [18. `signal()`: Send a signal to the current task](#18-signal-send-a-signal-to-current-task)
    - [19. `strncmp()`: Compare first n characters of two strings](#19-strncmp-compare-first-n-characters-of-two-strings)
    - [20. `override()`: Override return value](#20-override-override-return-value)
    - [21. `buf()`: Buffers](#21-buf-buffers)
    - [22. `sizeof()`: Size of type or expression](#22-sizeof-size-of-type-or-expression)
    - [23. `print()`: Print Value](#23-print-print-value)
    - [24. `strftime()`: Formatted timestamp](#24-strftime-formatted-timestamp)
    - [25. `path()`: Return full path](#25-path-return-full-path)
    - [26. `uptr()`: Annotate userspace pointer](#26-uptr-annotate-userspace-pointer)
    - [27. `kptr()`: Annotate kernelspace pointer](#27-kptr-annotate-kernelspace-pointer)
    - [28. `macaddr()`: Convert MAC address data to text](#28-macaddr-convert-mac-address-data-to-text)
- [Map Functions](#map-functions)
    - [1. Builtins](#1-builtins-2)
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
    - [3. `hist()`, `printf()`: Histogram Printing](#3-hist-print-histogram-printing)
- [BTF Support](#btf-support)
- [Advanced Tools](#advanced-tools)
- [Errors](#errors)

# Terminology

Term | Description
---- | -----------
BPF | Berkeley Packet Filter: a kernel technology originally developed for optimizing the processing of packet filters (eg, tcpdump expressions)
eBPF | Enhanced BPF: a kernel technology that extends BPF so that it can execute more generic programs on any events, such as the bpftrace programs listed below. It makes use of the BPF sandboxed virtual machine environment. Also note that eBPF is often just referred to as BPF.
probe | An instrumentation point in software or hardware, that generates events that can execute bpftrace programs.
static tracing | Hard-coded instrumentation points in code. Since these are fixed, they may be provided as part of a stable API, and documented.
dynamic tracing | Also known as dynamic instrumentation, this is a technology that can instrument any software event, such as function calls and returns, by live modification of instruction text. Target software usually does not need special capabilities to support dynamic tracing, other than a symbol table that bpftrace can read. Since this instruments all software text, it is not considered a stable API, and the target functions may not be documented outside of their source code.
tracepoints | A Linux kernel technology for providing static tracing.
kprobes | A Linux kernel technology for providing dynamic tracing of kernel functions.
uprobes | A Linux kernel technology for providing dynamic tracing of user-level functions.
USDT | User Statically-Defined Tracing: static tracing points for user-level software. Some applications support USDT.
BPF map | A BPF memory object, which is used by bpftrace to create many higher-level objects.
BTF | BPF Type Format: the metadata format which encodes the debug info related to BPF program/map.

# Usage

Command line usage is summarized by bpftrace without options:

```
# bpftrace
USAGE:
    bpftrace [options] filename
    bpftrace [options] -e 'program'

OPTIONS:
    -B MODE        output buffering mode ('line', 'full', or 'none')
    -d             debug info dry run
    -dd            verbose debug info dry run
    -e 'program'   execute this program
    -h             show this help message
    -I DIR         add the specified DIR to the search path for include files.
    --include FILE adds an implicit #include which is read before the source file is preprocessed.
    -l [search]    list probes
    -p PID         enable USDT probes on PID
    -c 'CMD'       run CMD and enable USDT probes on resulting process
    -q             keep messages quiet
    -v             verbose messages
    -k             emit a warning when a bpf helper returns an error (except read functions)
    -kk            check all bpf helper functions
    --version      bpftrace version

ENVIRONMENT:
    BPFTRACE_STRLEN             [default: 64] bytes on BPF stack per str()
    BPFTRACE_NO_CPP_DEMANGLE    [default: 0] disable C++ symbol demangling
    BPFTRACE_MAP_KEYS_MAX       [default: 4096] max keys in a map
    BPFTRACE_MAX_PROBES         [default: 512] max number of probes bpftrace can attach to
    BPFTRACE_CACHE_USER_SYMBOLS [default: auto] enable user symbol cache
    BPFTRACE_VMLINUX            [default: none] vmlinux path used for kernel symbol resolution
    BPFTRACE_BTF                [default: none] BTF file

EXAMPLES:
bpftrace -l '*sleep*'
    list probes containing "sleep"
bpftrace -e 'kprobe:do_nanosleep { printf("PID %d sleeping...\n", pid); }'
    trace processes calling sleep
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
    count syscalls by process name
```

## 1. Hello World

The most basic example of a bpftrace program:

```
# bpftrace -e 'BEGIN { printf("Hello, World!\n"); }'
Attaching 1 probe...
Hello, World!
^C
```

The syntax to this program will be explained in the [Language](#language) section. In this section, we'll
cover tool usage.

A program will continue running until Ctrl-C is hit, or an `exit()` function is called. When a program
exits, all populated maps are printed: this behavior, and maps, are explained in later sections.

## 2. `-e 'program'`: One-Liners

The `-e` option allows a program to be specified, and is a way to construct one-liners:

```
# bpftrace -e 'tracepoint:syscalls:sys_enter_nanosleep { printf("%s is sleeping.\n", comm); }'
Attaching 1 probe...
iscsid is sleeping.
irqbalance is sleeping.
iscsid is sleeping.
iscsid is sleeping.
[...]
```

This example is printing when processes call the nanosleep syscall. Again, the syntax of the program will
be explained in the [Language](#language) section.

## 3. `filename`: Program Files

Programs saved as files are often called scripts, and can be executed by specifying their file name.
We'll often use a `.bt` file extension, short for bpftrace, but the extension is ignored.

For example, listing the sleepers.bt file using `cat -n` (which enumerates the output lines):

```
# cat -n sleepers.bt
1 tracepoint:syscalls:sys_enter_nanosleep
2 {
3   printf("%s is sleeping.\n", comm);
4 }
```

Running sleepers.bt:

```
# bpftrace sleepers.bt
Attaching 1 probe...
iscsid is sleeping.
iscsid is sleeping.
[...]
```

It can also be made executable to run stand-alone. Start by adding an interpreter line at the top (`#!`)
with either the path to your installed bpftrace (/usr/local/bin is the default) or the path to `env`
(usually just `/usr/bin/env`) followed by `bpftrace` (so it will find bpftrace in your `$PATH`):

```
1 #!/usr/local/bin/bpftrace
2
3 tracepoint:syscalls:sys_enter_nanosleep
4 {
5   printf("%s is sleeping.\n", comm);
6 }
```

Then make it executable:

```
# chmod 755 sleepers.bt
# ./sleepers.bt
Attaching 1 probe...
iscsid is sleeping.
iscsid is sleeping.
[...]
```

## 4. `-l`: Listing Probes

Probes from the tracepoint and kprobe libraries can be listed with `-l`.

```
# bpftrace -l | more
tracepoint:xfs:xfs_attr_list_sf
tracepoint:xfs:xfs_attr_list_sf_all
tracepoint:xfs:xfs_attr_list_leaf
tracepoint:xfs:xfs_attr_list_leaf_end
[...]
# bpftrace -l | wc -l
46260
```

Other libraries generate probes dynamically, such as uprobe, and require specific ways to determine
available probes. See the later [Probes](#probes) sections.

Search terms can be added:

```
# bpftrace -l '*nanosleep*'
tracepoint:syscalls:sys_enter_clock_nanosleep
tracepoint:syscalls:sys_exit_clock_nanosleep
tracepoint:syscalls:sys_enter_nanosleep
tracepoint:syscalls:sys_exit_nanosleep
kprobe:nanosleep_copyout
kprobe:hrtimer_nanosleep
[...]
```

The `-v` option when listing tracepoints will show their arguments for use from the args builtin. For
example:

```
# bpftrace -lv tracepoint:syscalls:sys_enter_open
tracepoint:syscalls:sys_enter_open
    int __syscall_nr;
    const char * filename;
    int flags;
    umode_t mode;
```

If BTF is available, it is also possible to list struct/union/enum definitions. For example:

```
# bpftrace -lv "struct path"
struct path {
        struct vfsmount *mnt;
        struct dentry *dentry;
};
```

## 5. `-d`: Debug Output

The `-d` option produces debug output, and does not run the program. This is mostly useful for debugging
issues with bpftrace itself. You can also use `-dd` to produce a more verbose debug output, which will
also print unoptimized IR.

**If you are an end-user of bpftrace, you should not normally need the `-d` or `-v` options, and you can
skip to the [Language](#language) section.**


```
# bpftrace -d -e 'tracepoint:syscalls:sys_enter_nanosleep { printf("%s is sleeping.\n", comm); }'
Program
 tracepoint:syscalls:sys_enter_nanosleep
  call: printf
   string: %s is sleeping.\n
   builtin: comm
[...]
```

The output begins with `Program` and then an abstract syntax tree (AST) representation of the program.

Continued:

```
[...]
%printf_t = type { i64, [16 x i8] }
[...]
define i64 @"tracepoint:syscalls:sys_enter_nanosleep"(i8*) local_unnamed_addr section "s_tracepoint:syscalls:sys_enter_nanosleep" {
entry:
  %comm = alloca [16 x i8], align 1
  %printf_args = alloca %printf_t, align 8
  %1 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr inbounds [16 x i8], [16 x i8]* %comm, i64 0, i64 0
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* nonnull %3, i8 0, i64 24, i32 8, i1 false)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.memset.p0i8.i64(i8* nonnull %2, i8 0, i64 16, i32 1, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 (i8*, i64)*)([16 x i8]* nonnull %comm, i64 16)
  %4 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1, i64 0
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %4, i8* nonnull %2, i64 16, i32 1, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 24)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
[...]
```

This section shows the llvm intermediate representation (IR) assembly, which is then compiled into BPF.

## 6. `-v`: Verbose Output

The `-v` option prints more information about the program as it is run:

```
# bpftrace -v -e 'tracepoint:syscalls:sys_enter_nanosleep { printf("%s is sleeping.\n", comm); }'
Attaching 1 probe...

The verifier log:
0: (bf) r6 = r1
1: (b7) r1 = 0
2: (7b) *(u64 *)(r10 -24) = r1
3: (7b) *(u64 *)(r10 -32) = r1
4: (7b) *(u64 *)(r10 -40) = r1
5: (7b) *(u64 *)(r10 -8) = r1
6: (7b) *(u64 *)(r10 -16) = r1
7: (bf) r1 = r10
8: (07) r1 += -16
9: (b7) r2 = 16
10: (85) call bpf_get_current_comm#16
11: (79) r1 = *(u64 *)(r10 -16)
12: (7b) *(u64 *)(r10 -32) = r1
13: (79) r1 = *(u64 *)(r10 -8)
14: (7b) *(u64 *)(r10 -24) = r1
15: (18) r7 = 0xffff9044e65f1000
17: (85) call bpf_get_smp_processor_id#8
18: (bf) r4 = r10
19: (07) r4 += -40
20: (bf) r1 = r6
21: (bf) r2 = r7
22: (bf) r3 = r0
23: (b7) r5 = 24
24: (85) call bpf_perf_event_output#25
25: (b7) r0 = 0
26: (95) exit
processed 26 insns (limit 131072), stack depth 40

Attaching tracepoint:syscalls:sys_enter_nanosleep
Running...
iscsid is sleeping.
iscsid is sleeping.
[...]
```

This includes `The verifier log:` and then the log message from the in-kernel verifier.

## 7. Preprocessor Options

The `-I` option can be used to add directories to the list of directories that bpftrace uses to look for
headers. Can be defined multiple times.

```
# cat program.bt
#include <foo.h>

BEGIN { @ = FOO }

# bpftrace program.bt
definitions.h:1:10: fatal error: 'foo.h' file not found

# /tmp/include
foo.h

# bpftrace -I /tmp/include program.bt
Attaching 1 probe...
```

The `--include` option can be used to include headers by default. Can be defined multiple times. Headers
are included in the order they are defined, and they are included before any other include in the program
being executed.


```
# bpftrace --include linux/path.h --include linux/dcache.h \
    -e 'kprobe:vfs_open { printf("open path: %s\n", str(((struct path *)arg0)->dentry->d_name.name)); }'
Attaching 1 probe...
open path: .com.google.Chrome.ASsbu2
open path: .com.google.Chrome.gimc10
open path: .com.google.Chrome.R1234s
```


## 8. Other Options

- The `--version` option prints the bpftrace version:

```
# bpftrace --version
bpftrace v0.8-90-g585e-dirty
```

- The `--no-warnings` option disables warnings.

## 9. Environment Variables

### 9.1 `BPFTRACE_STRLEN`

Default: 64

Number of bytes allocated on the BPF stack for the string returned by str().

Make this larger if you wish to read bigger strings with str().

Beware that the BPF stack is small (512 bytes), and that you pay the toll again inside printf() (whilst
it composes a perf event output buffer). So in practice you can only grow this to about 200 bytes.

Support for even larger strings is [being discussed](https://github.com/iovisor/bpftrace/issues/305).

### 9.2 `BPFTRACE_NO_CPP_DEMANGLE`

Default: 0

C++ symbol demangling in userspace stack traces is enabled by default.

This feature can be turned off by setting the value of this environment variable to `1`.

### 9.3 `BPFTRACE_MAP_KEYS_MAX`

Default: 4096

This is the maximum number of keys that can be stored in a map. Increasing the value will consume more
memory and increase startup times. There are some cases where you will want to: for example, sampling
stack traces, recording timestamps for each page, etc.

### 9.4 `BPFTRACE_MAX_PROBES`

Default: 512

This is the maximum number of probes that bpftrace can attach to. Increasing the value will consume more
memory, increase startup times and can incur high performance overhead or even freeze or crash the
system.

### 9.5 `BPFTRACE_CACHE_USER_SYMBOLS`

Default: 0 if ASLR is enabled on system and `-c` option is not given; otherwise 1

By default, bpftrace caches the results of symbols resolutions only when ASLR (Address Space Layout
Randomization) is disabled. This is because the symbol addresses change with each execution with ASLR.
However, disabling caching may incur some performance. Set this env variable to 1 to force bpftrace to
cache. This is fine if only trace one program execution.

### 9.6 `BPFTRACE_VMLINUX`

Default: None

This specifies the vmlinux path used for kernel symbol resolution when attaching kprobe to offset.
If this value is not given, bpftrace searches vmlinux from pre defined locations.
See src/attached_probe.cpp:find_vmlinux() for details.

### 9.7 `BPFTRACE_BTF`

Default: None

The path to a BTF file. By default, bpftrace searches several locations to find a BTF file.
See src/btf.cpp for the details.

### 9.8 `BPFTRACE_PERF_RB_PAGES`

Default: 64

Number of pages to allocate per CPU for perf ring buffer. The value must be a power of 2.

If you're getting a lot of dropped events bpftrace may not be processing events in the ring buffer
fast enough. It may be useful to bump the value higher so more events can be queued up. The tradeoff
is that bpftrace will use more memory.

## 10. Clang Environment Variables

bpftrace parses header files using libclang, the C interface to Clang. Thus environment variables
affecting the clang toolchain can be used. For example, if header files are included from a non-default
directory, the `CPATH` or `C_INCLUDE_PATH` environment variables can be set to allow clang to locate the
files. See clang documentation for more information on these environment variables and their usage.


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

This is a one-liner invocation of bpftrace. The probe is `kprobe:do_sys_open`. When that probe "fires"
(the instrumentation event occurred) the action will be executed, which consists of a `print()`
statement. Explanations of the probe and action are in the sections that follow.

## 2. `/.../`: Filtering

Syntax: `/filter/`

Filters (also known as predicates) can be added after probe names. The probe still fires, but it will
skip the action unless the filter is true.

Examples:

```
# bpftrace -e 'kprobe:vfs_read /arg2 < 16/ { printf("small read: %d byte buffer\n", arg2); }'
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
# bpftrace -e 'kprobe:vfs_read /comm == "bash"/ { printf("read by %s\n", comm); }'
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

tracepoint example:

```
# bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
Attaching 1 probe...
snmpd /proc/diskstats
snmpd /proc/stat
snmpd /proc/vmstat
[...]
```

This is returning the `filename` member from the `args` struct, which for tracepoint probes contains the
tracepoint arguments. See the [Static Tracing, Kernel-Level
Arguments](#6-tracepoint-static-tracing-kernel-level-arguments) section for the contents of this struct.

kprobe example:

```
# cat path.bt
#include <linux/path.h>
#include <linux/dcache.h>

kprobe:vfs_open
{
	printf("open path: %s\n", str(((struct path *)arg0)->dentry->d_name.name));
}

# bpftrace path.bt
Attaching 1 probe...
open path: dev
open path: if_inet6
open path: retrans_time_ms
[...]
```

This uses dynamic tracing of the `vfs_open()` kernel function, via the short script path.bt. Some kernel
headers needed to be included to understand the `path` and `dentry` structs.

## 5. `struct`: Struct Declaration

Example:

```
// from fs/namei.c:
struct nameidata {
        struct path     path;
        struct qstr     last;
        // [...]
};
```

You can define your own structs when needed. In some cases, kernel structs are not declared in the kernel
headers package, and are declared manually in bpftrace tools (or partial structs are: enough to reach the
member to dereference).

## 6. `? :`: ternary operators

Examples:

```
# bpftrace -e 'tracepoint:syscalls:sys_exit_read { @error[args->ret < 0 ? - args->ret : 0] = count(); }'
Attaching 1 probe...
^C

@error[11]: 24
@error[0]: 78
```

```
# bpftrace -e 'BEGIN { pid & 1 ? printf("Odd\n") : printf("Even\n"); exit(); }'
Attaching 1 probe...
Odd
```

## 7. `if () {...} else {...}`: if-else statements

Example:

```
# bpftrace -e 'tracepoint:syscalls:sys_enter_read { @reads = count();
    if (args->count > 1024) { @large = count(); } }'
Attaching 1 probe...
^C
@large: 72

@reads: 80
```

## 8. `unroll () {...}`: Unroll

Example:

```
# bpftrace -e 'kprobe:do_nanosleep { $i = 1; unroll(5) { printf("i: %d\n", $i); $i = $i + 1; } }'
Attaching 1 probe...
i: 1
i: 2
i: 3
i: 4
i: 5
^C

```

## 9. `++` and `--`: Increment operators

`++` and `--` can be used to conveniently increment or decrement counters in maps or variables.

Note that maps will be implicitly declared and initialized to 0 if not already
declared or defined. Scratch variables must be initialized before using these
operators.

Example - variable:

```
bpftrace -e 'BEGIN { $x = 0; $x++; $x++; printf("x: %d\n", $x); }'
Attaching 1 probe...
x: 2
^C
```

Example - map:

```
bpftrace -e 'k:vfs_read { @++ }'
Attaching 1 probe...
^C

@: 12807
```

Example - map with key:

```
# bpftrace -e 'k:vfs_read { @[probe]++ }'
Attaching 1 probe...
^C

@[kprobe:vfs_read]: 13369
```

## 10. `[]`: Array Access

You may access one-dimensional constant arrays with the array access operator `[]`.

Example:

```
# bpftrace -e 'struct MyStruct { int y[4]; } uprobe:./testprogs/array_access:test_struct {
    $s = (struct MyStruct *) arg0; @x = $s->y[0]; exit(); }'
Attaching 1 probe...

@x: 1
```

## 11. Integer casts

Integers are internally represented as 64 bit signed. If you need another
representation, you may cast to the following built in types:

| Type     | Explanation              |
|----------|--------------------------|
| `uint8`  | unsigned 8 bit integer   |
| `int8`   | signed 8 bit integer     |
| `uint16` | unsigned 16 bit integer  |
| `int16`  | signed 16 bit integer    |
| `uint32` | unsigned 32 bit integer  |
| `int32`  | signed 32 bit integer    |
| `uint64` | unsigned 64 bit integer  |
| `int64`  | signed 64 bit integer    |

Example:

```
# bpftrace -e 'BEGIN { $x = 1<<16; printf("%d %d\n", (uint16)$x, $x); }'
Attaching 1 probe...
0 65536
^C
```

## 12. Looping Constructs

**Experimental**

Kernel: 5.3

bpftrace supports C style while loops:

```
# bpftrace -e 'i:ms:100 { $i = 0; while ($i <= 100) { printf("%d ", $i); $i++} exit(); }'
```

Loops can be short circuited by using the `continue` and `break` keywords.

## 13. `return`: Terminate Early

The `return` keyword is used to exit the current probe. This differs from
`exit()` in that it doesn't exit bpftrace.

## 14. `( , )`: Tuples

N-tuples are supported, where N is any integer greater than 1.

Indexing is supported using the `.` operator. Tuples are immutable once created.

Example:

```
# bpftrace -e 'BEGIN { $t = (1, 2, "string"); printf("%d %s\n", $t.1, $t.2); }'
Attaching 1 probe...
2 string
^C
```

# Probes

- `kprobe` - kernel function start
- `kretprobe` - kernel function return
- `uprobe` - user-level function start
- `uretprobe` - user-level function return
- `tracepoint` - kernel static tracepoints
- `usdt` - user-level static tracepoints
- `profile` - timed sampling
- `interval` - timed output
- `software` - kernel software events
- `hardware` - processor-level events

Some probe types allow wildcards to match multiple probes, eg, `kprobe:vfs_*`. You may also specify
multiple attach points for an action block using a comma separated list.

Quoted strings (eg. `uprobe:"/usr/lib/c++lib.so":foo`) may be used to escape
characters in attach point definitions.

## 1. `kprobe`/`kretprobe`: Dynamic Tracing, Kernel-Level

Syntax:

```
kprobe:function_name[+offset]
kretprobe:function_name
```

These use kprobes (a Linux kernel capability). `kprobe` instruments the beginning of a function's
execution, and `kretprobe` instruments the end (its return).

Examples:

```
# bpftrace -e 'kprobe:do_nanosleep { printf("sleep by %d\n", tid); }'
Attaching 1 probe...
sleep by 1396
sleep by 3669
sleep by 1396
sleep by 27662
sleep by 3669
^C
```

It's also possible to specify offset within the probed function:

```
# gdb -q /usr/lib/debug/boot/vmlinux-`uname -r` --ex 'disassemble do_sys_open'
Reading symbols from /usr/lib/debug/boot/vmlinux-5.0.0-32-generic...done.
Dump of assembler code for function do_sys_open:
   0xffffffff812b2ed0 <+0>:     callq  0xffffffff81c01820 <__fentry__>
   0xffffffff812b2ed5 <+5>:     push   %rbp
   0xffffffff812b2ed6 <+6>:     mov    %rsp,%rbp
   0xffffffff812b2ed9 <+9>:     push   %r15
...
# bpftrace -e 'kprobe:do_sys_open+9 { printf("in here\n"); }'
Attaching 1 probe...
in here
...
```

The address is being checked using vmlinux (with debug symbols) if it's aligned with instruction
boundaries and within the function.  If it's not, we fail to add it:
```
# bpftrace -e 'kprobe:do_sys_open+1 { printf("in here\n"); }'
Attaching 1 probe...
Could not add kprobe into middle of instruction: /usr/lib/debug/boot/vmlinux-5.0.0-32-generic:do_sys_open+1
```

If bpftrace is compiled with `ALLOW_UNSAFE_PROBE` option, you can use --unsafe option to skip the check.
In this case, linux kernel still checks instruction alignment.

The default vmlinux path can be overridden using the environment variable `BPFTRACE_VMLINUX`.

Examples in situ:
[(kprobe) search /tools](https://github.com/iovisor/bpftrace/search?q=kprobe%3A+path%3Atools&type=Code)
[(kretprobe) /tools](https://github.com/iovisor/bpftrace/search?q=kretprobe%3A+path%3Atools&type=Code)

## 2. `kprobe`/`kretprobe`: Dynamic Tracing, Kernel-Level Arguments

Syntax:

```
kprobe: arg0, arg1, ..., argN
kretprobe: retval
```

Arguments can be accessed via these variables names. `arg0` is the first argument and can only be
accessed with a `kprobe`. `retval` is the return value for the instrumented function, and can only be
accessed on `kretprobe`.

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

As an example of struct arguments:

```
# cat path.bt
#include <linux/path.h>
#include <linux/dcache.h>

kprobe:vfs_open
{
	printf("open path: %s\n", str(((struct path *)arg0)->dentry->d_name.name));
}

# bpftrace path.bt
Attaching 1 probe...
open path: dev
open path: if_inet6
open path: retrans_time_ms
[...]
```

Here arg0 was casted as a (struct path \*), since that is the first argument to vfs_open(). The struct
support is the same as bcc, and based on available kernel headers. This means that many, but not all,
structs will be available, and you may need to manually define some structs.

If the kernel has BTF (BPF Type Format) data, all kernel structs are always available without defining
them. For example:

```
# bpftrace -e 'kprobe:vfs_open { printf("open path: %s\n", \
                                 str(((struct path *)arg0)->dentry->d_name.name)); }'
Attaching 1 probe...
open path: cmdline
open path: interrupts
[...]
```

See [BTF Support](#btf-support) for more details.

Examples in situ:
[(kprobe) search /tools](https://github.com/iovisor/bpftrace/search?q=kprobe%3A+path%3Atools&type=Code)
[(kretprobe) /tools](https://github.com/iovisor/bpftrace/search?q=kretprobe%3A+path%3Atools&type=Code)

## 3. `uprobe`/`uretprobe`: Dynamic Tracing, User-Level

Syntax:

```
uprobe:library_name:function_name[+offset]
uprobe:library_name:address
uretprobe:library_name:function_name
```

These use uprobes (a Linux kernel capability). `uprobe` instruments the beginning of a user-level
function's execution, and `uretprobe` instruments the end (its return).

To list available uprobes, you can use any program to list the text segment symbols from a binary, such
as `objdump` and `nm`. For example:

```
# objdump -tT /bin/bash | grep readline
00000000007003f8 g    DO .bss	0000000000000004  Base        rl_readline_state
0000000000499e00 g    DF .text	00000000000001c5  Base        readline_internal_char
00000000004993d0 g    DF .text	0000000000000126  Base        readline_internal_setup
000000000046d400 g    DF .text	000000000000004b  Base        posix_readline_initialize
000000000049a520 g    DF .text	0000000000000081  Base        readline
[...]
```

This has listed various functions containing "readline" from /bin/bash. These can be instrumented using
`uprobe` and `uretprobe`.

Examples:

```
# bpftrace -e 'uretprobe:/bin/bash:readline { printf("read a line\n"); }'
Attaching 1 probe...
read a line
read a line
read a line
^C
```

While tracing, this has caught a few executions of the `readline()` function in /bin/bash. This example
is continued in the next section.

It's also possible to specify uprobe with virtual address, like:

```
# objdump -tT /bin/bash | grep main
...
000000000002ec00 g    DF .text  0000000000001868  Base        main
...
# bpftrace -e 'uprobe:/bin/bash:0x2ec00 { printf("in here\n"); }'
Attaching 1 probe...
```

And to specify offset within the probed function:

```
# objdump -d /bin/bash
...
000000000002ec00 <main@@Base>:
   2ec00:       f3 0f 1e fa             endbr64
   2ec04:       41 57                   push   %r15
   2ec06:       41 56                   push   %r14
   2ec08:       41 55                   push   %r13
   ...
# bpftrace -e 'uprobe:/bin/bash:main+4 { printf("in here\n"); }'
Attaching 1 probe...
...
```

The address is being checked if it's aligned with instruction boundaries.
If it's not, we fail to add it:
```
# bpftrace -e 'uprobe:/bin/bash:main+1 { printf("in here\n"); }'
Attaching 1 probe...
Could not add uprobe into middle of instruction: /bin/bash:main+1
```

If bpftrace is compiled with `ALLOW_UNSAFE_PROBE` option, you can use --unsafe option to skip the check:

```
# bpftrace -e 'uprobe:/bin/bash:main+1 { printf("in here\n"); } --unsafe'
Attaching 1 probe...
Unsafe uprobe in the middle of the instruction: /bin/bash:main+1
```

Using --unsafe option you can also place uprobes on arbitrary addresses.
This might come in handy when the binary is stripped.
```
$ echo 'int main(){return 0;}' | gcc -xc -o bin -
$ nm bin | grep main
...
0000000000001119 T main
...
$ strip bin
# bpftrace --unsafe -e 'uprobe:bin:0x1119 { printf("main called\n"); }'
Attaching 1 probe...
WARNING: could not determine instruction boundary for uprobe:bin:4377 (binary appears stripped). Misaligned probes can lead to tracee crashes!
```

Examples in situ:
[(uprobe) search /tools](https://github.com/iovisor/bpftrace/search?q=uprobe%3A+path%3Atools&type=Code)
[(uretprobe) /tools](https://github.com/iovisor/bpftrace/search?q=uretprobe%3A+path%3Atools&type=Code)

## 4. `uprobe`/`uretprobe`: Dynamic Tracing, User-Level Arguments

Syntax:

```
uprobe: arg0, arg1, ..., argN
uretprobe: retval
```

Arguments can be accessed via these variables names. `arg0` is the first argument, and can only be
accessed with a `uprobe`. `retval` is the return value for the instrumented function, and can only be
accessed on `uretprobe`.

Examples:

```
# bpftrace -e 'uprobe:/bin/bash:readline { printf("arg0: %d\n", arg0); }'
Attaching 1 probe...
arg0: 19755784
arg0: 19755016
arg0: 19755784
^C
```

What does `arg0` of `readline()` in /bin/bash contain? I don't know. I'd need to look at the bash source
code to find out what its arguments were.

```
# bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libc-2.23.so:fopen { printf("fopen: %s\n", str(arg0)); }'
Attaching 1 probe...
fopen: /proc/filesystems
fopen: /usr/share/locale/locale.alias
fopen: /proc/self/mountinfo
^C
```

In this case, I know that the first argument of libc `fopen()` is the pathname (see the fopen(3) man
page), so I've traced it using a uprobe. Adjust the path to libc to match your system (it may not be
libc-2.23.so). A `str()` call is necessary to turn the char * pointer to a string, as explained in a
later section.

```
# bpftrace -e 'uretprobe:/bin/bash:readline { printf("readline: \"%s\"\n", str(retval)); }'
Attaching 1 probe...
readline: "echo hi"
readline: "ls -l"
readline: "date"
readline: "uname -r"
^C
```

Back to the bash `readline()` example: after checking the source code, I saw that the return value was
the string read. So I can use a `uretprobe` and the `retval` variable to see the read string.

Examples in situ:
[(uprobe) search /tools](https://github.com/iovisor/bpftrace/search?q=uprobe%3A+path%3Atools&type=Code)
[(uretprobe) /tools](https://github.com/iovisor/bpftrace/search?q=uretprobe%3A+path%3Atools&type=Code)

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

Examples in situ:
[search /tools](https://github.com/iovisor/bpftrace/search?q=tracepoint%3A+path%3Atools&type=Code)

## 6. `tracepoint`: Static Tracing, Kernel-Level Arguments

Example:

```
# bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
Attaching 1 probe...
irqbalance /proc/interrupts
irqbalance /proc/stat
snmpd /proc/diskstats
snmpd /proc/stat
snmpd /proc/vmstat
snmpd /proc/net/dev
[...]
```

The available members for each tracepoint can be listed from their /format file in /sys. For example:

```
# cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
name: sys_enter_openat
ID: 608
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * filename;	offset:24;	size:8;	signed:0;
	field:int flags;	offset:32;	size:8;	signed:0;
	field:umode_t mode;	offset:40;	size:8;	signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
```

Apart from the `filename` member, we can also print `flags`, `mode`, and more. After the "common" members
listed first, the members are specific to the tracepoint.

Examples in situ:
[search /tools](https://github.com/iovisor/bpftrace/search?q=tracepoint%3A+path%3Atools&type=Code)

## 7. `usdt`: Static Tracing, User-Level

Syntax:

```
usdt:binary_path:probe_name
usdt:binary_path:[probe_namespace]:probe_name
usdt:library_path:probe_name
usdt:library_path:[probe_namespace]:probe_name
```

Where `probe_namespace` is optional if `probe_name` is unique within the binary.

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

The namespace of the probe is deduced automatically. If the binary `/root/tick` contained multiple probes
with the name `loop` (e.g. `tick:loop` and `tock:loop`), no probe would be attached.
This may be solved by manually specifying the namespace or by using a wildcard:

```
# bpftrace -e 'usdt:/root/tick:loop { printf("hi\n"); }'
ERROR: namespace for usdt:/root/tick:loop not specified, matched 2 probes
INFO: please specify a unique namespace or use '*' to attach to all matched probes
No probes to attach

# bpftrace -e 'usdt:/root/tick:tock:loop { printf("hi\n"); }'
Attaching 1 probe...
hi
hi
^C

# bpftrace -e 'usdt:/root/tick:*:loop { printf("hi\n"); }'
Attaching 2 probes...
hi
hi
hi
hi
^C
```

bpftrace also supports USDT semaphores. If both your environment and bpftrace
support uprobe refcounts, then USDT semaphores are automatically activated for
all processes upon probe attachment (and `--usdt-file-activation` becomes a
noop). You can check if your system supports uprobe refcounts by running:

```
# bpftrace --info 2>&1 | grep "uprobe refcount"
  bcc bpf_attach_uprobe refcount: yes
  uprobe refcount (depends on Build:bcc bpf_attach_uprobe refcount): yes
```

If your system does not support uprobe refcounts, you may activate semaphores by passing in `-p $PID` or
`--usdt-file-activation`. `--usdt-file-activation` looks through `/proc` to find processes that
have your probe's binary mapped with executable permissions into their address space and then tries
to attach your probe. Note that file activation occurs only once (during attach time). In other
words, if later during your tracing session a new process with your executable is spawned, your
current tracing session will not activate the new process. Also note that `--usdt-file-activation`
matches based on file path. This means that if bpftrace runs from the root host, things may not work
as expected if there are processes `execve`d from private mount namespaces or bind mounted directories.
One workaround is to run bpftrace inside the appropriate namespaces (ie the container).

## 8. `usdt`: Static Tracing, User-Level Arguments

Examples:

```
# bpftrace -e 'usdt:/root/tick:loop { printf("%s: %d\n", str(arg0), arg1); }'
my string: 1
my string: 2
my string: 3
my string: 4
my string: 5
^C
```

```
# bpftrace -e 'usdt:/root/tick:loop /arg1 > 2/ { printf("%s: %d\n", str(arg0), arg1); }'
my string: 3
my string: 4
my string: 5
my string: 6
^C
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

## 10. `interval`: Timed Output

Syntax:

```
interval:ms:rate
interval:s:rate
interval:us:rate
interval:hz:rate
```

This fires on one CPU only, and can be used for generating per-interval output.

Example:

```
# bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @syscalls = count(); }
    interval:s:1 { print(@syscalls); clear(@syscalls); }'
Attaching 2 probes...
@syscalls: 1263
@syscalls: 731
@syscalls: 891
@syscalls: 1195
@syscalls: 1154
@syscalls: 1635
@syscalls: 1208
[...]
```

This prints the rate of syscalls per second.

Examples in situ:
[search /tools](https://github.com/iovisor/bpftrace/search?q=interval+extension%3Abt+path%3Atools&type=Code)

## 11. `software`: Pre-defined Software Events

Syntax:

```
software:event_name:count
software:event_name:
```

These are the pre-defined software events provided by the Linux kernel, as commonly traced via the perf
utility. They are similar to tracepoints, but there is only about a dozen of these, and they are
documented in the perf\_event\_open(2) man page. The event names are:

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

The count is the trigger for the probe, which will fire once for every count events. If the count is not
provided, a default is used.

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

This roughly counts who is causing page faults, by sampling the process name for every one in one hundred
faults.

## 12. `hardware`: Pre-defined Hardware Events

Syntax:

```
hardware:event_name:count
hardware:event_name:
```

These are the pre-defined hardware events provided by the Linux kernel, as commonly traced by the perf
utility. They are implemented using performance monitoring counters (PMCs): hardware resources on the
processor. There are about ten of these, and they are documented in the perf\_event\_open(2) man page.
The event names are:

- `cpu-cycles` or `cycles`
- `instructions`
- `cache-references`
- `cache-misses`
- `branch-instructions` or `branches`
- `branch-misses`
- `bus-cycles`
- `frontend-stalls`
- `backend-stalls`
- `ref-cycles`

The count is the trigger for the probe, which will fire once for every count events. If the count is not
provided, a default is used.

Examples:

```
bpftrace -e 'hardware:cache-misses:1000000 { @[pid] = count(); }'
```

That would fire once for every 1000000 cache misses. This usually indicates the last level cache (LLC).

## 13. `BEGIN`/`END`: Built-in events

Syntax:

```
BEGIN
END
```

These are special built-in events provided by the bpftrace runtime. `BEGIN` is triggered before all other
probes are attached. `END` is triggered after all other probes are detached.

Examples in situ:
[(BEGIN) search /tools](https://github.com/iovisor/bpftrace/search?q=BEGIN+extension%3Abt+path%3Atools&type=Code)
[(END) search /tools](https://github.com/iovisor/bpftrace/search?q=END+extension%3Abt+path%3Atools&type=Code)

## 14. `watchpoint`/`asyncwatchpoint`: Memory watchpoints

**WARNING**: this feature is experimental and may be subject to interface changes. Memory watchpoints are
also architecture dependant

Syntax:

```
watchpoint:absolute_address:length:mode
watchpoint:function+argN:length:mode
```

These are memory watchpoints provided by the kernel. Whenever a memory address is written to (`w`), read
from (`r`), or executed (`x`), the kernel can generate an event.

In the first form, an absolute address is monitored. If a pid (`-p`) or a command (`-c`) is provided,
bpftrace takes the address as a userspace address and monitors the appropriate process. If not,
bpftrace takes the address as a kernel space address.

In the second form, the address present in `argN` (see [uprobe
arguments](#4-uprobeuretprobe-dynamic-tracing-user-level-arguments)) when `function` is entered is
monitored. A pid or command must be provided for this form. If synchronous (`watchpoint`), a
`SIGSTOP` is sent to the tracee upon function entry. The tracee will be `SIGCONT`d after the
watchpoint is attached. This is to ensure events are not missed. If you want to avoid the
`SIGSTOP` + `SIGCONT` use `asyncwatchpoint`.

Note that on most architectures you may not monitor for execution while monitoring read or write.

Examples:

```
bpftrace -e 'watchpoint:0x10000000:8:rw { printf("hit!\n"); exit(); }' -c ./testprogs/watchpoint
```

It will output "hit" and exit when the watchpoint process is trying to read or write 0x10000000.

```
# bpftrace -e "watchpoint:0x$(awk '$3 == "jiffies" {print $1}' /proc/kallsyms):8:w {@[kstack] = count();}"
Attaching 1 probe...
^C
......
@[
    do_timer+12
    tick_do_update_jiffies64.part.22+89
    tick_sched_do_timer+103
    tick_sched_timer+39
    __hrtimer_run_queues+256
    hrtimer_interrupt+256
    smp_apic_timer_interrupt+106
    apic_timer_interrupt+15
    cpuidle_enter_state+188
    cpuidle_enter+41
    do_idle+536
    cpu_startup_entry+25
    start_secondary+355
    secondary_startup_64+164
]: 319
```

It shows the kernel stacks in which jiffies is updated.

```
# cat wpfunc.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline))
void increment(__attribute__((unused)) int _, int *i)
{
  (*i)++;
}

int main()
{
  int *i = malloc(sizeof(int));
  while (1)
  {
    increment(0, i);
    (*i)++;
    usleep(1000);
  }
}

# bpftrace -e 'watchpoint:increment+arg1:4:w { printf("hit!\n"); exit() }' -c ./wpfunc
```

bpftrace will output "hit" and exit when the memory pointed to by `arg1` of `increment` is
written.

## 15. `kfunc`/`kretfunc`: Kernel Functions Tracing

Syntax:

```
kfunc:function
kretfunc:function
```

These are kernel function probes implemented via eBPF trampolines which allows
kernel code to call into BPF programs with practically zero overhead.

Examples:

```
# bpftrace -e 'kfunc:x86_pmu_stop { printf("pmu %s stop\n", str(args->event->pmu->name)); }'
# bpftrace -e 'kretfunc:fget { printf("fd %d name %s\n", args->fd, str(retval->f_path.dentry->d_name.name));  }'
```

You can get list of available functions via list option:

```
# bpftrace -l
...
kfunc:ksys_ioperm
kfunc:ksys_unshare
kfunc:ksys_setsid
kfunc:ksys_sync_helper
kfunc:ksys_fadvise64_64
kfunc:ksys_readahead
kfunc:ksys_mmap_pgoff
...
```

## 16. `kfunc`/`kretfunc`: Kernel Functions Tracing Arguments

Syntax:

```
kfunc:function      args->NAME  ...
kretfunc:function   args->NAME ... retval
```

Arguments can be accessed via args being dereferenced to argument's `NAME`.
Return value can be referenced by `retval` builtin, see the [1. Builtins](#1-builtins).

It's possible to get available argument names for function via verbose list option:

```
# bpftrace -lv
...
kfunc:fget
    unsigned int fd;
    struct file * retval;
...
```

The `fget` function takes one argument as file descriptor and
you can access it via `args->fd` in `kfunc:fget` probe:

```
# bpftrace -e 'kfunc:fget { printf("fd %d\n", args->fd);  }'
Attaching 1 probe...
fd 3
fd 3
...
```

The return value of `fget` function probe is accessible via `retval`:

```
# bpftrace -e 'kretfunc:fget { printf("fd %d name %s\n", args->fd, str(retval->f_path.dentry->d_name.name));  }'
Attaching 1 probe...
fd 3 name ld.so.cache
fd 3 name libselinux.so.1
fd 3 name libselinux.so.1
...
```
And as you can see in above example it's also possible to access function arguments on `kretfunc` probes.

## 17. `iter`: Iterators Tracing

**WARNING**: this feature is experimental and may be subject to interface changes.

Syntax:

```
iter:task[:pin]
iter:task_file[:pin]
```

Kernel: 5.4

These are eBPF iterator probes, that allows iteration over kernel objects.

Iterator probe can't be mixed with any other probe, not even other iterator.

Each iterator probe provides set of fields that could be accessed with
ctx pointer. User can display set of available fields for iterator via
-lv options as described below.

Examples:

```
# bpftrace -e 'iter:task { printf("%s:%d\n", ctx->task->comm, ctx->task->pid); }'
Attaching 1 probe...
systemd:1
kthreadd:2
rcu_gp:3
rcu_par_gp:4
kworker/0:0H:6
mm_percpu_wq:8
...

# bpftrace -e 'iter:task_file { printf("%s:%d %d:%s\n", ctx->task->comm, ctx->task->pid, ctx->fd, path(ctx->file->f_path)); }'
Attaching 1 probe...
systemd:1 1:/dev/null
systemd:1 2:/dev/null
systemd:1 3:/dev/kmsg
...
su:1622 1:/dev/pts/1
su:1622 2:/dev/pts/1
su:1622 3:/var/lib/sss/mc/passwd
...
bpftrace:1892 1:pipe:[35124]
bpftrace:1892 2:/dev/pts/1
bpftrace:1892 3:anon_inode:bpf-map
bpftrace:1892 4:anon_inode:bpf-map
bpftrace:1892 5:anon_inode:bpf_link
bpftrace:1892 6:anon_inode:bpf-prog
bpftrace:1892 7:anon_inode:bpf_iter
```

You can get list of available functions via list option:

```
# bpftrace -l iter:*
iter:task
iter:task_file

# bpftrace -l iter:* -v
iter:task
    struct task_struct *task;
iter:task_file
    struct task_struct *task;
    int fd;
    struct file *file;
```

It's possible to pin iterator with specifying optional probe ':pin' part,
that defines the pin file. It can be specified as absolute path or relative
to /sys/fs/bpf.

Examples with relative pin file:

```
# bpftrace -e 'iter:task:list { printf("%s:%d\n", ctx->task->comm, ctx->task->pid); }'
Attaching 1 probe...
Program pinned to /sys/fs/bpf/list


# cat /sys/fs/bpf/list
systemd:1
kthreadd:2
rcu_gp:3
rcu_par_gp:4
kworker/0:0H:6
mm_percpu_wq:8
rcu_tasks_kthre:9
...
```

Examples with absolute pin file:

```
# bpftrace -e 'iter:task_file:/sys/fs/bpf/files { printf("%s:%d %s\n", ctx->task->comm, ctx->task->pid, path(ctx->file->f_path)); }'
Attaching 1 probe...
Program pinned to /sys/fs/bpf/files

# cat /sys/fs/bpf/files
systemd:1 anon_inode:inotify
systemd:1 anon_inode:[timerfd]
...
systemd-journal:849 /dev/kmsg
systemd-journal:849 anon_inode:[eventpoll]
...
sssd:1146 /var/log/sssd/sssd.log
sssd:1146 anon_inode:[eventpoll]
...
NetworkManager:1155 anon_inode:[eventfd]
NetworkManager:1155 /var/lib/sss/mc/passwd (deleted)

```

# Variables

## 1. Builtins

- `pid` - Process ID (kernel tgid)
- `tid` - Thread ID (kernel pid)
- `uid` - User ID
- `gid` - Group ID
- `nsecs` - Nanosecond timestamp
- `elapsed` - Nanoseconds since bpftrace initialization
- `cpu` - Processor ID
- `comm` - Process name
- `kstack` - Kernel stack trace
- `ustack` - User stack trace
- `arg0`, `arg1`, ..., `argN`. - Arguments to the traced function; assumed to be 64 bits wide
- `sarg0`, `sarg1`, ..., `sargN`. - Arguments to the traced function (for programs that store arguments
  on the stack); assumed to be 64 bits wide
- `retval` - Return value from traced function
- `func` - Name of the traced function
- `probe` - Full name of the probe
- `curtask` - Current task struct as a u64
- `rand` - Random number as a u32
- `cgroup` - Cgroup ID of the current process
- `cpid` - Child pid(u32), only valid with the `-c command` flag
- `$1`, `$2`, ..., `$N`, `$#`. - Positional parameters for the bpftrace program

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
    kprobe:do_nanosleep /@start != 0/ { printf("at %d ms: sleep\n", (nsecs - @start) / 1000000); }'
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
# bpftrace -e 'kprobe:do_nanosleep { @start[tid] = nsecs; }
    kretprobe:do_nanosleep /@start[tid] != 0/ {
        printf("slept for %d ms\n", (nsecs - @start[tid]) / 1000000); delete(@start[tid]); }'
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
# bpftrace -e 'kprobe:do_nanosleep { @start[tid] = nsecs; }
    kretprobe:do_nanosleep /@start[tid] != 0/ { $delta = nsecs - @start[tid];
        printf("slept for %d ms\n", $delta / 1000000); delete(@start[tid]); }'
Attaching 2 probes...
slept for 1000 ms
slept for 1000 ms
slept for 1000 ms
```

## 3. `@[]`: Associative Arrays

Syntax:
```
@associative_array_name[key_name] = value
@associative_array_name[key_name, key_name2, ...] = value
```

These are implemented using BPF maps.

For example, `@start[tid]`:

```
# bpftrace -e 'kprobe:do_nanosleep { @start[tid] = nsecs; }
    kretprobe:do_nanosleep /@start[tid] != 0/ {
        printf("slept for %d ms\n", (nsecs - @start[tid]) / 1000000); delete(@start[tid]); }'
Attaching 2 probes...
slept for 1000 ms
slept for 1000 ms
slept for 1000 ms
[...]
```

```
# bpftrace -e 'BEGIN { @[1,2] = 3; printf("%d\n", @[1,2]); clear(@); }'
Attaching 1 probe...
3
^C
```

## 4. `count()`: Frequency Counting

This is provided by the count() function: see the [Count](#2-count-count) section.

## 5. `hist()`, `lhist()`: Histograms

These are provided by the hist() and lhist() functions. See the [Log2 Histogram](#8-hist-log2-histogram)
and [Linear Histogram](#9-lhist-linear-histogram) sections.

## 6. `nsecs`: Timestamps and Time Deltas

Syntax: `nsecs`

These are implemented using bpf_ktime_get_ns().

Examples:

```
# bpftrace -e 'BEGIN { @start = nsecs; }
    kprobe:do_nanosleep /@start != 0/ { printf("at %d ms: sleep\n", (nsecs - @start) / 1000000); }'
Attaching 2 probes...
at 437 ms: sleep
at 647 ms: sleep
at 1098 ms: sleep
at 1438 ms: sleep
^C
```

## 7. `kstack`: Stack Traces, Kernel

Syntax: `kstack`

This builtin is an alias to [`kstack()`](#15-kstack-stack-traces-kernel).

Examples:

```
# bpftrace -e 'kprobe:ip_output { @[kstack] = count(); }'
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

This builtin is an alias to [`ustack()`](#16-ustack-stack-traces-user).

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

## 9. `$1`, ..., `$N`, `$#`: Positional Parameters

Syntax: `$1`, `$2`, ..., `$N`, `$#`

These are the positional parameters to the bpftrace program, also referred to as command line arguments.
If the parameter is numeric (entirely digits), it can be used as a number. If it is non-numeric, it must
be used as a string in the `str()` call. If a parameter is used that was not provided, it will default to
zero for numeric context, and "" for string context. Positional parameters may also be used in probe
argument and will be treated as a string parameter.

If a positional parameter is used in `str()`, it is interpreted as a pointer to the actual given string
literal, which allows to do pointer arithmetic on it. Only addition of a single constant, less or equal to
the length of the supplied string, is allowed.

`$#` returns the number of positional arguments supplied.

This allows scripts to be written that use basic arguments to change their behavior. If you develop a
script that requires more complex argument processing, it may be better suited for bcc instead, which
supports Python's argparse and completely custom argument processing.

One-liner examples:

```
# bpftrace -e 'BEGIN { printf("I got %d, %s (%d args)\n", $1, str($2), $#); }' 42 "hello"
Attaching 1 probe...
I got 42, hello (2 args)

# bpftrace -e 'BEGIN { printf("%s\n", str($1 + 1)) }' "hello"
Attaching 1 probe...
ello
```

Script example, bsize.d:

```
#!/usr/local/bin/bpftrace

BEGIN
{
	printf("Tracing block I/O sizes > %d bytes\n", $1);
}

tracepoint:block:block_rq_issue
/args->bytes > $1/
{
	@ = hist(args->bytes);
}
```

When run with a 65536 argument:

```
# ./bsize.bt 65536
Attaching 2 probes...
Tracing block I/O sizes > 65536 bytes
^C

@:
[512K, 1M)             1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

```

It has passed the argument in as $1, and used it as a filter.

With no arguments, $1 defaults to zero:

```
# ./bsize.bt
Attaching 2 probes...
Tracing block I/O sizes > 0 bytes
^C

@:
[4K, 8K)             115 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[8K, 16K)             35 |@@@@@@@@@@@@@@@                                     |
[16K, 32K)             5 |@@                                                  |
[32K, 64K)             3 |@                                                   |
[64K, 128K)            1 |                                                    |
[128K, 256K)           0 |                                                    |
[256K, 512K)           0 |                                                    |
[512K, 1M)             1 |                                                    |
```

# Functions

## 1. Builtins

- `printf(char *fmt, ...)` - Print formatted
- `time(char *fmt)` - Print formatted time
- `join(char *arr[] [, char *delim])` - Print the array
- `str(char *s [, int length])` - Returns the string pointed to by s
- `buf(void *d [, int length])` - Returns a hex-formatted string of the data pointed to by d
- `ksym(void *p)` - Resolve kernel address
- `usym(void *p)` - Resolve user space address
- `kaddr(char *name)` - Resolve kernel symbol name
- `uaddr(char *name)` - Resolve user-level symbol name
- `reg(char *name)` - Returns the value stored in the named register
- `system(char *fmt)` - Execute shell command
- `exit()` - Quit bpftrace
- `cgroupid(char *path)` - Resolve cgroup ID
- `kstack([StackMode mode, ][int level])` - Kernel stack trace
- `ustack([StackMode mode, ][int level])` - User stack trace
- `ntop([int af, ]int|char[4|16] addr)` - Convert IP address data to text
- `cat(char *filename)` - Print file content
- `signal(char[] signal | u32 signal)` - Send a signal to the current task
- `strncmp(char *s1, char *s2, int length)` - Compare first n characters of two strings
- `override(u64 rc)` - Override return value
- `buf(void *d [, length])` - Hex-format a buffer
- `sizeof(...)` - Return size of a type or expression
- `print(...)` - Print a non-map value with default formatting
- `strftime(char *format, int nsecs)` - Return a formatted timestamp
- `path(struct path *path)` - Return full path
- `uptr(void *p)` - Annotate as userspace pointer
- `kptr(void *p)` - Annotate as kernelspace pointer
- `macaddr(char[6] addr)` - Convert MAC address data

Some of these are asynchronous: the kernel queues the event, but some time later (milliseconds) it is
processed in user-space. The asynchronous actions are: `printf()`, `time()`, and `join()`. Both `ksym()`
and `usym()`, as well as the variables `kstack` and `ustack`, record addresses synchronously, but then do
symbol translation asynchronously.

A selection of these are discussed in the following sections.

## 2. `printf()`: Printing

Syntax: `printf(fmt, args)`

This behaves like printf() from C and other languages, with a limited set of format characters. Example:

```
# bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s called %s\n", comm, str(args->filename)); }'
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
# bpftrace -e 'kprobe:do_nanosleep { time("%H:%M:%S\n"); }'
07:11:03
07:11:09
^C
```

If a format string is not provided, it defaults to "%H:%M:%S\n".

Note that this builtin is asynchronous. The printed timestamp is the time at
which userspace has processed the queued up event, _not_ the time at which the
bpf prog calls `time()`. For a more precise timestamp, see
[strftime()](#24-strftime-formatted-timestamp).

## 4. `join()`: Join

Syntax: `join(char *arr[] [, char *delim])`

This joins the array of strings with a space character, and prints it out, separated by delimiters. The
default delimiter, if none is provided, is the space character. This current version does not return a
string, so it cannot be used as an argument in printf(). Example:

```
# bpftrace -e 'tracepoint:syscalls:sys_enter_execve { join(args->argv); }'
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
```
# bpftrace -e 'tracepoint:syscalls:sys_enter_execve { join(args->argv, ","); }'
Attaching 1 probe...
ls,--color=auto
man,ls
preconv,-e,UTF-8
preconv,-e,UTF-8
preconv,-e,UTF-8
preconv,-e,UTF-8
preconv,-e,UTF-8
tbl
[...]
```

## 5. `str()`: Strings

Syntax: `str(char *s [, int length])`

Returns the string pointed to by s. `length` can be used to limit the size of the read, and/or introduce
a null-terminator. By default, the string will have size 64 bytes (tuneable using [env var
`BPFTRACE_STRLEN`](#91-bpftrace_strlen)).

Examples:

We can take the `args->filename` of `sys_enter_execve` (a `const char *filename`), and read the string to
which it points. This string can be provided as an argument to printf():

```
# bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s called %s\n", comm, str(args->filename)); }'
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

We can trace strings that are displayed in a bash shell. Some length tuning is employed, because:

- sys_enter_write()'s `args->buf` does not point to null-terminated strings
  - we use the length parameter to limit how many bytes to read of the pointed-to string
- sys_enter_write()'s `args->buf` contains messages larger than 64 bytes
  - we increase BPFTRACE_STRLEN to accommodate the large messages

```
# BPFTRACE_STRLEN=200 bpftrace -e 'tracepoint:syscalls:sys_enter_write /pid == 23506/
    { printf("<%s>\n", str(args->buf, args->count)); }'
# type pwd into terminal 23506
<p>
<w>
<d>
# press enter in terminal 23506
<
>
</home/anon
>
<anon@anon-VirtualBox:~$ >
```

## 6. `ksym()`: Symbol resolution, kernel-level

Syntax: `ksym(addr)`

Examples:

```
# bpftrace -e 'kprobe:do_nanosleep { printf("%s\n", ksym(reg("ip"))); }'
Attaching 1 probe...
do_nanosleep
do_nanosleep
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

## 8. `kaddr()`: Address resolution, kernel-level

Syntax: `kaddr(char *name)`

Examples:

```
# bpftrace -e 'BEGIN { printf("%s\n", str(*kaddr("usbcore_name"))); }'
Attaching 1 probe...
usbcore
^C
```

This is printing the `usbcore_name` string from drivers/usb/core/usb.c:

```
const char *usbcore_name = "usbcore";
```

## 9. `uaddr()`: Address resolution, user-level

Syntax:
- `u64 *uaddr(symbol)` (default)
- `u64 *uaddr(symbol)`
- `u32 *uaddr(symbol)`
- `u16 *uaddr(symbol)`
- `u8  *uaddr(symbol)`

Supported Probe Types:
- u(ret)probes
- USDT

**Does not work with ASLR, see issue [#75](https://github.com/iovisor/bpftrace/issues/75)**

The `uaddr` function returns the address of the specified symbol. This lookup
happens during program compilation and cannot be used dynamically.

The default return type is `u64*`. If the ELF object size matches a known
integer size (1, 2, 4 or 8 bytes) the return type is modified to match the width
(`u8*`, `u16*`, `u32*` or `u64*` resp.). As ELF does not contain type info the
type is always assumed to be unsigned.

Examples:

```
# bpftrace -e 'uprobe:/bin/bash:readline { printf("PS1: %s\n", str(*uaddr("ps1_prompt"))); }'
Attaching 1 probe...
PS1: \[\e[34;1m\]\u@\h:\w>\[\e[0m\]
PS1: \[\e[34;1m\]\u@\h:\w>\[\e[0m\]
^C
```

This is printing the `ps1_prompt` string from /bin/bash, whenever a `readline()`
function is executed.

## 10. `reg()`: Registers

Syntax: `reg(char *name)`

Examples:

```
# bpftrace -e 'kprobe:tcp_sendmsg { @[ksym(reg("ip"))] = count(); }'
Attaching 1 probe...
^C

@[tcp_sendmsg]: 7
```

See src/arch/x86_64.cpp for the register name list.

## 11. `system()`: System

Syntax: `system(fmt)`

This runs the provided command at the shell. For example:

```
# bpftrace --unsafe -e 'kprobe:do_nanosleep { system("ps -p %d\n", pid); }'
Attaching 1 probe...
  PID TTY          TIME CMD
 1339 ?        00:00:15 iscsid
  PID TTY          TIME CMD
 1339 ?        00:00:15 iscsid
  PID TTY          TIME CMD
 1518 ?        00:01:07 irqbalance
  PID TTY          TIME CMD
 1339 ?        00:00:15 iscsid
^C
```

This can be useful to execute commands or a shell script when an instrumented event happens.

Note this is an unsafe function. To use it, bpftrace must be run with `--unsafe`.

## 12. `exit()`: Exit

Syntax: `exit()`

This exits bpftrace, and can be combined with an interval probe to record statistics for a certain
duration. Example:

```
# bpftrace -e 'kprobe:do_sys_open { @opens = count(); } interval:s:1 { exit(); }'
Attaching 2 probes...
@opens: 119
```

## 13. `cgroupid()`: Resolve cgroup ID

Syntax: `cgroupid(char *path)`

This returns a cgroup ID of a specific cgroup, and can be combined with the `cgroup` builtin to filter
the tasks that belong to the specific cgroup, for example:

```
# bpftrace -e 'tracepoint:syscalls:sys_enter_openat /cgroup == cgroupid("/sys/fs/cgroup/unified/mycg")/
    { printf("%s\n", str(args->filename)); }':
Attaching 1 probe...
/etc/ld.so.cache
/lib64/libc.so.6
/usr/lib/locale/locale-archive
/etc/shadow
^C
```

And in other terminal:

```
# echo $$ > /sys/fs/cgroup/unified/mycg/cgroup.procs
# cat /etc/shadow
```

## 14. `ntop()`: Convert IP address data to text

Syntax: `ntop([int af, ]int|char[4|16] addr)`

This returns the string representation of an IPv4 or IPv6 address. ntop will infer the address type (IPv4
or IPv6) based on the `addr` type and size. If an integer or `char[4]` is given, ntop assumes IPv4, if a
`char[16]` is given, ntop assumes IPv6. You can also pass the address type explicitly as the first
parameter.

Examples:

A simple example of ntop with an ipv4 hex-encoded literal:

```
bpftrace -e 'BEGIN { printf("%s\n", ntop(0x0100007f));}'
127.0.0.1
^C
```

Same example as before, but passing the address type explicitly to ntop:

```
bpftrace -e '#include <linux/socket.h>
BEGIN { printf("%s\n", ntop(AF_INET, 0x0100007f));}'
127.0.0.1
^C
```

A less trivial example of this usage, tracing tcp state changes, and printing the destination IPv6
address:

```
bpftrace -e 'tracepoint:tcp:tcp_set_state { printf("%s\n", ntop(args->daddr_v6)) }'
Attaching 1 probe...
::ffff:216.58.194.164
::ffff:216.58.194.164
::ffff:216.58.194.164
::ffff:216.58.194.164
::ffff:216.58.194.164
^C
```

And initiate a connection to this (or any) address in another terminal:

```
curl www.google.com
```

## 15. `kstack()`: Stack Traces, Kernel

Syntax: `kstack([StackMode mode, ][int limit])`

These are implemented using BPF stack maps.

Examples:

```
# bpftrace -e 'kprobe:ip_output { @[kstack()] = count(); }'
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

Sampling only three frames from the stack (limit = 3):

```
# bpftrace -e 'kprobe:ip_output { @[kstack(3)] = count(); }'
Attaching 1 probe...
[...]
@[
    ip_output+1
    tcp_transmit_skb+1308
    tcp_write_xmit+482
]: 22186
```

You can also choose a different output format. Available formats are `bpftrace` and `perf`:

```
# bpftrace -e 'kprobe:do_mmap { @[kstack(perf)] = count(); }'
Attaching 1 probe...
[...]
@[
	ffffffffb4019501 do_mmap+1
	ffffffffb401700a sys_mmap_pgoff+266
	ffffffffb3e334eb sys_mmap+27
	ffffffffb3e03ae3 do_syscall_64+115
	ffffffffb4800081 entry_SYSCALL_64_after_hwframe+61

]: 22186
```

It's also possible to use a different output format and limit the number of frames:

```
# bpftrace -e 'kprobe:do_mmap { @[kstack(perf, 3)] = count(); }'
Attaching 1 probe...
[...]
@[
	ffffffffb4019501 do_mmap+1
	ffffffffb401700a sys_mmap_pgoff+266
	ffffffffb3e334eb sys_mmap+27

]: 22186
```

## 16. `ustack()`: Stack Traces, User

Syntax: `ustack([StackMode mode, ][int limit])`

These are implemented using BPF stack maps.

Examples:

```
# bpftrace -e 'kprobe:do_sys_open /comm == "bash"/ { @[ustack()] = count(); }'
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

Sampling only six frames from the stack (limit = 6):

```
# bpftrace -e 'kprobe:do_sys_open /comm == "bash"/ { @[ustack(6)] = count(); }'
Attaching 1 probe...
^C

@[
    __open_nocancel+65
    command_word_completion_function+3604
    rl_completion_matches+370
    bash_default_completion+540
    attempt_shell_completion+2092
    gen_completion_matches+82
]: 27
```

You can also choose a different output format. Available formats are `bpftrace` and `perf`:

```
# bpftrace -e 'uprobe:bash:readline { printf("%s\n", ustack(perf)); }'
Attaching 1 probe...

	5649feec4090 readline+0 (/home/mmarchini/bash/bash/bash)
	5649fee2bfa6 yy_readline_get+451 (/home/mmarchini/bash/bash/bash)
	5649fee2bdc6 yy_getc+13 (/home/mmarchini/bash/bash/bash)
	5649fee2cd36 shell_getc+469 (/home/mmarchini/bash/bash/bash)
	5649fee2e527 read_token+251 (/home/mmarchini/bash/bash/bash)
	5649fee2d9e2 yylex+192 (/home/mmarchini/bash/bash/bash)
	5649fee286fd yyparse+777 (/home/mmarchini/bash/bash/bash)
	5649fee27dd6 parse_command+54 (/home/mmarchini/bash/bash/bash)

```

It's also possible to use a different output format and limit the number of frames:

```
# bpftrace -e 'uprobe:bash:readline { printf("%s\n", ustack(perf, 3)); }'
Attaching 1 probe...

	5649feec4090 readline+0 (/home/mmarchini/bash/bash/bash)
	5649fee2bfa6 yy_readline_get+451 (/home/mmarchini/bash/bash/bash)
	5649fee2bdc6 yy_getc+13 (/home/mmarchini/bash/bash/bash)
```

Note that for these examples to work, bash had to be recompiled with frame pointers.

## 17. `cat()`: Print file content

Syntax: `cat(filename)`

This prints the file content. For example:

```
# bpftrace -e 't:syscalls:sys_enter_execve { printf("%s ", str(args->filename)); cat("/proc/loadavg"); }'
Attaching 1 probe...
/usr/libexec/grepconf.sh 3.18 2.90 2.94 2/977 30138
/usr/bin/grep 3.18 2.90 2.94 4/978 30139
/usr/bin/flatpak 3.18 2.90 2.94 2/980 30143
/usr/bin/grep 3.18 2.90 2.94 3/977 30144
/usr/bin/sed 3.18 2.90 2.94 7/978 30146
/usr/bin/tclsh 3.18 2.90 2.94 5/978 30150
/usr/bin/manpath 3.18 2.90 2.94 2/978 30152
/bin/ps 3.18 2.90 2.94 2/979 30155
^C
```

The `cat()` builtin also supports a format string as argument:

```
./bpftrace -e 'tracepoint:syscalls:sys_enter_sendmsg { printf("%s => ", comm);
    cat("/proc/%d/cmdline", pid); printf("\n") }'
Attaching 1 probe...
Gecko_IOThread => /usr/lib64/firefox/firefox
Gecko_IOThread => /usr/lib64/firefox/firefox
Gecko_IOThread => /usr/lib64/firefox/firefox
Gecko_IOThread => /usr/lib64/firefox/firefox
Gecko_IOThread => /usr/lib64/firefox/firefox
Gecko_IOThread => /usr/lib64/firefox/firefox
Gecko_IOThread => /usr/lib64/firefox/firefox
^C
```

## 18. `signal()`: Send a signal to current task

Syntax:
- `signal(u32 signal)`
- `signal("SIG")`

Kernel: 5.3

Supported Probe Types:
- k(ret)probes
- u(ret)probes
- USDT
- profile

`signal` sends the specified signal to the current task:

```
# bpftrace  -e 'kprobe:__x64_sys_execve /comm == "bash"/ { signal(5); }' --unsafe
$ ls
Trace/breakpoint trap (core dumped)
```

The signal can also be specified using a name, similar to the `kill(1)` command:

```
# bpftrace -e 'k:f { signal("KILL"); }'
# bpftrace -e 'k:f { signal("SIGINT"); }'
```

## 19. `strncmp()`: Compare first n characters of two strings

Syntax: `strncmp(char *s1, char *s2, int length)`

Return zero if the first `length` characters in `s1` and `s2` are equal, and non-zero otherwise.

Examples:

```
bpftrace -e 't:syscalls:sys_enter_* /strncmp("mpv", comm, 3) == 0/ { @[comm, probe] = count() }'
Attaching 320 probes...
[...]
@[mpv/vo, tracepoint:syscalls:sys_enter_rt_sigaction]: 238
@[mpv:gdrv0, tracepoint:syscalls:sys_enter_futex]: 680
@[mpv/ao, tracepoint:syscalls:sys_enter_write]: 1022
@[mpv, tracepoint:syscalls:sys_enter_ioctl]: 2677
@[mpv:cs0, tracepoint:syscalls:sys_enter_ioctl]: 2889
@[mpv/vo, tracepoint:syscalls:sys_enter_read]: 2993
@[mpv/demux, tracepoint:syscalls:sys_enter_futex]: 4745
@[mpv, tracepoint:syscalls:sys_enter_write]: 6936
@[mpv/vo, tracepoint:syscalls:sys_enter_futex]: 7662
@[mpv:cs0, tracepoint:syscalls:sys_enter_futex]: 8127
@[mpv/lua script , tracepoint:syscalls:sys_enter_futex]: 10150
@[mpv/vo, tracepoint:syscalls:sys_enter_poll]: 10241
@[mpv/vo, tracepoint:syscalls:sys_enter_recvmsg]: 15018
@[mpv, tracepoint:syscalls:sys_enter_getpid]: 31178
@[mpv, tracepoint:syscalls:sys_enter_futex]: 403868
```

## 20. `override()`: Override return value

Syntax: `override(u64 rc)`

Kernel: 4.16

Supported Probe Types: kprobes

The probed function will not be executed, instead a helper will be executed
that will just return `rc`.

```
# bpftrace -e 'k:__x64_sys_getuid /comm == "id"/ { override(2<<21); }' --unsafe -c id
uid=4194304 gid=0(root) euid=0(root) groups=0(root)
```

This feature only works on kernels compiled with `CONFIG_BPF_KPROBE_OVERRIDE`
and only works on functions tagged `ALLOW_ERROR_INJECTION`.

bpftrace does not test whether error injection is allowed for the probed
function, instead if will fail to load the program into the kernel:

```
ioctl(PERF_EVENT_IOC_SET_BPF): Invalid argument
Error attaching probe: 'kprobe:vfs_read'
```

## 21. `buf()`: Buffers

Syntax: `buf(void *d [, int length])`

Returns a hex-formatted string of the data pointed to by `d` that is safe to print. Because the
length of the buffer cannot always be inferred, the `length` parameter may be provided to
limit the number of bytes that are read. By default, the maximum number of bytes is 64, but this can
be tuned using the [`BPFTRACE_STRLEN`](#91-bpftrace_strlen) environment variable.

For example, we can take the `buff` parameter (`void *`) of `sys_enter_sendto`, read the
number of bytes specified by `len` (`size_t`), and format the bytes in hexadecimal so that
they don't corrupt the terminal display. The resulting string can be provided as an argument to
printf() using the `%r` format specifier:

```
# bpftrace -e 'tracepoint:syscalls:sys_enter_sendto
    { printf("Datagram bytes: %r\n", buf(args->buff, args->len)); }' -c 'ping 8.8.8.8 -c1'
Attaching 1 probe...
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
Datagram bytes: \x08\x00+\xb9\x06b\x00\x01Aen^\x00\x00\x00\x00KM\x0c\x00\x00\x00\x00\x00\x10\x11
\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&'()*+,-./01234567
64 bytes from 8.8.8.8: icmp_seq=1 ttl=52 time=19.4 ms

--- 8.8.8.8 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 19.426/19.426/19.426/0.000 ms
```

## 22. `sizeof()`: Size of type or expression

Syntax:
- `sizeof(TYPE)`
- `sizeof(EXPRESSION)`

Returns size of the argument in bytes. Similar to C/C++ `sizeof` operator. Note
that the expression does not get evaluated.

Examples:

```
# bpftrace -e 'struct Foo { int x; char c; } BEGIN { printf("%d\n", sizeof(struct Foo)); }'
Attaching 1 probe...
8

# bpftrace -e 'struct Foo { int x; char c; } BEGIN { printf("%d\n", sizeof(((struct Foo)0).c)); }'
Attaching 1 probe...
1

# bpftrace -e 'BEGIN { printf("%d\n", sizeof(1 == 1)); }'
Attaching 1 probe...
8

# bpftrace -e 'BEGIN { printf("%d\n", sizeof(struct task_struct)); }'
Attaching 1 probe...
13120

# bpftrace -e 'BEGIN { $x = 3; printf("%d\n", sizeof($x)); }'
Attaching 1 probe...
8
```

## 23. `print()`: Print Value

Syntax: ```print(value)```

The `print()` function can print a non-map value with default formatting.

For example, local variables and most builtins can be printed:

```
# bpftrace -e 'BEGIN { $t = (1, "string"); print(123); print($t); print(comm) }'
Attaching 1 probe...
123
(1, string)
bpftrace
^C
```

It is important to note that printing values is different than printing maps.
Both printing maps and printing values are asynchronous: the kernel queues the
event but some time later it is processed in userspace. For values, the event
contains the memcopy'd value so the value at `print()` invocation time will be
printed.  However for maps, only the handle to the map is queued up, so the
printed map may be different than the map at `print()` invocation.

## 24. `strftime()`: Formatted timestamp

Syntax:
- `strftime(const char *format, int nsecs)`

This returns a formatted timestamp that is printable with `printf`. The format
string must be supported by `strftime(3)`. `nsecs` is nanoseconds since boot,
typically derived from [nsecs](#6-nsecs-timestamps-and-time-deltas).

Use format specifier "%s" when printing the return value. Note that `strftime`
does not actually return a string in bpf (kernel), the formatting happens in
userspace.

Examples:

```
# bpftrace -e 'i:s:1 { printf("%s\n", strftime("%H:%M:%S", nsecs)); }'
Attaching 1 probe...
13:11:22
13:11:23
13:11:24
13:11:25
13:11:26
^C
```

## 25. `path()`: Return full path

Syntax:
- `path(struct path *path)`

Return full path referenced by struct path pointer in argument.
There's list of allowed kernel functions, that can use this
helper in probe.

Examples:
```
# bpftrace  -e 'kfunc:filp_close { printf("%s\n", path(args->filp->f_path)); }'
Attaching 1 probe...
/proc/sys/net/ipv6/conf/eno2/disable_ipv6
/proc/sys/net/ipv6/conf/eno2/use_tempaddr
socket:[23276]
/proc/sys/net/ipv6/conf/eno2/disable_ipv6
socket:[17655]
/sys/devices/pci0000:00/0000:00:1c.5/0000:04:00.1/net/eno2/type
socket:[38745]
/proc/sys/net/ipv6/conf/eno2/disable_ipv6

# bpftrace  -e 'kretfunc:dentry_open { printf("%s\n", path(retval->f_path)); }'
Attaching 1 probe...
/dev/pts/1 -> /dev/pts/1
```

## 26. `uptr()`: Annotate userspace pointer

Syntax:
- `uptr(void *p)`

Annotate `p` as a pointer belonging to userspace address space.

bpftrace can usually infer the address space of a pointer. However, there are
corner cases where inference fails. For example, kernel functions that deal
with userspace pointers (a parameter like `const char __user *p`). In these
cases, you'll need to annotate the pointer.

Examples:

```
# bpftrace -e 'kprobe:do_sys_open { printf("%s\n", str(uptr(arg1))) }'
Attaching 1 probe...
.
state
^C
```

## 27. `kptr()`: Annotate kernelspace pointer

Syntax:
- `kptr(void *p)`

Annotate `p` as a pointer belonging to kernel address space.

Just like `uptr`, you'll generally only need this if bpftrace has inferred the
pointer address space incorrectly.

## 28. `macaddr()`: Convert MAC address data to text

Syntax: `macaddr(char[6] addr)`

This returns the canonical string representation of a MAC address.

Example:

```
# bpftrace -e 'kprobe:arp_create { printf("SRC %s, DST %s\n", macaddr(sarg0), macaddr(sarg1)); }'
SRC 18:C0:4D:08:2E:BB, DST 74:83:C2:7F:8C:FF
^C
```

# Map Functions

Maps are special BPF data types that can be used to store counts, statistics, and histograms. They are
also used for some variable types as discussed in the previous section, whenever `@` is used:
[globals](#21-global), [per thread variables](#22-per-thread), and [associative
arrays](#3--associative-arrays).

When bpftrace exits, all maps are printed. For example (the `count()` function is covered in the sections
that follow):

```
# bpftrace -e 'kprobe:vfs_read { @[comm] = count(); }'
Attaching 1 probe...
^C

@[systemd]: 6
@[vi]: 7
@[sshd]: 16
@[snmpd]: 321
@[snmp-pass]: 374
```

The map was printed after the Ctrl-C to end the program. If you use maps that you do not wish to be
automatically printed on exit, you can add an END block that clears the maps. For example:

```
END
{
	clear(@start);
}
```

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
- `print(value)` - Print a value
- `clear(@x)` - Delete all keys from the map
- `zero(@x)` - Set all map values to zero

Some of these are asynchronous: the kernel queues the event, but some time later (milliseconds) it is
processed in user-space. The asynchronous actions are: `print()` on maps, `clear()`, and `zero()`.

## 2. `count()`: Count

Syntax: `@counter_name[optional_keys] = count()`

This is implemented using a BPF map.

For example, `@reads`:

```
# bpftrace -e 'kprobe:vfs_read { @reads = count();  }'
Attaching 1 probe...
^C

@reads: 119
```

That shows there were 119 calls to vfs_read() while tracing.

This next example includes the `comm` variable as a key, so that the value is broken down by each process
name. For example, `@reads[comm]`:

```
# bpftrace -e 'kprobe:vfs_read { @reads[comm] = count(); }'
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
# bpftrace -e 'kprobe:vfs_read { @bytes[comm] = sum(arg2); }'
Attaching 1 probe...
^C

@bytes[bash]: 7
@bytes[sleep]: 4160
@bytes[ls]: 6208
@bytes[snmpd]: 20480
@bytes[snmp-pass]: 65536
@bytes[sshd]: 262144
```

That is summing requested bytes via the vfs_read() kernel function, which is one of two possible entry
points for the read syscall. To see actual bytes read:

```
# bpftrace -e 'kretprobe:vfs_read /retval > 0/ { @bytes[comm] = sum(retval); }'
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

Now a filter is used to ensure the return value was positive before it is used in the sum(). The return
value may be negative in cases of error, as is the case with other functions. Remember this whenever
using sum() on a retval.

## 4. `avg()`: Average

Syntax: `@counter_name[optional_keys] = avg(value)`

This is implemented using a BPF map.

For example, `@bytes[comm]`:

```
# bpftrace -e 'kprobe:vfs_read { @bytes[comm] = avg(arg2); }'
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
# bpftrace -e 'kprobe:vfs_read { @bytes[comm] = min(arg2); }'
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
# bpftrace -e 'kprobe:vfs_read { @bytes[comm] = max(arg2); }'
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
# bpftrace -e 'kprobe:vfs_read { @bytes[comm] = stats(arg2); }'
Attaching 1 probe...
^C

@bytes[bash]: count 7, average 1, total 7
@bytes[sleep]: count 5, average 832, total 4160
@bytes[ls]: count 7, average 886, total 6208
@bytes[snmpd]: count 18, average 1706, total 30718
@bytes[snmp-pass]: count 12, average 8192, total 98304
@bytes[sshd]: count 15, average 16384, total 245760
```

This stats() function returns three statistics: the count of events, the average for the argument value,
and the total of the argument value. This is similar to using count(), avg(), and sum().

## 8. `hist()`: Log2 Histogram

Syntax:

```
@histogram_name[optional_key] = hist(value)
```

This is implemented using a BPF map.

Examples:

### 8.1. Power-Of-2:

```
# bpftrace -e 'kretprobe:vfs_read { @bytes = hist(retval); }'
Attaching 1 probe...
^C

@bytes:
(..., 0)             117 |@@@@@@@@@@@@                                        |
[0]                    5 |                                                    |
[1]                  325 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                  |
[2, 4)                 6 |                                                    |
[4, 8)                 3 |                                                    |
[8, 16)              495 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[16, 32)              35 |@@@                                                 |
[32, 64)              25 |@@                                                  |
[64, 128)             21 |@@                                                  |
[128, 256)             1 |                                                    |
[256, 512)             3 |                                                    |
[512, 1K)              2 |                                                    |
[1K, 2K)               1 |                                                    |
[2K, 4K)               2 |                                                    |
```

### 8.2. Power-Of-2 By Key:

```
# bpftrace -e 'kretprobe:do_sys_open { @bytes[comm] = hist(retval); }'
Attaching 1 probe... ^C

@bytes[snmp-pass]:
[4, 8)                 6 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

@bytes[ls]:
[2, 4)                 9 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

@bytes[snmpd]:
[1]                    1 |@@@@                                                |
[2, 4)                 0 |                                                    |
[4, 8)                 0 |                                                    |
[8, 16)                4 |@@@@@@@@@@@@@@@@@@                                  |
[16, 32)              11 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

@bytes[irqbalance]:
(..., 0)              15 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               |
[0]                    0 |                                                    |
[1]                    0 |                                                    |
[2, 4)                 0 |                                                    |
[4, 8)                21 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
```

## 9. `lhist()`: Linear Histogram

Syntax:

```
@histogram_name[optional_key] = lhist(value, min, max, step)
```

This is implemented using a BPF map. `min` must be non-negative.

Examples:

```
# bpftrace -e 'kretprobe:vfs_read { @bytes = lhist(retval, 0, 10000, 1000); }'
Attaching 1 probe...
^C

@bytes:
[0, 1000)            480 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1000, 2000)          49 |@@@@@                                               |
[2000, 3000)          12 |@                                                   |
[3000, 4000)          39 |@@@@                                                |
[4000, 5000)         267 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@                        |
```

## 10. `print()`: Print Map

Syntax: ```print(@map [, top [, divisor]])```

The `print()` function will print a map, similar to the automatic printing when bpftrace ends. Two
optional arguments can be provided: a top number, so that only the top number of entries are printed, and
a divisor, which divides the value. A couple of examples will explain their use.

As an example of top, tracing `vfs` operations and printing the top 5:

```
# bpftrace -e 'kprobe:vfs_* { @[func] = count(); } END { print(@, 5); clear(@); }'
Attaching 54 probes...
^C
@[vfs_getattr]: 91
@[vfs_getattr_nosec]: 92
@[vfs_statx_fd]: 135
@[vfs_open]: 188
@[vfs_read]: 405
```

The final `clear()` is used to prevent printing the map automatically on exit.

As an example of divisor, summing total time in vfs_read() by process name as milliseconds:

```
# bpftrace -e 'kprobe:vfs_read { @start[tid] = nsecs; }
    kretprobe:vfs_read /@start[tid]/ {@ms[pid] = sum(nsecs - @start[tid]); delete(@start[tid]); }
    END { print(@ms, 0, 1000000); clear(@ms); clear(@start); }'
```

This one-liner sums the vfs_read() durations as nanoseconds, and then does the division to milliseconds
when printing. Without this capability, should one try to divide to milliseconds when summing (eg,
`sum((nsecs - @start[tid]) / 1000000)`), the value would often be rounded to zero, and not accumulate as
it should.

Note that printing maps is different than printing values. See the explanation
in [`print()`: Print Value](#23-print-print-value).

# Output

## 1. `printf()`: Per-Event Output

Syntax: `printf(char *format, arguments)`

Per-event details can be printed using `print()`.

Examples:

```
# bpftrace -e 'kprobe:do_nanosleep { printf("sleep by %d\n", tid); }'
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
# bpftrace -e 'kprobe:do_sys_open { @opens = @opens + 1; }
    interval:s:1 { printf("opens/sec: %d\n", @opens); @opens = 0; }'
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

Declared histograms are automatically printed out on program termination. See [5.
Histograms](#5-histograms) for declarations.

Examples:

```
# bpftrace -e 'kretprobe:vfs_read { @bytes = hist(retval); }'
Attaching 1 probe...
^C

@bytes:
(..., 0)             117 |@@@@@@@@@@@@                                        |
[0]                    5 |                                                    |
[1]                  325 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                  |
[2, 4)                 6 |                                                    |
[4, 8)                 3 |                                                    |
[8, 16)              495 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[16, 32)              35 |@@@                                                 |
[32, 64)              25 |@@                                                  |
[64, 128)             21 |@@                                                  |
[128, 256)             1 |                                                    |
[256, 512)             3 |                                                    |
[512, 1K)              2 |                                                    |
[1K, 2K)               1 |                                                    |
[2K, 4K)               2 |                                                    |
```

Histograms can also be printed on-demand, using the `print()` function. Eg:

```
# bpftrace -e 'kretprobe:vfs_read { @bytes = hist(retval); } interval:s:1 { print(@bytes); clear(@bytes); }'

[...]
```

# BTF Support

If kernel has BTF, kernel types are automatically available and there is no need to include additional headers
to use them.

Requirements for using BTF:

- Linux 4.18+ with `CONFIG_DEBUG_INFO_BTF=y`
    - Building requires dwarves with pahole v1.13+
- bpftrace v0.9.3+ with BTF support (built with libbpf v0.0.4+)

See [kernel documentation](https://www.kernel.org/doc/html/latest/bpf/btf.html) for more information on BTF.

Beware that BTF types are not available to a bpftrace program if it contains a user-defined type that
redefines some BTF type. Here, "user-defined types" are also types introduced via included headers.
Therefore, if you include a kernel header in your bpftrace program, it is very likely that it will define some
kernel type and that BTF won't be available to your program (and you'll have to define/include all necessary
types manually).

# Advanced Tools

bpftrace can be used to create some powerful one-liners and some simple tools. For complex tools, which
may involve command line options, positional parameters, argument processing, and customized output,
consider switching to [bcc](https://github.com/iovisor/bcc). bcc provides Python (and other) front-ends,
enabling usage of all the other Python libraries (including argparse), as well as a direct control of the
kernel BPF program. The down side is that bcc is much more verbose and laborious to program. Together,
bpftrace and bcc are complimentary.

An expected development path would be exploration with bpftrace one-liners, then and ad hoc scripting
with bpftrace, then finally, when needed, advanced tooling with bcc.

As an example of bpftrace vs bcc differences, the bpftrace xfsdist.bt tool also exists in bcc as
xfsdist.py. Both measure the same functions and produce the same summary of information. However, the bcc
version supports various arguments:

```
# ./xfsdist.py -h
usage: xfsdist.py [-h] [-T] [-m] [-p PID] [interval] [count]

Summarize XFS operation latency

positional arguments:
  interval            output interval, in seconds
  count               number of outputs

optional arguments:
  -h, --help          show this help message and exit
  -T, --notimestamp   don't include timestamp on interval output
  -m, --milliseconds  output in milliseconds
  -p PID, --pid PID   trace this PID only

examples:
    ./xfsdist            # show operation latency as a histogram
    ./xfsdist -p 181     # trace PID 181 only
    ./xfsdist 1 10       # print 1 second summaries, 10 times
    ./xfsdist -m 5       # 5s summaries, milliseconds
```

The bcc version is 131 lines of code. The bpftrace version is 22.

# Errors

## 1. Looks like the BPF stack limit of 512 bytes is exceeded

BPF programs that operate on many data items may hit this limit. There are a number of things you can try
to stay within the limit:

1. Find ways to reduce the size of the data used in the program. Eg, avoid strings if they are
   unnecessary: use `pid` instead of `comm`. Use fewer map keys.
1. Split your program over multiple probes.
1. Check the status of the BPF stack limit in Linux (it may be increased in the future, maybe as a
   tuneabe).
1. (advanced): Run -d and examine the LLVM IR, and look for ways to optimize src/ast/codegen_llvm.cpp.

## 2. Kernel headers not found

bpftrace requires kernel headers for certain features, which are searched for by default in:

```bash
/lib/modules/$(uname -r)
```

The default search directory can be overridden using the environment variable `BPFTRACE_KERNEL_SOURCE`.
