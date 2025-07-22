# bpftrace Standard Library

## Builtins

Builtins are special variables built into the language.
Unlike scratch and map variables they don’t need a `$` or `@` as prefix (except for the positional parameters).

| Variable | Type | BPF Helper | Description |
| --- | --- | --- | --- |
| [`$1`, `$2`, `...$n`](language.md#positional-parameters) | int64 | n/a | The nth positional parameter passed to the bpftrace program. If less than n parameters are passed this evaluates to `0` in an action block or an empty string in a probe. For string arguments in an action block use the `str()` call to retrieve the value. |
| `$#` | int64 | n/a | Total amount of positional parameters passed. |
| `arg0`, `arg1`, `...argn` | int64 | n/a | nth argument passed to the function being traced. These are extracted from the CPU registers. The amount of args passed in registers depends on the CPU architecture. (kprobes, uprobes, usdt). |
| `args` | struct args | n/a | The struct of all arguments of the traced function. Available in `rawtracepoint`, `tracepoint`, `fentry`, `fexit`, and `uprobe` (with DWARF) probes. Use `args.x` to access argument `x` or `args` to get a record with all arguments. |
| `cgroup` | uint64 | get_current_cgroup_id | ID of the cgroup the current process belongs to. Only works with cgroupv2. |
| `comm` | string | get_current_comm | Name of the current thread |
| `cpid` | uint32 | n/a | Child process ID, if bpftrace is invoked with `-c` |
| `cpu` | uint32 | raw_smp_processor_id | ID of the processor executing the BPF program |
| `ncpus` | uint64 | n/a | Number of CPUs |
| `curtask` | uint64 | get_current_task | Pointer to `struct task_struct` of the current task |
| `elapsed` | uint64 | (see nsec) | ktime_get_ns / ktime_get_boot_ns | Nanoseconds elapsed since bpftrace initialization, based on `nsecs` |
| `func` | string | n/a | Name of the current function being traced (kprobes,uprobes) |
| `gid` | uint64 | get_current_uid_gid | Group ID of the current thread, as seen from the init namespace |
| `jiffies` | uint64 | get_jiffies_64 | Jiffies of the kernel. In 32-bit system, using this builtin might be slower. |
| `numaid` | uint32 | numa_node_id | ID of the NUMA node executing the BPF program |
| `pid` | uint32 | get_current_pid_tgid / get_ns_current_pid_tgid | Process ID of the current thread (aka thread group ID), as seen from the PID namespace of bpftrace |
| `probe` | string | n/na | n/a | Name of the current probe |
| `rand` | uint32 | get_prandom_u32 | Random number |
| `return` | n/a | n/a | The return keyword is used to exit the current probe. This differs from exit() in that it doesn’t exit bpftrace. |
| `retval` | uint64 | n/a | Value returned by the function being traced (kretprobe, uretprobe, fexit). For kretprobe and uretprobe, its type is `uint64`, but for fexit it depends. You can look up the type using `bpftrace -lv` |
| `tid` | uint32 | get_current_pid_tgid / get_ns_current_pid_tgid | Thread ID of the current thread, as seen from the PID namespace of bpftrace |
| `uid` | uint64 | get_current_uid_gid | User ID of the current thread, as seen from the init namespace |
| `username` | string | n/a | get_current_uid_gid | User name of the current thread, as seen from the init namespace |
| `usermode` | uint8 | n/a | Returns 1 if the current process is in user mode, 0 otherwise. Currently only available on x86_64. |

## Functions

| Name | Description | Sync/Async/Compile Time |
| --- | --- | --- |
| [`bswap`](#bswap) | Reverse byte order | Sync |
| [`buf`](#buf) | Returns a hex-formatted string of the data pointed to by d | Sync |
| [`cat`](#cat) | Print file content | Async |
| [`cgroupid`](#cgroupid) | Resolve cgroup ID | Compile Time |
| [`cgroup_path`](#cgroup_path) | Convert cgroup id to cgroup path | Sync |
| [`exit`](#exit) | Quit bpftrace with an optional exit code | Async |
| [`getopt`](#getopt) | Get named command line option/parameter | Sync |
| [`join`](#join) | Combine an array of char* into one string and print it | Async |
| [`kaddr`](#kaddr) | Resolve kernel symbol name | Compile Time |
| [`kptr`](#kptr) | Annotate as kernelspace pointer | Sync |
| [`kstack`](#kstack) | Kernel stack trace | Sync |
| [`ksym`](#ksym) | Resolve kernel address | Async |
| [`len`](#len) | Count ustack/kstack frames | Sync |
| [`macaddr`](#macaddr) | Convert MAC address data | Sync |
| [`nsecs`](#nsecs) | Timestamps and Time Deltas | Sync |
| [`ntop`](#ntop) | Convert IP address data to text | Sync |
| [`offsetof`](#offsetof) | Offset of element in structure | Compile Time |
| [`override`](#override) | Override return value | Sync |
| [`path`](#path) | Return full path | Sync |
| [`percpu_kaddr`](#percpu_kaddr) | Resolve percpu kernel symbol name | Sync |
| [`pid`](#pid) | Process ID of the current thread | Sync |
| [`print`](#print) | Print a non-map value with default formatting | Async |
| [`printf`](#printf) | Print formatted | Async |
| [`pton`](#pton) | Convert text IP address to byte array | Compile Time |
| [`reg`](#reg) | Returns the value stored in the named register | Sync |
| [`signal`](#signal) | Send a signal to the current process | Sync |
| [`sizeof`](#sizeof) | Return size of a type or expression | Sync |
| [`skboutput`](#skboutput) | Write skb 's data section into a PCAP file | Async |
| [`socket_cookie`](#socket_cookie) | Get the cookie of a socket | Sync |
| [`str`](#str) | Returns the string pointed to by s | Sync |
| [`strcontains`](#strcontains) | Compares whether the string haystack contains the string needle. | Sync |
| [`strerror`](#strerror) | Get error message for errno code | Sync |
| [`strftime`](#strftime) | Return a formatted timestamp | Async |
| [`strncmp`](#strncmp) | Compare first n characters of two strings | Sync |
| [`system`](#system) | Execute shell command | Async |
| [`tid`](#tid) | Thread ID of the current thread | Sync |
| [`time`](#time) | Print formatted time | Async |
| [`uaddr`](#uaddr) | Resolve user-level symbol name | Compile Time |
| [`uptr`](#uptr) | Annotate as userspace pointer | Sync |
| [`ustack`](#ustack) | User stack trace | Sync |
| [`usym`](#usym) | Resolve user space address | Async |

Functions that are marked **async** are asynchronous which can lead to unexpected behaviour, see the [Invocation Mode](#invocation-mode) section for more information.

**compile time** functions are evaluated at compile time, a static value will be compiled into the program.

**unsafe** functions can have dangerous side effects and should be used with care, the `--unsafe` flag is required for use.

### bswap

**variants**

* `uint8 bswap(uint8 n)`
* `uint16 bswap(uint16 n)`
* `uint32 bswap(uint32 n)`
* `uint64 bswap(uint64 n)`

`bswap` reverses the order of the bytes in integer `n`. In case of 8 bit integers, `n` is returned without being modified.
The return type is an unsigned integer of the same width as `n`.

### buf

**variants**

* `buffer buf(void * data, [int64 length])`

`buf` reads `length` amount of bytes from address `data`.
The maximum value of `length` is limited to the `BPFTRACE_MAX_STRLEN` variable.
For arrays the `length` is optional, it is automatically inferred from the signature.

`buf` is address space aware and will call the correct helper based on the address space associated with `data`.

The `buffer` object returned by `buf` can safely be printed as a hex encoded string with the `%r` format specifier.

Bytes with values >=32 and \&lt;=126 are printed using their ASCII character, other bytes are printed in hex form (e.g. `\x00`). The `%rx` format specifier can be used to print everything in hex form, including ASCII characters. The similar `%rh` format specifier prints everything in hex form without `\x` and with spaces between bytes (e.g. `0a fe`).

```
interval:s:1 {
  printf("%r\n", buf(kaddr("avenrun"), 8));
}
```

```
\x00\x03\x00\x00\x00\x00\x00\x00
\xc2\x02\x00\x00\x00\x00\x00\x00
```

### cat

**variants**

* `void cat(string namefmt, [...args])`

**async**

Dump the contents of the named file to stdout.
`cat` supports the same format string and arguments that `printf` does.
If the file cannot be opened or read an error is printed to stderr.

```
tracepoint:syscalls:sys_enter_execve {
  cat("/proc/%d/maps", pid);
}
```

```
55f683ebd000-55f683ec1000 r--p 00000000 08:01 1843399                    /usr/bin/ls
55f683ec1000-55f683ed6000 r-xp 00004000 08:01 1843399                    /usr/bin/ls
55f683ed6000-55f683edf000 r--p 00019000 08:01 1843399                    /usr/bin/ls
55f683edf000-55f683ee2000 rw-p 00021000 08:01 1843399                    /usr/bin/ls
55f683ee2000-55f683ee3000 rw-p 00000000 00:00 0
```

### pid
**variants**

* `uint32 pid([curr_ns|init])`

Returns the process ID of the current thread.
Defaults to `curr_ns`.

* `pid(curr_ns)` - The process ID as seen from the PID namespace of bpftrace.
* `pid(init)` - The process ID as seen from the initial PID namespace.

### tid
**variants**

* `uint32 tid([curr_ns|init])`

Returns the thread ID of the current thread.
Defaults to `curr_ns`.

* `tid(curr_ns)` - The thread ID as seen from the PID namespace of bpftrace.
* `tid(init)` - The thread ID as seen from the initial PID namespace.

### cgroupid

**variants**

* `uint64 cgroupid(const string path)`

**compile time**

`cgroupid` retrieves the cgroupv2 ID  of the cgroup available at `path`.

```
BEGIN {
  print(cgroupid("/sys/fs/cgroup/system.slice"));
}
```

### cgroup_path

**variants**

* `cgroup_path_t cgroup_path(int cgroupid, string filter)`

Convert cgroup id to cgroup path.
This is done asynchronously in userspace when the cgroup_path value is printed,
therefore it can resolve to a different value if the cgroup id gets reassigned.
This also means that the returned value can only be used for printing.

A string literal may be passed as an optional second argument to filter cgroup
hierarchies in which the cgroup id is looked up by a wildcard expression (cgroup2
is always represented by "unified", regardless of where it is mounted).

The currently mounted hierarchy at /sys/fs/cgroup is used to do the lookup. If
the cgroup with the given id isn’t present here (e.g. when running in a Docker
container), the cgroup path won’t be found (unlike when looking up the cgroup
path of a process via /proc/.../cgroup).

```
BEGIN {
  $cgroup_path = cgroup_path(3436);
  print($cgroup_path);
  print($cgroup_path); /* This may print a different path */
  printf("%s %s", $cgroup_path, $cgroup_path); /* This may print two different paths */
}
```

### exit

**variants**

* `void exit([int code])`

**async**

Terminate bpftrace, as if a `SIGTERM` was received.
The `END` probe will still trigger (if specified) and maps will be printed.
An optional exit code can be provided.

```
BEGIN {
  exit();
}
```

Or

```
BEGIN {
  exit(1);
}
```

### getopt

**variants**

* `bool getopt(string arg_name)`
* `string getopt(string arg_name, string default_value)`
* `int getopt(string arg_name, int default_value)`
* `bool getopt(string arg_name, bool default_value)`

Get the named command line argument/option e.g.
```
# bpftrace -e 'BEGIN { print(getopt("hello", 1)); }' -- --hello=5

```

`getopt` defines the type of the argument by the default value’s type.
If no default type is provided, the option is treated like a boolean arg e.g. `getopt("hello")` would evaluate to `false` if `--hello` is not specified on the command line or `true` if `--hello` is passed or set to one of the following values: `true`, `1`.
Additionally, boolean args accept the following false values: `0`, `false` e.g. `--hello=false`.
If the arg is not set on the command line, the default value is used.

```
# bpftrace -e 'BEGIN { print((getopt("aa", 10), getopt("bb", "hello"), getopt("cc"), getopt("dd", false))); }' -- --cc --bb=bye

```

### join

**variants**

* `void join(char *arr[], [char * sep = ' '])`

**async**

`join` joins a char * `arr` with `sep` as separator into one string.
This string will be printed to stdout directly, it cannot be used as string value.

The concatenation of the array members is done in BPF and the printing happens in userspace.

```
tracepoint:syscalls:sys_enter_execve {
  join(args.argv);
}
```

### kaddr

**variants**

* `uint64 kaddr(const string name)`

**compile time**

Get the address of the kernel symbol `name`.

```
interval:s:1 {
  $avenrun = kaddr("avenrun");
  $load1 = *$avenrun;
}
```

You can find all kernel symbols at `/proc/kallsyms`.

### kptr

**variants**

* `T * kptr(T * ptr)`

Marks `ptr` as a kernel address space pointer.
See the address-spaces section for more information on address-spaces.
The pointer type is left unchanged.

### kstack

**variants**

* `kstack_t kstack([StackMode mode, ][int limit])`

These are implemented using BPF stack maps.

```
kprobe:ip_output { @[kstack()] = count(); }

/*
 * Sample output:
 * @[
 *  ip_output+1
 *  tcp_transmit_skb+1308
 *  tcp_write_xmit+482
 *  tcp_release_cb+225
 *  release_sock+64
 *  tcp_sendmsg+49
 *  sock_sendmsg+48
 *  sock_write_iter+135
 *   __vfs_write+247
 *  vfs_write+179
 *  sys_write+82
 *   entry_SYSCALL_64_fastpath+30
 * ]: 1708
 */
```

Sampling only three frames from the stack (limit = 3):

```
kprobe:ip_output { @[kstack(3)] = count(); }

/*
 * Sample output:
 * @[
 *  ip_output+1
 *  tcp_transmit_skb+1308
 *  tcp_write_xmit+482
 * ]: 1708
 */
```

You can also choose a different output format.
Available formats are `bpftrace`, `perf`, and `raw` (no symbolication):

```
kprobe:ip_output { @[kstack(perf, 3)] = count(); }

/*
 * Sample output:
 * @[
 *  ffffffffb4019501 do_mmap+1
 *  ffffffffb401700a sys_mmap_pgoff+266
 *  ffffffffb3e334eb sys_mmap+27
 * ]: 1708
 */
```

### ksym

**variants**

* `ksym_t ksym(uint64 addr)`

**async**

Retrieve the name of the function that contains address `addr`.
The address to name mapping happens in user-space.

The `ksym_t` type can be printed with the `%s` format specifier.

```
kprobe:do_nanosleep
{
  printf("%s\n", ksym(reg("ip")));
}

/*
 * Sample output:
 * do_nanosleep
 */
```

### len

**variants**

* `int64 len(ustack stack)`
* `int64 len(kstack stack)`

Retrieve the depth (measured in # of frames) of the call stack
specified by `stack`.

### macaddr

**variants**

* `macaddr_t macaddr(char [6] mac)`

Create a buffer that holds a macaddress as read from `mac`
This buffer can be printed in the canonical string format using the `%s` format specifier.

```
kprobe:arp_create {
  $stack_arg0 = *(uint8*)(reg("sp") + 8);
  $stack_arg1 = *(uint8*)(reg("sp") + 16);
  printf("SRC %s, DST %s\n", macaddr($stack_arg0), macaddr($stack_arg1));
}

/*
 * Sample output:
 * SRC 18:C0:4D:08:2E:BB, DST 74:83:C2:7F:8C:FF
 */
```

### nsecs

**variants**

* `timestamp nsecs([TimestampMode mode])`

Returns a timestamp in nanoseconds, as given by the requested kernel clock.
Defaults to `boot` if no clock is explicitly requested.

* `nsecs(monotonic)` - nanosecond timestamp since boot, exclusive of time the system spent suspended (CLOCK_MONOTONIC)
* `nsecs(boot)` - nanoseconds since boot, inclusive of time the system spent suspended (CLOCK_BOOTTIME)
* `nsecs(tai)` - TAI timestamp in nanoseconds (CLOCK_TAI)
* `nsecs(sw_tai)` - approximation of TAI timestamp in nanoseconds, is obtained through the "triple vdso sandwich" method. For older kernels without direct TAI timestamp access in BPF.

```
interval:s:1 {
  $sw_tai1 = nsecs(sw_tai);
  $tai = nsecs(tai);
  $sw_tai2 = nsecs(sw_tai);
  printf("sw_tai precision: %lldns\n", ($sw_tai1 + $sw_tai2)/2 - $tai);
}

/*
 * Sample output:
 * sw_tai precision: -98ns
 * sw_tai precision: -99ns
 * ...
 */
```

### ntop

**variants**

* `inet ntop([int64 af, ] int addr)`
* `inet ntop([int64 af, ] char addr[4])`
* `inet ntop([int64 af, ] char addr[16])`

`ntop` returns the string representation of an IPv4 or IPv6 address.
`ntop` will infer the address type (IPv4 or IPv6) based on the `addr` type and size.
If an integer or `char[4]` is given, ntop assumes IPv4, if a `char[16]` is given, ntop assumes IPv6.
You can also pass the address type (e.g. AF_INET) explicitly as the first parameter.

### offsetof

**variants**

* `uint64 offsetof(STRUCT, FIELD[.SUBFIELD])`
* `uint64 offsetof(EXPRESSION, FIELD[.SUBFIELD])`

**compile time**

Returns offset of the field offset bytes in struct.
Similar to kernel `offsetof` operator.

Support any number of sub field levels, for example:

```
struct Foo {
  struct {
    struct {
      struct {
        int d;
      } c;
    } b;
  } a;
}
BEGIN {
  @x = offsetof(struct Foo, a.b.c.d);
  exit();
}
```

### override

**variants**

* `void override(uint64 rc)`

**unsafe**

**Kernel** 4.16

**Helper** `bpf_override`

**Supported probes**

* kprobe

When using `override` the probed function will not be executed and instead `rc` will be returned.

```
kprobe:__x64_sys_getuid
/comm == "id"/ {
  override(2<<21);
}
```

```
uid=4194304 gid=0(root) euid=0(root) groups=0(root)
```

This feature only works on kernels compiled with `CONFIG_BPF_KPROBE_OVERRIDE` and only works on functions tagged `ALLOW_ERROR_INJECTION`.

bpftrace does not test whether error injection is allowed for the probed function, instead if will fail to load the program into the kernel:

```
ioctl(PERF_EVENT_IOC_SET_BPF): Invalid argument
Error attaching probe: 'kprobe:vfs_read'
```

### path

**variants**

* `char * path(struct path * path [, int32 size])`

**Kernel** 5.10

**Helper** `bpf_d_path`

Return full path referenced by struct path pointer in argument. If `size` is set,
the path will be clamped by `size` otherwise `BPFTRACE_MAX_STRLEN` is used.

If `size` is smaller than the resolved path, the resulting string will be truncated at the front rather than at the end.

This function can only be used by functions that are allowed to, these functions are contained in the `btf_allowlist_d_path` set in the kernel.

### percpu_kaddr

**variants**

* `uint64 *percpu_kaddr(const string name)`
* `uint64 *percpu_kaddr(const string name, int cpu)`

**sync**

Get the address of the percpu kernel symbol `name` for CPU `cpu`. When `cpu` is
omitted, the current CPU is used.

```
interval:s:1 {
  $proc_cnt = percpu_kaddr("process_counts");
  printf("% processes are running on CPU %d\n", *$proc_cnt, cpu);
}
```

The second variant may return NULL if `cpu` is higher than the number of
available CPUs. Therefore, it is necessary to perform a NULL-check on the result
when accessing fields of the pointed structure, otherwise the BPF program will
be rejected.

```
interval:s:1 {
  $runqueues = (struct rq *)percpu_kaddr("runqueues", 0);
  if ($runqueues != 0) {         // The check is mandatory here
    print($runqueues->nr_running);
  }
}
```

### print

**variants**

* `void print(T val)`

**async**

**variants**

* `void print(T val)`
* `void print(@map)`
* `void print(@map, uint64 top)`
* `void print(@map, uint64 top, uint64 div)`

`print` prints a the value, which can be a map or a scalar value, with the default formatting for the type.

```
interval:s:1 {
  print(123);
  print("abc");
  exit();
}

/*
 * Sample output:
 * 123
 * abc
 */
```

```
interval:ms:10 { @=hist(rand); }
interval:s:1 {
  print(@);
  exit();
}
```

Prints:

```
@:
[16M, 32M)             3 |@@@                                                 |
[32M, 64M)             2 |@@                                                  |
[64M, 128M)            1 |@                                                   |
[128M, 256M)           4 |@@@@                                                |
[256M, 512M)           3 |@@@                                                 |
[512M, 1G)            14 |@@@@@@@@@@@@@@                                      |
[1G, 2G)              22 |@@@@@@@@@@@@@@@@@@@@@@                              |
[2G, 4G)              51 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
```

Declared maps and histograms are automatically printed out on program termination.

Note that maps are printed by reference while scalar values are copied.
This means that updating and printing maps in a fast loop will likely result in bogus map values as the map will be updated before userspace gets the time to dump and print it.

The printing of maps supports the optional `top` and `div` arguments.
`top` limits the printing to the top N entries with the highest integer values

```
BEGIN {
  $i = 11;
  while($i) {
    @[$i] = --$i;
  }
  print(@, 2);
  clear(@);
  exit()
}

/*
 * Sample output:
 * @[9]: 9
 * @[10]: 10
 */
```

The `div` argument scales the values prior to printing them.
Scaling values before storing them can result in rounding errors.
Consider the following program:

```
kprobe:f {
  @[func] += arg0/10;
}
```

With the following sequence as numbers for arg0: `134, 377, 111, 99`.
The total is `721` which rounds to `72` when scaled by 10 but the program would print `70` due to the rounding of individual values.

Changing the print call to `print(@, 5, 2)` will take the top 5 values and scale them by 2:

```
@[6]: 3
@[7]: 3
@[8]: 4
@[9]: 4
@[10]: 5
```

### printf

**variants**

* `void printf(const string fmt, args...)`

**async**

`printf()` formats and prints data.
It behaves similar to `printf()` found in `C` and many other languages.

The format string has to be a constant, it cannot be modified at runtime.
The formatting of the string happens in user space.
Values are copied and passed by value.

bpftrace supports all the typical format specifiers like `%llx` and `%hhu`.
The non-standard ones can be found in the table below:

| Specifier | Type | Description |
| --- | --- | --- |
| r | buffer | Hex-formatted string to print arbitrary binary content returned by the [buf](#buf) function. |
| rh | buffer | Prints in hex-formatted string without `\x` and with spaces between bytes (e.g. `0a fe`) |

`printf()` can also symbolize enums as strings. User defined enums as well as enums
defined in the kernel are supported. For example:

```
enum custom {
  CUSTOM_ENUM = 3,
};

BEGIN {
  $r = SKB_DROP_REASON_SOCKET_FILTER;
  printf("%d, %s, %s\n", $r, $r, CUSTOM_ENUM);
  exit();
}
```

yields:

```
6, SKB_DROP_REASON_SOCKET_FILTER, CUSTOM_ENUM
```

Colors are supported too, using standard terminal escape sequences:

```
print("\033[31mRed\t\033[33mYellow\033[0m\n")
```

### pton

**variants**

* `char addr[4] pton(const string *addr_v4)`
* `char addr[16] pton(const string *addr_v6)`

**compile time**

`pton` converts a text representation of an IPv4 or IPv6 address to byte array.
`pton` infers the address family based on `.` or `:` in the given argument.
`pton` comes in handy when we need to select packets with certain IP addresses.

### reg

**variants**

* `uint64 reg(const string name)`

**Supported probes**

* kprobe
* uprobe

Get the contents of the register identified by `name`.
Valid names depend on the CPU architecture.

### signal

**variants**

* `void signal(const string sig)`
* `void signal(uint32 signum)`

**unsafe**

**Kernel** 5.3

**Helper** `bpf_send_signal`

Probe types: k(ret)probe, u(ret)probe, USDT, profile

Send a signal to the process being traced.
The signal can either be identified by name, e.g. `SIGSTOP` or by ID, e.g. `19` as found in `kill -l`.

```
kprobe:__x64_sys_execve
/comm == "bash"/ {
  signal(5);
}
```
```
$ ls
Trace/breakpoint trap (core dumped)
```

### sizeof

**variants**

* `uint64 sizeof(TYPE)`
* `uint64 sizeof(EXPRESSION)`

**compile time**

Returns size of the argument in bytes.
Similar to C/C++ `sizeof` operator.
Note that the expression does not get evaluated.

### skboutput

**variants**

* `uint32 skboutput(const string path, struct sk_buff *skb, uint64 length, const uint64 offset)`

**Kernel** 5.5

**Helper** bpf_skb_output

Write sk_buff `skb` 's data section to a PCAP file in the `path`, starting from `offset` to `offset` + `length`.

The PCAP file is encapsulated in RAW IP, so no ethernet header is included.
The `data` section in the struct `skb` may contain ethernet header in some kernel contexts, you may set `offset` to 14 bytes to exclude ethernet header.

Each packet’s timestamp is determined by adding `nsecs` and boot time, the accuracy varies on different kernels, see `nsecs`.

This function returns 0 on success, or a negative error in case of failure.

Environment variable `BPFTRACE_PERF_RB_PAGES` should be increased in order to capture large packets, or else these packets will be dropped.

Usage

```
# cat dump.bt
fentry:napi_gro_receive {
  $ret = skboutput("receive.pcap", args.skb, args.skb->len, 0);
}

fentry:dev_queue_xmit {
  // setting offset to 14, to exclude ethernet header
  $ret = skboutput("output.pcap", args.skb, args.skb->len, 14);
  printf("skboutput returns %d\n", $ret);
}

# export BPFTRACE_PERF_RB_PAGES=1024
# bpftrace dump.bt
...

# tcpdump -n -r ./receive.pcap  | head -3
reading from file ./receive.pcap, link-type RAW (Raw IP)
dropped privs to tcpdump
10:23:44.674087 IP 22.128.74.231.63175 > 192.168.0.23.22: Flags [.], ack 3513221061, win 14009, options [nop,nop,TS val 721277750 ecr 3115333619], length 0
10:23:45.823194 IP 100.101.2.146.53 > 192.168.0.23.46619: 17273 0/1/0 (130)
10:23:45.823229 IP 100.101.2.146.53 > 192.168.0.23.46158: 45799 1/0/0 A 100.100.45.106 (60)
```

### socket_cookie

**variants**

* `uint64 socket_cookie(struct sock *sk)`

**Helper** `bpf_get_socket_cookie`

Retrieve the cookie (generated by the kernel) of the socket.
If no cookie has been set yet, generate a new cookie. Once generated, the socket cookie remains stable for the life of the socket.

This function returns a `uint64` unique number on success, or 0 if **sk** is NULL.

```
fentry:tcp_rcv_established
{
  $cookie = socket_cookie(args->sk);
  @psize[$cookie] = hist(args->skb->len);
}
```

Prints:

```
@psize[65551]:
[32, 64)               4 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

@psize[504]:
[32, 64)               4 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[64, 128)              1 |@@@@@@@@@@@@@                                       |
[128, 256)             0 |                                                    |
[256, 512)             1 |@@@@@@@@@@@@@                                       |
[512, 1K)              0 |                                                    |
[1K, 2K)               0 |                                                    |
[2K, 4K)               1 |@@@@@@@@@@@@@                                       |
```

### str

**variants**

* `string str(char * data [, uint32 length)`

**Helper** `probe_read_str, probe_read_{kernel,user}_str`

`str` reads a NULL terminated (`\0`) string from `data`.
The maximum string length is limited by the `BPFTRACE_MAX_STRLEN` env variable, unless `length` is specified and shorter than the maximum.
In case the string is longer than the specified length only `length - 1` bytes are copied and a NULL byte is appended at the end.

When available (starting from kernel 5.5, see the `--info` flag) bpftrace will automatically use the `kernel` or `user` variant of `probe_read_{kernel,user}_str` based on the address space of `data`, see [Address-spaces](./language.md#address-spaces) for more information.

### strcontains

**variants**

* `int64 strcontains(const char *haystack, const char *needle)`

`strcontains` compares whether the string haystack contains the string needle.
If needle is contained `1` is returned, else zero is returned.

bpftrace doesn’t read past the length of the shortest string.

### strerror

**variants**

* `strerror_t strerror(int error)`

Convert errno code to string.
This is done asynchronously in userspace when the strerror value is printed, hence the returned value can only be used for printing.

```
#include <errno.h>
BEGIN {
  print(strerror(EPERM));
}
```

### strftime

**variants**

* `timestamp strftime(const string fmt, int64 timestamp_ns)`

**async**

Format the nanoseconds since boot timestamp `timestamp_ns` according to the format specified by `fmt`.
The time conversion and formatting happens in user space, therefore  the `timestamp` value returned can only be used for printing using the `%s` format specifier.

bpftrace uses the `strftime(3)` function for formatting time and supports the same format specifiers.

```
interval:s:1 {
  printf("%s\n", strftime("%H:%M:%S", nsecs));
}
```

bpftrace also supports the following format string extensions:

| Specifier | Description |
| --- | --- |
| `%f` | Microsecond as a decimal number, zero-padded on the left |

### strncmp

**variants**

* `int64 strncmp(char * s1, char * s2, int64 n)`

`strncmp` compares up to `n` characters string `s1` and string `s2`.
If they’re equal `0` is returned, else a non-zero value is returned.

bpftrace doesn’t read past the length of the shortest string.

The use of the `==` and `!=` operators is recommended over calling `strncmp` directly.

### system

**variants**

* `void system(string namefmt [, ...args])`

**unsafe**
**async**

`system` lets bpftrace run the specified command (`fork` and `exec`) until it completes and print its stdout.
The `command` is run with the same privileges as bpftrace and it blocks execution of the processing threads which can lead to missed events and delays processing of async events.

```
interval:s:1 {
  time("%H:%M:%S: ");
  printf("%d\n", @++);
}
interval:s:10 {
  system("/bin/sleep 10");
}
interval:s:30 {
  exit();
}
```

Note how the async `time` and `printf` first print every second until the `interval:s:10` probe hits, then they print every 10 seconds due to bpftrace blocking on `sleep`.

```
Attached 3 probes
08:50:37: 0
08:50:38: 1
08:50:39: 2
08:50:40: 3
08:50:41: 4
08:50:42: 5
08:50:43: 6
08:50:44: 7
08:50:45: 8
08:50:46: 9
08:50:56: 10
08:50:56: 11
08:50:56: 12
08:50:56: 13
08:50:56: 14
08:50:56: 15
08:50:56: 16
08:50:56: 17
08:50:56: 18
08:50:56: 19
```

`system` supports the same format string and arguments that `printf` does.

```
tracepoint:syscalls:sys_enter_execve {
  system("/bin/grep %s /proc/%d/status", "vmswap", pid);
}
```

### time

**variants**

* `void time(const string fmt)`

**async**

Format the current wall time according to the format specifier `fmt` and print it to stdout.
Unlike `strftime()` `time()` doesn’t send a timestamp from the probe, instead it is the time at which user-space processes the event.

bpftrace uses the `strftime(3)` function for formatting time and supports the same format specifiers.

### uaddr

**variants**

* `T * uaddr(const string sym)`

**Supported probes**

* uprobes
* uretprobes
* USDT

***Does not work with ASLR, see issue [#75](https://github.com/bpftrace/bpftrace/issues/75)***

The `uaddr` function returns the address of the specified symbol.
This lookup happens during program compilation and cannot be used dynamically.

The default return type is `uint64*`.
If the ELF object size matches a known integer size (1, 2, 4 or 8 bytes) the return type is modified to match the width (`uint8*`, `uint16*`, `uint32*` or `uint64*` resp.).
As ELF does not contain type info the type is always assumed to be unsigned.

```
uprobe:/bin/bash:readline {
  printf("PS1: %s\n", str(*uaddr("ps1_prompt")));
}
```

### uptr

**variants**

* `T * uptr(T * ptr)`

Marks `ptr` as a user address space pointer.
See the address-spaces section for more information on address-spaces.
The pointer type is left unchanged.

### ustack

**variants**

* `ustack_t ustack([StackMode mode, ][int limit])`

These are implemented using BPF stack maps.

```
kprobe:do_sys_open /comm == "bash"/ { @[ustack()] = count(); }

/*
 * Sample output:
 * @[
 *  __open_nocancel+65
 *  command_word_completion_function+3604
 *  rl_completion_matches+370
 *  bash_default_completion+540
 *  attempt_shell_completion+2092
 *  gen_completion_matches+82
 *  rl_complete_internal+288
 *  rl_complete+145
 *  _rl_dispatch_subseq+647
 *  _rl_dispatch+44
 *  readline_internal_char+479
 *  readline_internal_charloop+22
 *  readline_internal+23
 *  readline+91
 *  yy_readline_get+152
 *  yy_readline_get+429
 *  yy_getc+13
 *  shell_getc+469
 *  read_token+251
 *  yylex+192
 *  yyparse+777
 *  parse_command+126
 *  read_command+207
 *  reader_loop+391
 *  main+2409
 *  __libc_start_main+231
 *  0x61ce258d4c544155
 * ]: 9
 */
```

Sampling only three frames from the stack (limit = 3):

```
kprobe:ip_output { @[ustack(3)] = count(); }

/*
 * Sample output:
 * @[
 *  __open_nocancel+65
 *  command_word_completion_function+3604
 *  rl_completion_matches+370
 * ]: 20
 */
```

You can also choose a different output format.
Available formats are `bpftrace`, `perf`, and `raw` (no symbolication):

```
kprobe:ip_output { @[ustack(perf, 3)] = count(); }

/*
 * Sample output:
 * @[
 *  5649feec4090 readline+0 (/home/mmarchini/bash/bash/bash)
 *  5649fee2bfa6 yy_readline_get+451 (/home/mmarchini/bash/bash/bash)
 *  5649fee2bdc6 yy_getc+13 (/home/mmarchini/bash/bash/bash)
 * ]: 20
 */
```

Note that for these examples to work, bash had to be recompiled with frame pointers.

### usym

**variants**

* `usym_t usym(uint64 * addr)`

**async**

**Supported probes**

* uprobes
* uretprobes

Equal to [ksym](#ksym) but resolves user space symbols.

If ASLR is enabled, user space symbolication only works when the process is running at either the time of the symbol resolution or the time of the probe attachment. The latter requires `BPFTRACE_CACHE_USER_SYMBOLS` to be set to `PER_PID`, and might not work with older versions of BCC. A similar limitation also applies to dynamically loaded symbols.

```
uprobe:/bin/bash:readline
{
  printf("%s\n", usym(reg("ip")));
}

/*
 * Sample output:
 * readline
 */
```

### unwatch

**variants**

* `void unwatch(void * addr)`

**async**

Removes a watchpoint

## Map Functions

Map functions are built-in functions who’s return value can only be assigned to maps.
The data type associated with these functions are only for internal use and are not compatible with the (integer) operators.

Functions that are marked **async** are asynchronous which can lead to unexpected behavior, see the [Invocation Mode](#invocation-mode) section for more information.

More information on [map printing](./language.md#map-printing).

| Name | Description | Sync/async |
| --- | --- | --- |
| [`avg`](#avg) | Calculate the running average of `n` between consecutive calls. | Sync |
| [`clear`](#clear) | Clear all keys/values from a map. | Async |
| [`count`](#count) | Count how often this function is called. | Sync |
| [`delete`](#delete) | Delete a single key from a map. | Sync |
| [`has_key`](#has_key) | Return true if the key exists in this map. Otherwise return false. | Sync |
| [`hist`](#hist) | Create a log2 histogram of n using buckets per power of 2, 0 &lt;= k &lt;= 5, defaults to 0. | Sync |
| [`len`](#len) | Return the number of elements in a map. | Sync |
| [`lhist`](#lhist) | Create a linear histogram of n. lhist creates M ((max - min) / step) buckets in the range [min,max) where each bucket is step in size. | Sync |
| [`max`](#max) | Update the map with n if n is bigger than the current value held. | Sync |
| [`min`](#min) | Update the map with n if n is smaller than the current value held. | Sync |
| [`stats`](#stats) | Combines the count, avg and sum calls into one. | Sync |
| [`sum`](#sum) | Calculate the sum of all n passed. | Sync |
| [`zero`](#zero) | Set all values for all keys to zero. | Async |
| [`tseries`](#tseries) | Create a time series that tracks either the last integer value in each interval or the per-interval average, minimum, maximum, or sum. | Sync |

### avg

**variants**

* `avg_t avg(int64 n)`

Calculate the running average of `n` between consecutive calls.

```
interval:s:1 {
  @x++;
  @y = avg(@x);
  print(@x);
  print(@y);
}
```

Internally this keeps two values in the map: value count and running total.
The average is computed in user-space when printing by dividing the total by the
count. However, you can get the average in kernel space in expressions like
`if (@y == 5)` but this is expensive as bpftrace needs to iterate over all the
cpus to collect and sum BOTH count and total.

### clear

**variants**

* `void clear(map m)`

**async**

Clear all keys/values from map `m`.

```
interval:ms:100 {
  @[rand % 10] = count();
}

interval:s:10 {
  print(@);
  clear(@);
}
```

### count

**variants**

* `count_t count()`

Count how often this function is called.

Using `@=count()` is conceptually similar to `@++`.
The difference is that the `count()` function uses a map type optimized for
performance and correctness using cheap, thread-safe writes (PER_CPU). However, sync reads
can be expensive as bpftrace needs to iterate over all the cpus to collect and
sum these values.

Note: This differs from "raw" writes (e.g. `@++`) where multiple writers to a
shared location might lose updates, as bpftrace does not generate any atomic instructions
for `++`.

Example one:
```
BEGIN {
  @ = count();
  @ = count();
  printf("%d\n", (int64)@);   // prints 2
  exit();
}
```

Example two:
```
interval:ms:100 {
  @ = count();
}

interval:s:10 {
  // async read
  print(@);
  // sync read
  if (@ > 10) {
    print(("hello"));
  }
  clear(@);
}
```

### delete

**variants**

* `bool delete(map m, mapkey k)`
* deprecated `bool delete(mapkey k)`

Delete a single key from a map.
For scalar maps (e.g. no explicit keys), the key is omitted and is equivalent to calling `clear`.
For map keys that are composed of multiple values (e.g. `@mymap[3, "hello"] = 1` - remember these values are represented as a tuple) the syntax would be: `delete(@mymap, (3, "hello"));`

If deletion fails (e.g. the key doesn’t exist) the function returns false (0).
Additionally, if the return value for `delete` is discarded, and deletion fails, you will get a warning.

```
@a[1] = 1;

delete(@a, 1); // no warning (the key exists)

if (delete(@a, 2)) { // no warning (return value is used)
  ...
}

$did_delete = delete(@a, 2); // no warning (return value is used)

delete(@a, 2); // warning (return value is discarded and the key doesn’t exist)
```

The, now deprecated, API (supported in version &lt;= 0.21.x) of passing map arguments with the key is still supported:
e.g. `delete(@mymap[3, "hello"]);`.

```
kprobe:dummy {
  @scalar = 1;
  delete(@scalar); // ok
  @single["hello"] = 1;
  delete(@single, "hello"); // ok
  @associative[1,2] = 1;
  delete(@associative, (1,2)); // ok
  delete(@associative); // error
  delete(@associative, 1); // error

    // deprecated but ok
    delete(@single["hello"]);
    delete(@associative[1, 2]);
}
```

### has_key

**variants**

* `boolean has_key(map m, mapkey k)`

Return true (1) if the key exists in this map.
Otherwise return false (0).
Error if called with a map that has no keys (aka scalar map).
Return value can also be used for scratch variables and map keys/values.

```
kprobe:dummy {
  @associative[1,2] = 1;
  if (!has_key(@associative, (1,3))) { // ok
    print(("bye"));
  }

    @scalar = 1;
    if (has_key(@scalar)) { // error
      print(("hello"));
    }

    $a = has_key(@associative, (1,2)); // ok
    @b[has_key(@associative, (1,2))] = has_key(@associative, (1,2)); // ok
}
```

### hist

**variants**

* `hist_t hist(int64 n[, int k])`

Create a log2 histogram of `n` using $2^k$ buckets per power of 2,
0 &lt;= k &lt;= 5, defaults to 0.

```
kretprobe:vfs_read {
  @bytes = hist(retval);
}
```

Prints:

```
@:
[1M, 2M)               3 |                                                    |
[2M, 4M)               2 |                                                    |
[4M, 8M)               2 |                                                    |
[8M, 16M)              6 |                                                    |
[16M, 32M)            16 |                                                    |
[32M, 64M)            27 |                                                    |
[64M, 128M)           48 |@                                                   |
[128M, 256M)          98 |@@@                                                 |
[256M, 512M)         191 |@@@@@@                                              |
[512M, 1G)           394 |@@@@@@@@@@@@@                                       |
[1G, 2G)             820 |@@@@@@@@@@@@@@@@@@@@@@@@@@@                         |
```

### len

**variants**

* `int64 len(map m)`

Return the number of elements in the map.

### lhist

**variants**

* `lhist_t lhist(int64 n, int64 min, int64 max, int64 step)`

Create a linear histogram of `n`.
`lhist` creates `M` (`(max - min) / step`) buckets in the range `[min,max)` where each bucket is `step` in size.
Values in the range `(-inf, min)` and `(max, inf)` get their get their own bucket too, bringing the total amount of buckets created to `M+2`.

```
interval:ms:1 {
  @ = lhist(rand %10, 0, 10, 1);
}

interval:s:5 {
  exit();
}
```

Prints:

```
@:
[0, 1)               306 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         |
[1, 2)               284 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@            |
[2, 3)               294 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@          |
[3, 4)               318 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       |
[4, 5)               311 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        |
[5, 6)               362 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[6, 7)               336 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    |
[7, 8)               326 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      |
[8, 9)               328 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     |
[9, 10)              318 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       |
```

### max

**variants**

* `max_t max(int64 n)`

Update the map with `n` if `n` is bigger than the current value held.
Similar to `count` this uses a PER_CPU map (thread-safe, fast writes, slow reads).

Note: this is different than the typical userspace `max()` in that bpftrace’s `max()`
only takes a single argument. The logical "other" argument to compare to is the value
in the map the "result" is being assigned to.

For example, compare the two logically equivalent samples (C++ vs bpftrace):

In C++:
```
int x = std::max(3, 33);  // x contains 33
```

In bpftrace:
```
@x = max(3);
@x = max(33);   // @x contains 33
```

Also note that bpftrace takes care to handle the unset case. In other words,
there is no default value. The first value you pass to `max()` will always
be returned.

### min

**variants**

* `min_t min(int64 n)`

Update the map with `n` if `n` is smaller than the current value held.
Similar to `count` this uses a PER_CPU map (thread-safe, fast writes, slow reads).

See `max()` above for how this differs from the typical userspace `min()`.

### stats

**variants**

* `stats_t stats(int64 n)`

`stats` combines the `count`, `avg` and `sum` calls into one.

```
kprobe:vfs_read {
  @bytes[comm] = stats(arg2);
}
```

```
@bytes[bash]: count 7, average 1, total 7
@bytes[sleep]: count 5, average 832, total 4160
@bytes[ls]: count 7, average 886, total 6208
@
```

### sum

**variants**

* `sum_t sum(int64 n)`

Calculate the sum of all `n` passed.

Using `@=sum(5)` is conceptually similar to `@+=5`.
The difference is that the `sum()` function uses a map type optimized for
performance and correctness using cheap, thread-safe writes (PER_CPU). However, sync reads
can be expensive as bpftrace needs to iterate over all the cpus to collect and
sum these values.

Note: This differs from "raw" writes (e.g. `@+=5`) where multiple writers to a
shared location might lose updates, as bpftrace does not generate any implicit
atomic operations.

Example one:
```
BEGIN {
  @ = sum(5);
  @ = sum(6);
  printf("%d\n", (int64)@);   // prints 11
  clear(@);
  exit();
}
```

Example two:
```
interval:ms:100 {
  @ = sum(5);
}

interval:s:10 {
  // async read
  print(@);
  // sync read
  if (@ > 10) {
    print(("hello"));
  }
  clear(@);
}
```

### zero

**variants**

* `void zero(map m)`

**async**

Set all values for all keys to zero.

### tseries

**variants**

* `tseries_t tseries(int64 n, int64 interval_ns, int64 num_intervals)`
* `tseries_t tseries(int64 n, int64 interval_ns, int64 num_intervals, const string agg)`

Create a time series that tracks an integer value. `tseries` records up to
`num_intervals` intervals representing `interval_ns` nanoseconds.

#### Durations

`interval_ns` is an unsigned integer that specifies the interval duration. You
may use numbers with duration suffixes to improve readability:

```
@a = tseries(1, 100ns, 5); // 100 nanoseconds
@b = tseries(1, 100us, 5); // 100 microseconds
@c = tseries(1, 100ms, 5); // 100 milliseconds
@d = tseries(1, 1s, 5);    // 1 second
```

#### Aggregation Functions

By default, each interval in `tseries` contains the last value recorded in that
interval. The optional `agg` parameter specifies how values in the same interval
are aggregated.

| Aggregation Function | Example | Description |
| --- | --- | --- |
| `avg` | `@ = tseries(@v, 1s, 5, "avg")` | Calculate the running average of all the values in each interval. |
| `max` | `@ = tseries(@v, 1s, 5, "max")` | Calculate the maximum of all values in each interval. |
| `min` | `@ = tseries(@v, 1s, 5, "min")` | Calculate the minimum of all values in each interval. |
| `sum` | `@ = tseries(@v, 1s, 5, "sum")` | Calculate the sum of all values in each interval. |

#### Examples

Example one:

```
// Record the minimum of ten random values generated during each 100ms interval.
i:ms:10 {
  @ = tseries(rand % 10, 100ms, 20, "min");
}
```

```
Attached 2 probes


@:
             0                                                   2
hh:mm:ss.ms  |___________________________________________________|
10:41:46.700 *                                                   | 0
10:41:46.800 *                                                   | 0
10:41:46.900 |                         *                         | 1
10:41:47.000 |                                                   * 2
10:41:47.100 |                         *                         | 1
10:41:47.200 *                                                   | 0
10:41:47.300 |                         *                         | 1
10:41:47.400 *                                                   | 0
10:41:47.500 |                         *                         | 1
10:41:47.600 *                                                   | 0
10:41:47.700 |                                                   * 2
10:41:47.800 *                                                   | 0
10:41:47.900 *                                                   | 0
10:41:48.000 |                         *                         | 1
10:41:48.100 |                         *                         | 1
10:41:48.200 |                         *                         | 1
10:41:48.300 *                                                   | 0
10:41:48.400 |                                                   * 2
10:41:48.500 |                         *                         | 1
10:41:48.600 |                         *                         | 1
             v___________________________________________________v
             0                                                   2
```

Example two:

```
// Create a zigzag pattern
BEGIN {
  @dir = 1;
  @c = -5;
}

i:ms:100 {
  @ = tseries(@c, 100ms, 20);
  @c += @dir;

  if (@c > 5) {
    @dir = -1;
    @c = 4
  } else if (@c < -5) {
    @dir = 1;
    @c = -4;
  }
}
```

```
Attached 2 probes


@:
             -5                                                  5
hh:mm:ss.ms  |___________________________________________________|
10:39:49.300 *                         .                         | -5
10:39:49.400 |    *                    .                         | -4
10:39:49.500 |         *               .                         | -3
10:39:49.600 |              *          .                         | -2
10:39:49.700 |                   *     .                         | -1
10:39:49.800 |                         *                         | 0
10:39:49.900 |                         .    *                    | 1
10:39:50.000 |                         .         *               | 2
10:39:50.100 |                         .              *          | 3
10:39:50.200 |                         .                   *     | 4
10:39:50.300 |                         .                         * 5
10:39:50.400 |                         .                   *     | 4
10:39:50.500 |                         .              *          | 3
10:39:50.600 |                         .         *               | 2
10:39:50.700 |                         .    *                    | 1
10:39:50.800 |                         *                         | 0
10:39:50.900 |                   *     .                         | -1
10:39:51.000 |              *          .                         | -2
10:39:51.100 |         *               .                         | -3
10:39:51.200 |    *                    .                         | -4
             v___________________________________________________v
             -5                                                  5
```

## Invocation Mode

There are three invocation modes for bpftrace built-in functions.

|     |     |     |
| --- | --- | --- |
| Mode | Description | Example functions |
| Synchronous | The value/effect of the built-in function is determined/handled right away by the bpf program in the kernel space. | `reg(), str(), ntop()` |
| Asynchronous | The value/effect of the built-in function is determined/handled later by the bpftrace process in the user space. | `printf(), clear(), exit()` |
| Compile-time | The value of the built-in function is determined before bpf programs are running. | `kaddr(), cgroupid(), offsetof()` |

While BPF in the kernel can do a lot there are still things that can only be done from user space, like the outputting (printing) of data.
The way bpftrace handles this is by sending events from the BPF program which user-space will pick up some time in the future (usually in milliseconds).
Operations that happen in the kernel are 'synchronous' ('sync') and those that are handled in user space are 'asynchronous' ('async')

The asynchronous behaviour can lead to some unexpected behavior as updates can happen before user space had time to process the event. The following situations may occur:

* event loss: when using printf(), the amount of data printed may be less than the actual number of events generated by the kernel during BPF program’s execution.
* delayed exit: when using the exit() to terminate the program, bpftrace needs to handle the exit signal asynchronously causing the BPF program may continue to run for some additional time.

One example is updating a map value in a tight loop:

```
BEGIN {
    @=0;
    unroll(10) {
      print(@);
      @++;
    }
    exit()
}
```

Maps are printed by reference not by value and as the value gets updated right after the print user-space will likely only see the final value once it processes the event:

```
@: 10
@: 10
@: 10
@: 10
@: 10
@: 10
@: 10
@: 10
@: 10
@: 10
```

Therefore, when you need precise event statistics, it is recommended to use synchronous functions (e.g. count() and hist()) to ensure more reliable and accurate results.
