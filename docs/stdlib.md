# bpftrace Standard Library

This includes builtins, functions, macros, and [map value functions](#map-value-functions).
The boundaries for the first three are blurred, by design, to allow for more flexible usage and are grouped below as "Helpers".
For example `pid` and `pid()` are equivalent; both yielding the process id.
Basically all functions or macros that don't have arguments or have default arguments can be invoked with or without the call syntax.

**async** helpers are asynchronous, which can lead to unexpected behaviour. See the [Invocation Mode](#invocation-mode) section for more information.

**compile time** helpers are evaluated at compile time, a static value will be compiled into the program.

**unsafe** helpers can have dangerous side effects and should be used with care, the `--unsafe` flag is required for use.

## Helpers

### assert
- `void assert(bool condition, string message)`

Simple assertion macro that will exit the entire script with an error code if the condition is not met.


### assert_str

Checks that this value is string-like.


### bswap
- `uint8 bswap(uint8 n)`
- `uint16 bswap(uint16 n)`
- `uint32 bswap(uint32 n)`
- `uint64 bswap(uint64 n)`

`bswap` reverses the order of the bytes in integer `n`. In case of 8 bit integers, `n` is returned without being modified.
The return type is an unsigned integer of the same width as `n`.


### buf
- `buffer buf(void * data, [int64 length])`

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
- `void cat(string namefmt, [...args])`

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


### cgroup
- `uint64 cgroup()`
- `uint64 cgroup`

ID of the cgroup the current process belongs to

Only works with cgroupv2

This utilizes the BPF helper `get_current_cgroup_id`


### cgroup_path
- `cgroup_path_t cgroup_path(int cgroupid, string filter)`

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


### cgroupid
- `uint64 cgroupid(const string path)`

**compile time**

`cgroupid` retrieves the cgroupv2 ID  of the cgroup available at `path`.

```
BEGIN {
  print(cgroupid("/sys/fs/cgroup/system.slice"));
}
```


### clear
- `void clear(map m)`

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


### comm
- `string comm()`
- `string comm`
- `string comm(uint32 pid)`

Name of the current thread or the process with the specified PID

This utilizes the BPF helper `get_current_comm`


### cpid
- `uint32 cpid()`
- `uint32 cpid`

Child process ID, if bpftrace is invoked with `-c`


### cpu
- `uint32 cpu()`
- `uint32 cpu`

ID of the processor executing the BPF program

BPF program, in this case, is the probe body

This utilizes the BPF helper `raw_smp_processor_id`


### curtask
- `uint64 curtask()`
- `uint64 curtask`

Pointer to `struct task_struct` of the current task

This utilizes the BPF helper `get_current_task`


### default_str_length

Returns the default unbounded length.


### delete
- `bool delete(map m, mapkey k)`
- deprecated `bool delete(mapkey k)`

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


### elapsed
- `uint64 elapsed()`
- `uint64 elapsed`

ktime_get_ns - ktime_get_boot_ns


### errorf
- `void errorf(const string fmt, args...)`

**async**

`errorf()` formats and prints data (similar to [`printf`](#printf)) as an error message with the source location.

```
BEGIN { errorf("Something bad with args: %d, %s", 10, "arg2"); }
```

Prints:

```
EXPECT stdin:1:9-62: ERROR: Something bad with args: 10, arg2
```


### exit
- `void exit([int code])`

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


### fail
- `void fail(const string fmt, args...)`

`fail()` formats and prints data (similar to [`printf`](#printf)) as an error message with the source location but, as opposed to [`errorf`](#errorf), is treated like a static assert and halts compilation if it is visited. All args have to be literals since they are evaluated at compile time.

```
BEGIN { if ($1 < 2) { fail("Expected the first positional param to be greater than 1. Got %d", $1); } }
```



### func
- `string func()`
- `string func`

Name of the current function being traced (kprobes,uprobes,fentry)


### getopt
- `bool getopt(string arg_name)`
- `string getopt(string arg_name, string default_value)`
- `int getopt(string arg_name, int default_value)`
- `bool getopt(string arg_name, bool default_value)`

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


### gid
- `uint64 gid()`
- `uint64 gid`

Group ID of the current thread, as seen from the init namespace

This utilizes the BPF helper `get_current_uid_gid`


### has_key
- `boolean has_key(map m, mapkey k)`

Return `true` if the key exists in this map.
Otherwise return `false`.
Error if called with a map that has no keys (aka scalar map).

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
}
```


### is_array
- `bool is_array(any expression)`

Determine whether the given expression is an array.


### is_integer
- `bool is_integer(any expression)`

Determine whether the given expression is an integer.


### is_literal
- `bool is_literal(Expression expr)`

Returns true if the passed expression is a literal, e.g. 1, true, "hello"


### is_ptr
- `bool is_ptr(any expression)`

Determine whether the given expression is a pointer.


### is_str
- `bool is_str(any expression)`

Determine whether the given expression is a string.


### is_unsigned_integer
- `bool is_unsigned_integer(any expression)`

Determine whether the given expression is an unsigned integer.


### jiffies
- `uint64 jiffies()`
- `uint64 jiffies`

Jiffies of the kernel

On 32-bit systems, using this builtin might be slower

This utilizes the BPF helper `get_jiffies_64`


### join
- `void join(char *arr[], [char * sep = ' '])`

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
- `uint64 kaddr(const string name)`

**compile time**

Get the address of the kernel symbol `name`.

```
interval:s:1 {
  $avenrun = kaddr("avenrun");
  $load1 = *$avenrun;
}
```

You can find all kernel symbols at `/proc/kallsyms`.


### kfunc_allowed
- `boolean kfunc_allowed(const string kfunc)`

Determine if a kfunc is supported for particular probe types.


### kfunc_exist
- `boolean kfunc_exist(const string kfunc)`

Determine if a kfunc exists using BTF.


### kptr
- `T * kptr(T * ptr)`

Marks `ptr` as a kernel address space pointer.
See the address-spaces section for more information on address-spaces.
The pointer type is left unchanged.


### kstack
- `kstack_t kstack([StackMode mode, ][int limit])`

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
- `ksym_t ksym(uint64 addr)`

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
- `int64 len(map m)`
- `int64 len(ustack stack)`
- `int64 len(kstack stack)`

For maps, return the number of elements in the map.

For kstack/ustack, return the depth (measured in # of frames) of the call stack.


### macaddr
- `macaddr_t macaddr(char [6] mac)`

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


### memcmp
- `int memcmp(left, right, uint64 count)`

Compares the first 'count' bytes of two expressions.
0 is returned if they are the same.
negative value if the first differing byte in left is less
than the corresponding byte in right.



### ncpus
- `uint64 ncpus()`
- `uint64 ncpus`

Number of CPUs


### nsecs
- `timestamp nsecs([TimestampMode mode])`
- `nsecs(monotonic) - nanosecond timestamp since boot, exclusive of time the system spent suspended (CLOCK_MONOTONIC)`
- `nsecs(boot) - nanoseconds since boot, inclusive of time the system spent suspended (CLOCK_BOOTTIME)`
- `nsecs(tai) - TAI timestamp in nanoseconds (CLOCK_TAI)`
- `nsecs(sw_tai) - approximation of TAI timestamp in nanoseconds, is obtained through the "triple vdso sandwich" method. For older kernels without direct TAI timestamp access in BPF.`

Returns a timestamp in nanoseconds, as given by the requested kernel clock.
Defaults to `boot` if no clock is explicitly requested.


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
- `inet ntop([int64 af, ] int addr)`
- `inet ntop([int64 af, ] char addr[4])`
- `inet ntop([int64 af, ] char addr[16])`

`ntop` returns the string representation of an IPv4 or IPv6 address.
`ntop` will infer the address type (IPv4 or IPv6) based on the `addr` type and size.
If an integer or `char[4]` is given, ntop assumes IPv4, if a `char[16]` is given, ntop assumes IPv6.
You can also pass the address type (e.g. AF_INET) explicitly as the first parameter.


### numaid
- `uint32 numaid()`
- `uint32 numaid`

ID of the NUMA node executing the BPF program

BPF program, in this case, is the probe body

This utilizes the BPF helper `numa_node_id`


### offsetof
- `uint64 offsetof(STRUCT, FIELD[.SUBFIELD])`
- `uint64 offsetof(EXPRESSION, FIELD[.SUBFIELD])`

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
- `void override(uint64 rc)`

**unsafe**

**Kernel** 4.16

This utilizes the BPF helper `bpf_override`

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
- `char * path(struct path * path [, int32 size])`

**Kernel** 5.10

This utilizes the BPF helper `bpf_d_path`

Return full path referenced by struct path pointer in argument. If `size` is set,
the path will be clamped by `size` otherwise `BPFTRACE_MAX_STRLEN` is used.

If `size` is smaller than the resolved path, the resulting string will be truncated at the front rather than at the end.

This function can only be used by functions that are allowed to, these functions are contained in the `btf_allowlist_d_path` set in the kernel.


### pcomm
- `string pcomm()`
- `string pcomm`
- `string pcomm(struct task_struct * task)`

Get the name of the process for the passed task or the current task if called without arguments. This is an alias for (task->group_leader->comm).


### percpu_kaddr
- `uint64 *percpu_kaddr(const string name)`
- `uint64 *percpu_kaddr(const string name, int cpu)`

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
    print($runqueues.nr_running);
  }
}
```


### pid
- `uint32 pid([curr_ns|init])`
- `uint32 pid`

Returns the process ID of the current thread.
Defaults to `curr_ns`.

* `pid(curr_ns)` - The process ID as seen from the PID namespace of bpftrace.
* `pid(init)` - The process ID as seen from the initial PID namespace.


### ppid
- `uint32 ppid()`
- `uint32 ppid`
- `uint32 ppid(struct task_struct * task)`

Get the pid of the parent process for the passed task or the current task if called without arguments.


### print
- `void print(T val)`
- `void print(T val)`
- `void print(@map)`
- `void print(@map, uint64 top)`
- `void print(@map, uint64 top, uint64 div)`

**async**

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
  for $elem : 1..$i {
    @[$elem] = $elem-1;
  }
  print(@, 2);
  clear(@);
  exit()
}

/*
 * Sample output:
 * @[9]: 8
 * @[10]: 9
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
- `void printf(const string fmt, args...)`

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


### probe
- `string probe()`
- `string probe`

Name of the fully expanded probe

For example: `kprobe:do_nanosleep`


### probetype
- `string probetype()`
- `string probetype`

Name of the probe type.
Note: `begin` and `end` probes are of type `special`.

For example: `kprobe`, `special`, `tracepoint`


### pton
- `char addr[4] pton(const string *addr_v4)`
- `char addr[16] pton(const string *addr_v6)`

**compile time**

`pton` converts a text representation of an IPv4 or IPv6 address to byte array.
`pton` infers the address family based on `.` or `:` in the given argument.
`pton` comes in handy when we need to select packets with certain IP addresses.


### rand
- `uint32 rand()`
- `uint32 rand`

Get a pseudo random number

This utilizes the BPF helper `get_prandom_u32`


### reg
- `uint64 reg(const string name)`

**Supported probes**

* kprobe
* uprobe

Get the contents of the register identified by `name`.
Valid names depend on the CPU architecture.


### retval
- `uint64 retval()`
- `uint64 retval`

Value returned by the function being traced

(kretprobe, uretprobe, fexit)
For kretprobe and uretprobe, its type is uint64, but for fexit it depends. You can look up the type using `bpftrace -lv`


### signal
- `void signal(const string sig)`
- `void signal(uint32 signum)`

**unsafe**

This utilizes the BPF helper `bpf_send_signal`.

Probe types: k(ret)probe, u(ret)probe, USDT, profile

Send a signal to the process being traced (any thread).
Use `signal_thread` to send to the thread being traced.
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


### signal_thread
- `void signal_thread(const string sig)`
- `void signal_thread(uint32 signum)`

**unsafe**

This utilizes the BPF helper `bpf_send_signal_thread`.

Probe types: k(ret)probe, u(ret)probe, USDT, profile

Send a signal to the thread being traced.
Use `signal` to send to the process being traced (any thread).
The signal can either be identified by name, e.g. `SIGSTOP` or by ID, e.g. `19` as found in `kill -l`.


### sizeof
- `uint64 sizeof(TYPE)`
- `uint64 sizeof(EXPRESSION)`

**compile time**

Returns size of the argument in bytes.
Similar to C/C++ `sizeof` operator.
Note that the expression does not get evaluated.


### skboutput
- `uint32 skboutput(const string path, struct sk_buff *skb, uint64 length, const uint64 offset)`

**Kernel** 5.5

This utilizes the BPF helper `bpf_skb_output`

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
  $ret = skboutput("receive.pcap", args.skb, args.skb.len, 0);
}

fentry:dev_queue_xmit {
  // setting offset to 14, to exclude ethernet header
  $ret = skboutput("output.pcap", args.skb, args.skb.len, 14);
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
- `uint64 socket_cookie(struct sock *sk)`

This utilizes the BPF helper `bpf_get_socket_cookie`

Retrieve the cookie (generated by the kernel) of the socket.
If no cookie has been set yet, generate a new cookie. Once generated, the socket cookie remains stable for the life of the socket.

This function returns a `uint64` unique number on success, or 0 if **sk** is NULL.

```
fentry:tcp_rcv_established
{
  $cookie = socket_cookie(args.sk);
  @psize[$cookie] = hist(args.skb.len);
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


### static_assert
- `void static_assert(bool condition, string msg)`

Assert something is true or fail the build.


### str
- `string str(char * data [, uint32 length)`

This utilizes the BPF helpers `probe_read_str, probe_read_{kernel,user}_str`

`str` reads a NULL terminated (`\0`) string from `data`.
The maximum string length is limited by the `BPFTRACE_MAX_STRLEN` env variable, unless `length` is specified and shorter than the maximum.
In case the string is longer than the specified length only `length - 1` bytes are copied and a NULL byte is appended at the end.

bpftrace will automatically use the `kernel` or `user` variant of `probe_read_{kernel,user}_str` based on the address space of `data`, see [Address-spaces](./language.md#address-spaces) for more information.


### strcap
- `int64 strcap(string exp)`
- `int64 strcap(int8 exp[])`
- `int64 strcap(int8 *exp)`

Returns the "capacity" of a string-like object.

In most cases this is the same as the length, but for bpftrace-native
strings and arrays, this is the underlying object capacity. This is used to
bound searches and lookups without needing to scan the string itself.


### strcontains
- `bool strcontains(string haystack, string needle)`

Compares whether the string haystack contains the string needle.

If needle is contained then true is returned, else false is returned.


### strerror
- `string strerror(int error)`

Convert errno code to string.

```
#include <errno.h>
begin {
  print(strerror(EPERM));
}
```


### strftime
- `timestamp strftime(const string fmt, int64 timestamp_ns)`

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


### strlen
- `uint64 strlen(string exp)`
- `uint64 strlen(int8 exp[])`
- `uint64 strlen(int8 *exp)`

Returns the length of a string-like object.


### strncmp
- `int64 strncmp(char * s1, char * s2, int64 n)`

`strncmp` compares up to `n` characters string `s1` and string `s2`.
If they’re equal `0` is returned, else a non-zero value is returned.

bpftrace doesn’t read past the length of the shortest string.

The use of the `==` and `!=` operators is recommended over calling `strncmp` directly.


### strstr
- `int64 strstr(string haystack, string needle)`

Returns the index of the first occurrence of the string needle in the string haystack. If needle is not in haystack then -1 is returned.


### syscall_name
- `string syscall_name(int nr_syscall)`

Convert syscall number to string.

```
#include <syscall.h>
begin {
  print(syscall_name(__NR_read)); // outputs "read"
}
```


### system
- `void system(string namefmt [, ...args])`

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


### tid
- `uint32 tid([curr_ns|init])`
- `uint32 tid`

Returns the thread ID of the current thread.
Defaults to `curr_ns`.

* `tid(curr_ns)` - The thread ID as seen from the PID namespace of bpftrace.
* `tid(init)` - The thread ID as seen from the initial PID namespace.


### time
- `void time(const string fmt)`

**async**

Format the current wall time according to the format specifier `fmt` and print it to stdout.
Unlike `strftime()` `time()` doesn’t send a timestamp from the probe, instead it is the time at which user-space processes the event.

bpftrace uses the `strftime(3)` function for formatting time and supports the same format specifiers.


### uaddr
- `T * uaddr(const string sym)`

**Supported probes**

* uprobes
* uretprobes
* USDT

If kernel supports task_vma open-coded iterator kfuncs (linux >= 6.7), uaddr() will correct the symbol addresses of PIE and dynamic libraries instead of directly using the symbol addresses in the ELF file, see https://github.com/torvalds/linux/commit/4ac454682158.

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


### uid
- `uint64 uid()`
- `uint64 uid`

User ID of the current thread, as seen from the init namespace

This utilizes the BPF helper `get_current_uid_gid`


### unwatch
- `void unwatch(void * addr)`

**async**

Removes a watchpoint


### uptr
- `T * uptr(T * ptr)`

Marks `ptr` as a user address space pointer.
See the address-spaces section for more information on address-spaces.
The pointer type is left unchanged.


### usermode
- `uint8 usermode()`
- `uint8 usermode`

Returns 1 if the current process is in user mode, 0 otherwise

Currently only available on x86_64.


### username
- `string username()`
- `string username`

Get the current username

Often this is just "root"


### ustack
- `ustack_t ustack([StackMode mode, ][int limit])`

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
- `usym_t usym(uint64 * addr)`

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


### warnf
- `void warnf(const string fmt, args...)`

**async**

`warnf()` formats and prints data (similar to [`printf`](#printf)) as an warning message with the source location. This respects the "--no-warnings" flag and will be silent if that is used.

```
BEGIN { warnf("Something kinda bad with args: %d, %s", 10, "arg2"); }
```

Prints:

```
EXPECT stdin:1:9-62: WARNING: Something kinda bad with args: 10, arg2
```


### zero
- `void zero(map m)`

**async**

Set all values (for all keys) in the map to zero.


## Map Value Functions

Map value functions can only be assigned to maps (when scalar) or map keys.
The data types associated with these functions are only for internal use but many can be cast to integers (e.g. `count_t` and `sum_t`).

### avg

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

### count

* `count_t count()`

Count how often this function is called.

Using `@=count()` is conceptually similar to `@++`.
The difference is that the `count()` function uses a map type optimized for
performance and correctness using cheap, thread-safe writes ([PERCPU](./language.md#percpu-types)). However, sync reads
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

### hist

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

### lhist

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

* `max_t max(int64 n)`

Update the map with `n` if `n` is bigger than the current value held.
Similar to `count` this uses a [PERCPU](./language.md#percpu-types) map (thread-safe, fast writes, slow reads).

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

* `min_t min(int64 n)`

Update the map with `n` if `n` is smaller than the current value held.
Similar to `count` this uses a [PERCPU](./language.md#percpu-types) map (thread-safe, fast writes, slow reads).

See `max()` above for how this differs from the typical userspace `min()`.

### stats

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

* `sum_t sum(int64 n)`

Calculate the sum of all `n` passed.

Using `@=sum(5)` is conceptually similar to `@+=5`.
The difference is that the `sum()` function uses a map type optimized for
performance and correctness using cheap, thread-safe writes ([PERCPU](./language.md#percpu-types)). However, sync reads
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

### tseries

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
