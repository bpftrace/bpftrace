# BPFtrace

BPFtrace aims to be a [DTrace](http://dtrace.org)-style dynamic tracing tool for linux, based on the extended BPF capabilities available in recent Linux kernels. BPFtrace uses [LLVM](http://llvm.org) as a backend to compile scripts to BPF-bytecode and makes use of [BCC](https://github.com/iovisor/bcc) for interacting with the Linux BPF system.

## Examples

To produce a histogram of amount of time (in nanoseconds) spent in the `read()` system call:
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
[128k, 256k)           0 |                                                    |
[256k, 512k)           0 |                                                    |
[512k, 1M)             0 |                                                    |
[1M, 2M)               0 |                                                    |
[2M, 4M)               0 |                                                    |
[4M, 8M)               0 |                                                    |
[8M, 16M)              2 |                                                    |
```

## Builtins
Builtins can be assigned to maps and will either store a value or perform some action on the map.

Variables:
- `pid` - Process ID (kernel tgid)
- `tid` - Thread ID (kernel pid)
- `uid` - User ID
- `gid` - Group ID
- `nsecs` - Nanosecond timestamp
- `stack` - Kernel stack trace
- `arg0`, `arg1`, ... etc. - Arguments to the function being traced

Functions:
- `quantize(int n)` - produce a log2 histogram of values of `n`
- `count()` - count the number of times this function is called
- `delete()` - delete the map element this is assigned to

# Building

## Using Docker

Building BPFtrace inside a Docker container is the recommended method:

`./build.sh`

There are some more fine-grained options if you find yourself building BPFtrace a lot:
- `./build-docker.sh` - builds just the `bpftrace-builder` Docker image
- `./build-debug.sh` - builds BPFtrace with debugging information
- `./build-release.sh` - builds BPFtrace in a release configuration

`./build.sh` is equivalent to `./build-docker.sh && ./build-release.sh`

These build scripts pass on any command line arguments to `make` internally. This means specific targets can be built individually, e.g.:
- `./build.sh bpftrace` - build only the targets required for the bpftrace executable
- `./build.sh bcc-update` - update the copy of BCC used to build BPFtrace
- `./build.sh gtest-update` - update the copy of Google Test used to build the BPFtrace tests

The latest versions of BCC and Google Test will be downloaded on the first build. To update them later, the targets `bcc-update` and `gtest-update` can be built as shown above.

## Native build process

### Requirements

- A C++ compiler
- CMake
- Flex
- Bison
- LLVM 3.9 development packages

### Compilation
```
git clone https://github.com/ajor/bpftrace
mkdir -p bpftrace/build
cd bpftrace/build
cmake -DCMAKE_BUILD_TYPE=Debug ../
make
```
