# BPFtrace

BPFtrace aims to be a [DTrace](http://dtrace.org)-style dynamic tracing tool for linux, based on the extended BPF capabilities available in recent Linux kernels. BPFtrace uses [LLVM](http://llvm.org) as a backend to compile scripts to BPF-bytecode and makes use of [BCC](https://github.com/iovisor/bcc) for interacting with the Linux BPF system.

## Examples

BPFtrace is a work in progress and not all the features shown are currently available. The examples below are to give an idea of what the final result should be.

To produce a histogram of amount of time spent in the `read()` system call:
```
kprobe:sys_read
{
  @start[tid] = nsecs;
}

kretprobe:sys_read / @start[tid] /
{
  @times = quantize(nsecs - @start[tid]);
  @start[tid] = 0;
}
```

## Builtins
The list of available builtins will grow as more features are added.

The following builtin variables are available for use in BPFtrace scripts:
- `pid` - Process ID (kernel tgid)
- `tid` - Thread ID (kernel pid)
- `uid` - User ID
- `gid` - Group ID
- `nsecs` - Nanosecond timestamp

The following builtin functions will also be available in the future:
- `quantize()`
- `count()`

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
