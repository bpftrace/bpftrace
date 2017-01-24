# BPFtrace

BPFtrace aims to be a [DTrace](http://dtrace.org)-style dynamic tracing tool for linux, based on the extended BPF capabilities available in recent Linux kernels. BPFtrace uses [LLVM](http://llvm.org) to compile scripts to BPF-bytecode and many helper functions are included from [BCC](https://github.com/iovisor/bcc).

BPFtrace's scripting language is inspired by [ply](https://github.com/iovisor/ply) and DTrace.

## Examples

BPFtrace is a work in progress and can not currently run scripts. The examples below are to give an idea of what the final result should be.

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
- `pid` - Process ID
- `tid` - Thread ID
- `nsecs` - Get a nanosecond timestamp

The following builtin functions are also available:
- `quantize()`
- `count()`

# Building

## Requirements
- A C++ compiler
- CMake
- Flex
- Bison
- LLVM

## Compilation
Compile using CMake, optionally substituting "Release" for "Debug" as CMAKE\_BUILD\_TYPE:
```
git clone https://github.com/ajor/bpftrace
cd bpftrace
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ../src
make
```
