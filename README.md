# BPFtrace

BPFtrace is currently a work in progress and can not currently run scripts. The examples below are to give an idea of what the final result should be.

## Examples

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
git clone https://github.com/ajor/bpftrace.git
cd bpftrace
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ../src
make
```
