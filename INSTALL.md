# Linux Kernel

Your kernel needs to be built with the following options:
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_BPF_JIT=y
CONFIG_BPF_EVENTS=y
```

To use some BPFtrace features, minimum kernel versions are required:
- 4.1+ - kprobes
- 4.3+ - uprobes
- 4.6+ - stack traces, count and quantize builtins (use PERCPU maps for accuracy and efficiency)
- 4.7+ - tracepoints
- 4.9+ - timers/profiling


# Building BPFtrace

## Native build process

### Requirements

- A C++ compiler
- CMake
- Flex
- Bison
- LLVM & Clang 5.0 development packages
- LibElf

For example, installing the requirements on Ubuntu:

```
apt-get update
apt-get install -y bison cmake flex g++ git libclang-5.0-dev libelf-dev llvm-5.0-dev zlib1g-dev
```

### Compilation

See previous requirements.

```
git clone https://github.com/ajor/bpftrace
mkdir -p bpftrace/build
cd bpftrace/build
cmake -DCMAKE_BUILD_TYPE=Debug ../
make
```

By default bpftrace will be built as a dynamically linked executable. If a statically linked executable would be preferred and your system has the required libraries installed, the CMake option `-DSTATIC_LINKING:BOOL=ON` can be used. Building bpftrace using the Docker method below will always result in a statically linked executable.

The latest versions of BCC and Google Test will be downloaded on each build. To speed up builds and only download their sources on the first run, use the CMake option `-DOFFLINE_BUILDS:BOOL=ON`.

## Using Docker

Building inside a Docker container will produce a statically linked bpftrace executable.

`./build.sh`

There are some more fine-grained options if you find yourself building BPFtrace a lot:
- `./build-docker.sh` - builds just the `bpftrace-builder` Docker image
- `./build-debug.sh` - builds BPFtrace with debugging information
- `./build-release.sh` - builds BPFtrace in a release configuration

`./build.sh` is equivalent to `./build-docker.sh && ./build-release.sh`
