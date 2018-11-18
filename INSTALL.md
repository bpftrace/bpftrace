# BPFtrace Install

- [Linux Kernel Requirements](#linux-kernel-requirements)
- [Building BPFtrace](#building-bpftrace)
  - [Ubuntu](#ubuntu)
  - [Fedora](#fedora)
  - [Amazon Linux](#amazon-linux)
  - (*please add sections for other OSes)*
  - [Using Docker](#using-docker)
  - [Generic build](#generic-build)
- [Package install](#package-install)
  - [Fedora](#fedora-package)

# Linux Kernel Requirements

Your kernel needs to be built with the following options:
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
```

To use some BPFtrace features, minimum kernel versions are required:
- 4.1+ - kprobes
- 4.3+ - uprobes
- 4.6+ - stack traces, count and hist builtins (use PERCPU maps for accuracy and efficiency)
- 4.7+ - tracepoints
- 4.9+ - timers/profiling


# Building BPFtrace

# Ubuntu

You'll want the newest kernel possible (see kernel requirements), eg, by using Ubuntu 18.04 LTS (Bionic Beaver) or newer.

The llvm/clang packages that are currently available for Ubuntu have an issue (see [#76](https://github.com/iovisor/bpftrace/issues/76)), so we'll use the ones from llvm.org for now. The build instructions are:

```
# see https://apt.llvm.org/ for the following archive signature:
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
cat <<EOF | sudo tee -a /etc/apt/sources.list
# from https://apt.llvm.org/:
deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial main
deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial main
# 5.0
deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-5.0 main
deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-5.0 main
# 6.0
deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-6.0 main
deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-6.0 main
EOF
sudo apt-get update
sudo apt-get install -y bison cmake flex g++ git libelf-dev zlib1g-dev libfl-dev
sudo apt-get install clang-5.0 libclang-5.0-dev libclang-common-5.0-dev libclang1-5.0 libllvm5.0 llvm-5.0 llvm-5.0-dev llvm-5.0-runtime
git clone https://github.com/iovisor/bpftrace
cd bpftrace
mkdir build; cd build; cmake -DCMAKE_BUILD_TYPE=DEBUG ..
make -j8
make install
```

The bpftrace binary will be in installed in /usr/local/bin/bpftrace, and tools in /usr/local/share/bpftrace/tools. You can change the install location using an argument to cmake, where the default is `-DCMAKE_INSTALL_PREFIX=/usr/local`.

# Fedora

You'll want the newest kernel possible (see kernel requirements), eg, by using Fedora 28 or newer.

```
sudo dnf install -y bison flex cmake make git gcc-c++ elfutils-libelf-devel zlib-devel llvm-devel clang-devel
git clone https://github.com/iovisor/bpftrace
cd bpftrace
mkdir build; cd build; cmake -DCMAKE_BUILD_TYPE=DEBUG ..
make -j8
make install
```

The bpftrace binary will be in installed in /usr/local/bin/bpftrace, and tools in /usr/local/share/bpftrace/tools. You can change the install location using an argument to cmake, where the default is `-DCMAKE_INSTALL_PREFIX=/usr/local`.

# Amazon Linux

In the future the install should be `yum install bpftrace`. Right now (16-Oct-2018), however, three dependencies need updating in the Amazon Linux repositories (llvm, libtinfo, bison), and bpftrace itself needs to be packaged. The current workaround is to build the three dependencies manually, as well as bpftrace. It's not fun, but it is doable, and will only get better as Amazon updates things.

```
sudo bash
builddir=/media/ephemeral0	# change to suit your system: needs about 2 Gbytes free

# dependencies
yum install git cmake3 gcc64-c++.x86_64 bison flex

# llvm
cd $builddir
wget http://releases.llvm.org/6.0.0/clang+llvm-6.0.0-x86_64-linux-gnu-Fedora27.tar.xz
tar xf clang*
(cd clang* && sudo cp -R * /usr/local/)
cp -p /usr/lib64/llvm6.0/lib/libLLVM-6.0.so /usr/lib64/libLLVM.so

# libtinfo.so.6 (comes from ncurses)
cd $builddir
wget ftp://ftp.gnu.org/gnu/ncurses/ncurses-6.0.tar.gz
tar xvf ncurses-6.0.tar.gz
cd ncurses-6.0
./configure --with-shared --with-termlib
make -j8
make install

# bison
cd $builddir
wget http://ftp.gnu.org/gnu/bison/bison-3.1.tar.gz
tar xf bison*
cd bison*
./configure
make -j4
make install

# bpftrace
cd $builddir
git clone https://github.com/iovisor/bpftrace
cd bpftrace
mkdir build; cd build
cmake3 ..
make -j8
make install
echo /usr/local/lib >> /etc/ld.so.conf
ldconfig -v
```

The bpftrace binary will be in installed in /usr/local/bin/bpftrace, and tools in /usr/local/share/bpftrace/tools. You may need to add /usr/local/bin to your $PATH. You can also change the install location using an argument to cmake, where the default is `-DCMAKE_INSTALL_PREFIX=/usr/local`.

# Using Docker

There are currently problems with BPFtrace string comparisons when using the Docker build. The regular build is recommended for now.

Building inside a Docker container will produce a statically linked bpftrace executable.

`./build.sh`

There are some more fine-grained options if you find yourself building BPFtrace a lot:
- `./build-docker-image.sh` - builds just the `bpftrace-builder` Docker image
- `./build-debug.sh` - builds BPFtrace with debugging information (requires `./build-docker-image.sh` to have already been run)
- `./build-release.sh` - builds BPFtrace in a release configuration (requires `./build-docker-image.sh` to have already been run)

`./build.sh` is equivalent to `./build-docker-image.sh && ./build-release.sh`

## Generic build process

Use specific OS build sections listed earlier if available (Ubuntu, Docker).

### Requirements

- A C++ compiler
- CMake
- Flex
- Bison
- LLVM & Clang 5.0 (or 6.0) development packages
- LibElf
- Kernel requirements described earlier

### Compilation

```
git clone https://github.com/iovisor/bpftrace
mkdir -p bpftrace/build
cd bpftrace/build
cmake -DCMAKE_BUILD_TYPE=Debug ../
make
```

By default bpftrace will be built as a dynamically linked executable. If a statically linked executable would be preferred and your system has the required libraries installed, the CMake option `-DSTATIC_LINKING:BOOL=ON` can be used. Building bpftrace using the Docker method below will always result in a statically linked executable.

The latest versions of BCC and Google Test will be downloaded on each build. To speed up builds and only download their sources on the first run, use the CMake option `-DOFFLINE_BUILDS:BOOL=ON`.

To test that the build works, you can try running the test suite, and a one-liner:

```
./tests/bpftrace_test
./src/bpftrace -e 'kprobe:do_nanosleep { printf("sleep by %s\n", comm); }'
```

# Package install

## Fedora package

For Fedora 28 (and later), bpftrace is already included in the official repo. Just install the package with dnf.

```
sudo dnf install bpftrace
```
