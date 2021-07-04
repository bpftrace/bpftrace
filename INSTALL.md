# bpftrace Install

- [Linux Kernel Requirements](#linux-kernel-requirements)
- [Package install](#package-install)
  - [Ubuntu](#ubuntu-packages)
  - [Fedora](#fedora-package)
  - [Gentoo](#gentoo-package)
  - [Debian](#debian-package)
  - [openSUSE](#openSUSE-package)
  - [CentOS](#CentOS-package)
- [Docker images](#docker-images)
  - [Copying bpftrace binary docker](#copying-bpftrace-binary-from-docker)
  - [Kernel headers install](#kernel-headers-install)
- [Building bpftrace](#building-bpftrace)
  - [Ubuntu](#ubuntu)
  - [Fedora](#fedora)
  - [Amazon Linux](#amazon-linux)
  - (*please add sections for other OSes)*
  - [Using Docker](#using-docker)
  - [Generic build](#generic-build-process)
- [Disable Lockdown](#disable-lockdown)

# Linux Kernel Requirements

It is recommended that you are running a Linux 4.9 kernel or higher. Some tools may work on older kernels, but these old kernels are no longer tested. To explain this requirement, these are the kernel versions where major features were added:

- 4.1 - kprobes
- 4.3 - uprobes
- 4.6 - stack traces, count and hist builtins (use PERCPU maps for accuracy and efficiency)
- 4.7 - tracepoints
- 4.9 - timers/profiling

Minor improvements have been added in later kernels, so newer than 4.9 is preferred.

Your kernel also needs to be built with the following options:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_FUNCTION_TRACER=y
CONFIG_HAVE_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_HAVE_KPROBES=y
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_ARCH_SUPPORTS_UPROBES=y
CONFIG_UPROBES=y
CONFIG_UPROBE_EVENTS=y
CONFIG_DEBUG_FS=y
```

This can be verified by running the `check_kernel_features` script from the
`scripts` directory.

# Package install

## Ubuntu packages

```
sudo apt-get install -y bpftrace
```

Should work on Ubuntu 19.04 and later.

On Ubuntu 16.04 and later, bpftrace is also available as a snap package (https://snapcraft.io/bpftrace), however, the snap provides extremely limited file permissions so the --devmode option should be specified on installation in order avoid file access issues.

```
sudo snap install --devmode bpftrace
sudo snap connect bpftrace:system-trace
```

The snap package also currently has issues with uprobes ([#829](https://github.com/iovisor/bpftrace/issues/829)).

## Fedora package

For Fedora 28 (and later), bpftrace is already included in the official repo. Just install the package with dnf.

```
sudo dnf install -y bpftrace
```

## Gentoo package

On Gentoo, bpftrace is included in the official repo. The package can be installed with emerge.
```
sudo emerge -av bpftrace
```

## Debian package

Is available and tracked [here](https://tracker.debian.org/pkg/bpftrace).

## openSUSE package

Is available and tracked [here](https://software.opensuse.org/package/bpftrace).

## CentOS package

A build maintained by @fbs can be found
[here](https://github.com/fbs/el7-bpf-specs/blob/master/README.md#repository).

# Docker images

Each push to master will result in a docker image being built and pushed to
the quay.io container hosting service. This publishes the docker embedded build
linked to glibc, packaged in a minimal ubuntu container.

This allows for such an invocation of bpftrace:

```
$ docker run -ti -v /usr/src:/usr/src:ro \
       -v /lib/modules/:/lib/modules:ro \
       -v /sys/kernel/debug/:/sys/kernel/debug:rw \
       --net=host --pid=host --privileged \
       quay.io/iovisor/bpftrace:latest \
       tcplife.bt
Attaching 3 probes...
PID   COMM       LADDR           LPORT RADDR           RPORT TX_KB RX_KB MS
```

The following tags are published for all builds:

- `quay.io/iovisor/bpftrace:${GIT_SHA}-${TYPE_TAG}`- eg `69149e94952db2eea579ad40e15fbc67c7b810d5-vanilla_llvm_clang_glibc2.27`
- `quay.io/iovisor/bpftrace:${GIT_REF}-${TYPE_TAG}`- eg `master-vanilla_llvm_clang_glibc2.23` or `v0.9.5-vanilla_llvm_clang_glibc2.23`

If the build is on the master branch, it also publishes these additional tags:

- `quay.io/iovisor/bpftrace:${GIT_REF}`- eg `master` or `v0.9.5`
- `quay.io/iovisor/bpftrace:${GIT_SHA}`- eg `69149e94952db2eea579ad40e15fbc67c7b810d5`
- `quay.io/iovisor/bpftrace:latest`

If the build type name ends with `_edge`, and `EDGE=ON` is set, and the build
is on master, these tags are not pushed, and instead the `edge` tag is pushed:

- `quay.io/iovisor/bpftrace:edge`

This `:edge` build is likely less stable than `:latest` or tagged revisions,
but builds against bcc master and the latest LLVM supported by bpftrace. The
principal goal of the `:edge` build is to help detect integration issues early,
and make all latest features available, but that may also make it less stable
for day-to-day or production use.

If using floating tagged images, such as branch tags, `:latest`, or `:edge` or
`:master`, it may be necessary to run `docker pull` explicitly, to ensure that
the tag is updated.

The [full list of tags](https://quay.io/repository/iovisor/bpftrace?tab=tags) can
be used to search for tags, and the history of all tags is recorded on
[quay.io](https://quay.io/repository/iovisor/bpftrace?tab=history), and the
distributed images are regularly scanned by a vulnerability scanner.

## Copying bpftrace binary from docker

As docker builds produce a bpftrace binary on every push to master, they also
allow for a convenient way to distribute bpftrace binaries. The only software
requirement to run bpftrace  is a version of glibc that is the same or newer as
what it was built at.

For this reason, an older glibc - 2.23 is provided for all builds, it can be
pulled with:

```
docker pull quay.io/iovisor/bpftrace:master-vanilla_llvm_clang_glibc2.23
```

To copy the binary out of bpftrace in the current directory:

```
$ docker run -v $(pwd):/output quay.io/iovisor/bpftrace:master-vanilla_llvm_clang_glibc2.23 /bin/bash -c "cp /usr/bin/bpftrace /output"
$ ./bpftrace -V
v0.9.4
```

bpftrace currently links to glibc 2.27 from Ubuntu Bionic by default, though
this should be portably to any glibc-based OS, such as Fedora, Chromium OS, etc.

## Kernel headers install

Usually kernels headers can be installed from a system package manager. In some
cases though, this may not be an option, and headers aren't easily available.
For instance, the default `docker desktop` (as of writing ships with kernel
4.19 which supports bpf), benefits from this, as does Chromium OS and other
lightweight Linux distributions.

Newer kernels may have the IKHEADERS option, or support btf - in which case
there is no need to build these headers as the kernel provides this.
For older kernels, and on distributions where headers may not be available,
this script provides a generic means to get bpftrace kernel headers:

```bash
#!/bin/bash

set -e

KERNEL_VERSION="${KERNEL_VERSION:-$(uname -r)}"
kernel_version="$(echo "${KERNEL_VERSION}" | awk -vFS=- '{ print $1 }')"
major_version="$(echo "${KERNEL_VERSION}" | awk -vFS=. '{ print $1 }')"

apt-get install -y build-essential bc curl flex bison libelf-dev

mkdir -p /usr/src/linux
curl -sL "https://www.kernel.org/pub/linux/kernel/v${major_version}.x/linux-$kernel_version.tar.gz"     | tar --strip-components=1 -xzf - -C /usr/src/linux
cd /usr/src/linux
zcat /proc/config.gz > .config
make ARCH=x86 oldconfig
make ARCH=x86 prepare
mkdir -p /lib/modules/$(uname -r)
ln -sf /usr/src/linux /lib/modules/$(uname -r)/source
ln -sf /usr/src/linux /lib/modules/$(uname -r)/build
```

# Building bpftrace

bpftrace's build system will download `gtest` at build time. If you don't want that or don't want tests, you can use the `make bpftrace` target.

## Ubuntu

Due to the kernel requirements Ubuntu 18.04 or newer is highly recommended.

### 18.04 and 18.10

The versions of `bcc` currently available in Ubuntu 18.04 (Bionic) and 18.10
(Cosmic) do not have all the requirements for building `bpftrace` so building
`bcc` first is required. The instructions for building `bcc` can be found
[here](https://github.com/iovisor/bcc/blob/master/INSTALL.md#install-and-compile-bcc).
The build dependencies listed below are also required for `bcc` so install those first.

Make sure `bcc` works by testing some of the shipped tools before proceeding. It
might be required to `ldconfig` to update the linker.

### 19.04 and newer

The version of `bcc` available in Ubuntu 19.04 (Disco) is new enough so
compilation is not required, install with:

```
sudo apt-get install -y libbpfcc-dev
```

### Building `bpftrace`

```
sudo apt-get update
sudo apt-get install -y bison cmake flex g++ git libelf-dev zlib1g-dev libfl-dev systemtap-sdt-dev binutils-dev
sudo apt-get install -y llvm-7-dev llvm-7-runtime libclang-7-dev clang-7
git clone https://github.com/iovisor/bpftrace
mkdir bpftrace/build; cd bpftrace/build;
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j8
sudo make install
```

The bpftrace binary will be in installed in /usr/local/bin/bpftrace, and tools
in /usr/local/share/bpftrace/tools. You can change the install location using an
argument to cmake, where the default is `-DCMAKE_INSTALL_PREFIX=/usr/local`.

## Fedora

You'll want the newest kernel possible (see kernel requirements), eg, by using Fedora 28 or newer.

```
sudo dnf install -y bison flex cmake make git gcc-c++ elfutils-libelf-devel zlib-devel llvm-devel clang-devel bcc-devel systemtap-sdt-devel binutils-devel libbpf-devel gtest-devel gmock-devel
git clone https://github.com/iovisor/bpftrace
cd bpftrace
mkdir build; cd build; cmake -DCMAKE_BUILD_TYPE=Release ..
make -j8
sudo make install
```

The bpftrace binary will be in installed in /usr/local/bin/bpftrace, and tools in /usr/local/share/bpftrace/tools. You can change the install location using an argument to cmake, where the default is `-DCMAKE_INSTALL_PREFIX=/usr/local`.

## Amazon Linux

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

## Using Docker

There are currently problems with bpftrace string comparisons when using the Docker build. The regular build is recommended for now.

Building inside a Docker container will produce a statically linked bpftrace executable.

`./build.sh`

There are some more fine-grained options if you find yourself building bpftrace a lot:
- `./build-docker-image.sh` - builds just the `bpftrace-builder` Docker image
- `./build-debug.sh` - builds bpftrace with debugging information (requires `./build-docker-image.sh` to have already been run)
- `./build-release.sh` - builds bpftrace in a release configuration (requires `./build-docker-image.sh` to have already been run)

`./build.sh` is equivalent to `./build-docker-image.sh && ./build-release.sh`

## Generic build process

Use specific OS build sections listed earlier if available (Ubuntu, Docker).

### Requirements

- A C++ compiler
- CMake
- Flex
- Bison
- LLVM & Clang 5.0+ development packages
- BCC development package
- LibElf
- Binutils development package
- Kernel requirements described earlier

### Compilation

```
git clone https://github.com/iovisor/bpftrace
mkdir -p bpftrace/build
cd bpftrace/build
cmake -DCMAKE_BUILD_TYPE=Release ../
make
```

By default bpftrace will be built as a dynamically linked executable. If a statically linked executable would be preferred and your system has the required libraries installed, the CMake option `-DSTATIC_LINKING:BOOL=ON` can be used. Building bpftrace using the alpine Docker image below will result in a statically linked executable, and additional flags allow for compiling and statically linking the dependencies of bpftrace, see [the embedded build docs](./docs/embedded_builds.md) for more about this type of build. A debug build of bpftrace can be set up with `cmake -DCMAKE_BUILD_TYPE=Debug ../`.

The latest version of Google Test will be downloaded on each build. To speed up builds and only download its source on the first run, use the CMake option `-DOFFLINE_BUILDS:BOOL=ON`.

To test that the build works, you can try running the test suite, and a one-liner:

```
./tests/bpftrace_test
./src/bpftrace -e 'kprobe:do_nanosleep { printf("sleep by %s\n", comm); }'
```

# Disable Lockdown

From the original patch set description:

> This patchset introduces an optional kernel lockdown feature, intended
> to strengthen the boundary between UID 0 and the kernel. When enabled,
> various pieces of kernel functionality are restricted. Applications that
> rely on low-level access to either hardware or the kernel may cease
> working as a result - therefore this should not be enabled without
> appropriate evaluation beforehand.
>
> The majority of mainstream distributions have been carrying variants of
> this patchset for many years now, so there's value in providing a
> doesn't meet every distribution requirement, but gets us much closer to
> not requiring external patches.
>
>   - https://patchwork.kernel.org/patch/11140085/

When lockdown is enabled and set to 'confidentiality' all methods that can
extract confidential data from the kernel are blocked. This means that:

- kprobes are blocked
- tracefs access is blocked
- probe_read and probe_read_str are blocked

which makes it impossible for bpftrace to function.

There are a few ways to disable lockdown.

1. Disable secure boot in UEFI.
2. Disable validation using mokutil, run the following command, reboot and
   follow the prompt.
```
$ sudo mokutil --disable-validation
```
3. Use the `SysRQ+x` key combination to temporarily lift lockdown (until next
   boot)
