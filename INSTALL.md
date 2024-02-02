# bpftrace Install

- [Linux Kernel Requirements](#linux-kernel-requirements)
- [Kernel headers install](#kernel-headers-install)
- [Package install](#package-install)
  - [Ubuntu](#ubuntu-packages)
  - [Fedora](#fedora-package)
  - [Gentoo](#gentoo-package)
  - [Debian](#debian-package)
  - [openSUSE](#openSUSE-package)
  - [CentOS](#CentOS-package)
  - [Arch](#arch-package)
  - [Alpine](#alpine-package)
- [AppImage install](#appimage-install)
- [Building bpftrace](#building-bpftrace)
  - [Ubuntu](#ubuntu)
  - [Fedora](#fedora)
  - [Debian](#debian)
  - [Amazon Linux](#amazon-linux)
  - (*please add sections for other OSes)*
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

# Kernel headers install

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
curl -sL "https://www.kernel.org/pub/linux/kernel/v${major_version}.x/linux-$kernel_version.tar.gz" \
  | tar --strip-components=1 -xzf - -C /usr/src/linux
cd /usr/src/linux
zcat /proc/config.gz > .config
make ARCH=x86 oldconfig
make ARCH=x86 prepare
mkdir -p /lib/modules/$(uname -r)
ln -sf /usr/src/linux /lib/modules/$(uname -r)/source
ln -sf /usr/src/linux /lib/modules/$(uname -r)/build
```

# Package install

## Ubuntu packages

```
sudo apt-get install -y bpftrace
```

Should work on Ubuntu 19.04 and later.

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

## Arch package

In Arch Linux, bpftrace is available in the official repositories.
```
sudo pacman -S bpftrace
```

## Alpine package

bpftrace is available in Alpine's official `community` repository:

```
sudo apk add bpftrace
```

To install tools and documentation:

```
sudo apk add bpftrace-doc bpftrace-tools bpftrace-tools-doc
```

# AppImage install

[AppImages](https://appimage.org/) are a portable way to distribute Linux
applications. To the user, they are functionally equivalent to statically
linked binaries.

bpftrace currently ships AppImages in two locations:

* in artifacts on official releases
* as a CI artifact for every build on master

To download the official release artifacts, see the
[latest release](https://github.com/bpftrace/bpftrace/releases/latest).

To download the bleeding edge AppImage, go to the
[workflow page](https://github.com/bpftrace/bpftrace/actions/workflows/binary.yml)
and select the latest run. You should find an uploaded artifact like below:

<img src="./images/ci_appimage_artifact.png" width="40%" height="40%">

Note that Github will automatically place all build artifacts in a .zip (it's
out of our control) so remember to unzip it first.

# Building bpftrace

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

For 19.04 and newer, please see the [regularly exercised Dockerfile](./docker/Dockerfile.ubuntu)
for documentation on how to build bpftrace on Ubuntu.

## Fedora

You'll want the newest kernel possible (see kernel requirements), eg, by using
Fedora 28 or newer.

Please see the [regularly exercised Dockerfile](./docker/Dockerfile.fedora)
for documentation on how to build bpftrace on Fedora.

## Debian

Please see the [regularly exercised Dockerfile](./docker/Dockerfile.debian)
for documentation on how to build bpftrace on Debian.

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
git clone https://github.com/bpftrace/bpftrace
cd bpftrace
mkdir build; cd build
cmake3 ..
make -j8
make install
echo /usr/local/lib >> /etc/ld.so.conf
ldconfig -v
```

The bpftrace binary will be in installed in /usr/local/bin/bpftrace, and tools in /usr/local/share/bpftrace/tools. You may need to add /usr/local/bin to your $PATH. You can also change the install location using an argument to cmake, where the default is `-DCMAKE_INSTALL_PREFIX=/usr/local`.

## Generic build process

Use specific OS build sections listed earlier if available.

### Requirements

- A C++ compiler
- Libbpf
- Libbcc
- CMake
- Flex
- Bison
- Asciidoctor
- LLVM & Clang 10.0+ development packages
- LibElf
- LibDw
- Binutils development package
- Libcereal
- Kernel requirements described earlier
- Libpcap
- Systemtap SDT headers
- Zlib development package

### Compilation

```
git clone https://github.com/bpftrace/bpftrace
mkdir -p bpftrace/build
cd bpftrace/build
cmake -DCMAKE_BUILD_TYPE=Release ../
make
sudo make install
```

A debug build of bpftrace can be set up with `cmake -DCMAKE_BUILD_TYPE=Debug ../`.

The bpftrace binary will be in installed in /usr/local/bin/bpftrace, and tools
in /usr/local/share/bpftrace/tools. You can change the install location using an
argument to cmake, where the default is `-DCMAKE_INSTALL_PREFIX=/usr/local`.

To test that the build works, you can try running the unit tests and a one-liner:

```
$ ./tests/bpftrace_test
# ./src/bpftrace -e 'kprobe:do_nanosleep { printf("sleep by %s\n", comm); }'
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

Note that you may encounter kernel lockdown error if you install bpftrace
via `snap` incorrectly. Please refer to [Ubuntu](#ubuntu-packages) for more
details regrading how to use `snap` to install `bpftrace`.
