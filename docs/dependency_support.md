# Dependency support policy

This document outlines our policy for supporting bpftrace's major dependencies.
Our support policy for minor dependencies are done on a case by case basis,
usually at distro/user request.

## Linux kernel

**Minimum kernel version: 5.15**

The linux kernel is bpftrace's biggest runtime dependency.
While we would like to support the oldest LTS kernel version, we also want to make
sure bpftrace is keeping up with the latest features. As a compromise bpftrace
supports stable kernels and the 4 most recent LTS kernels. Users that require support on older kernels can often simply use [older versions of bpftrace](https://github.com/bpftrace/bpftrace/releases).

The source of truth on EOL dates and LTS kernels is https://www.kernel.org/.

For features that have clear boundaries (eg. new builtins or helpers), bpftrace
is free to opportunistically depend on newer kernels as long as there is a
reasonable runtime fallback strategy or detailed error message.

### Required configuration

The kernel needs to be built with the following options:

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

## LLVM (dynamically linked)

LLVM is bpftrace's biggest build time dependency. The project always supports
the latest LLVM release as soon as it's practical (available in CI). On top of
that, we support 4 previous LLVM releases (i.e. 5 LLVM versions in total).

## LLVM (statically linked)

In contrast to dynamically linked LLVM, statically linked LLVM is significantly
more difficult to maintain. As a consequence, we only support a single LLVM
release in the static build configuration.

We do not yet have a policy on when the LLVM version is updated, but we will
document any changes in the release notes.

Please consult [static.sh][static] for the source of truth.

## libbpf

bpftrace relies on libbpf for most of the tasks related to management of BPF
programs, particularly loading and attachment. Occasionally, it is necessary to
introduce patches to libbpf to enable some bpftrace functionality or to fix
bugs. For this reason, we require a very recent, often unreleased, version of
libbpf.

To simplify development and building, bpftrace vendors libbpf as a submodule and
by default links against the vendored version statically. Since linking against
vendored library versions is not preferred by most distributions, we also allow
building against system libbpf by using `-DUSE_SYSTEM_LIBBPF=On` in CMake. Note
that it is the responsibility of the builder to ensure that the linked libbpf
contains all the necessary patches. The general recommendation is that the
linked libbpf should be at or beyond the commit referenced by the libbpf
submodule, which will be kept up to date when required patches change.

[static]: https://github.com/bpftrace/bpftrace/blob/master/.github/include/static.sh
