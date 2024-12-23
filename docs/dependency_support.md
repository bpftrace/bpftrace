# Dependency support policy

This document outlines our policy for supporting bpftrace's major dependencies.
Our support policy for minor dependencies are done on a case by case basis,
usually at distro/user request.

## Linux kernel

The linux kernel is bpftrace's biggest runtime dependency. Our stance on kernel
support is that for **cross cutting** implementation details (ie. something
every reasonably sophisticated user is expected to depend on), we'll support up
to and including the oldest LTS kernel still in service.

For features that have clear boundaries (eg. new builtins or helpers), bpftrace
is free to opportunistically depend on newer kernels as long as there is a
reasonable runtime fallback strategy. An error message is a reasonable fallback
strategy in this case.

The source of truth on EOL dates and LTS kernels is https://www.kernel.org/.

## LLVM (dynamically linked)

LLVM is bpftrace's biggest build time dependency. The project always supports
the latest LLVM release as soon as it's practical (available in CI). We support
some number of previous LLVM releases. Given LLVM's twice annual release
cadence, we have historically supported somewhere around the last 3 years'
worth. We do not provide a hard guarantee, but it's probably safe to the
versions from the previous year will be supported.

## LLVM (statically linked)

In contrast to dynamically linked LLVM, statically linked LLVM is significantly
more difficult to maintain. As a consequence, we only support a single LLVM
release in the static build configuration.

We do not yet have a policy on when the LLVM version is updated, but we will
document any changes in the release notes.

Please consult [static.sh][0] for the source of truth.


[0]: https://github.com/bpftrace/bpftrace/blob/master/.github/include/static.sh
