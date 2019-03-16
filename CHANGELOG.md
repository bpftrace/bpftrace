# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] 2019-03-16

### Deprecated

  - **Deprecate `sym()`**. Use `ksym()` instead (50a66d2) by williangaspar <williangaspar360@gmail.com>
  - **Deprecate `stack`**. Use `kstack` instead (e8b99cd) by williangaspar <williangaspar360@gmail.com>

### Added

  - List usdt probes with -l (fa7d5f3) by Timothy J Fontaine <tjfontaine@gmail.com>
  - Introduce perf formatting for ustack()/kstack() (db910b9) by Matheus Marchini <mat@mmarchini.me>
  - Add increment and decrement operators (++/--) (c8d8a08, 6aa66a1, 223d8d8, 1f82aaf, 8c5c4ea) by Dale Hamel <dale.hamel@shopify.com>
  - Add changelog file to keep track of unreleased changes (d11fb01) by Matheus Marchini <mat@mmarchini.me>
  - Allow args with multiple tracepoints (a0a905f, 2df50d3, cddae1a) by Brendan Gregg <bgregg@netflix.com>
  - Add elapsed builtin (0fde181) by Brendan Gregg <brendan.d.gregg@gmail.com>
  - Add support to demangle C++ symbols in userspace stack traces (872525c) by Augusto Caringi <acaringi@redhat.com>
  - allow \r (e7f0584) by Brendan Gregg <bgregg@netflix.com>
  - Use debuginfo files information when available (1132d42) by Augusto Caringi <acaringi@redhat.com>
  - Add ustack([int limit])/kstack([int limit]) calls (08da997) by Matheus Marchini <mat@mmarchini.me>
  - Allow custom provider name in USDT probe definition (361245c, 80d640a, 20ddfed, c3a6ff1) by Dale Hamel <dale.hamel@shopify.com>
  - Detect kernel headers even if they are splitted into source/ and build/ directories (4d76385) by Kirill Smelkov <kirr@nexedi.com>
  - Add support for arm64 (aarch64) (47fa8aa) by Ali Saidi <alisaidi@amazon.com>
  - Allow customizing stdout buffering mode via -b (1663b84) by Hongli Lai (Phusion) <hongli@phusion.nl>
  - Add support to list tracepoint arguments (#323) (4a048fc) by Augusto Caringi <acaringi@redhat.com>
  - Add `ksym` as a replacement for `sym` (50a66d2) by williangaspar <williangaspar360@gmail.com>
  - Add `kstack` as a replacement for `stack` (e8b99cd, 840712b, f8f7ceb,6ec9a02) by williangaspar <williangaspar360@gmail.com>
  - cmake: add BUILD_TESTING support (a56ab12) by Aleksa Sarai <cyphar@cyphar.com>
  - Add --version (61a4650, eab3675) by williangaspar <williangaspar360@gmail.com>
  - Add hint to install docs and normalize format (c0084a2) by Daniel Xu <dxu@dxuuu.xyz>
  - Make bpftrace -l list sofware and hardware types (#44) (acd9a80) by Augusto Caringi <acaringi@redhat.com>
  - Print program ID when the verbose option is enabled. (8e8258d) by David Calavera <david.calavera@gmail.com>

### Changed

  - Use `struct` when casting on docs and tools (e2ba048) by Brendan Gregg <bgregg@netflix.com>
  - Allow using the `struct` keyword when casting (df03256) by williangaspar <williangaspar360@gmail.com>
  - Make path optional on usdts when attaching to pid (c1c7c83) by Timothy J Fontaine <tjfontaine@gmail.com>
  - Resolve binary name from PATH for usdts and uprobes (28f0834) by Matheus Marchini <mat@mmarchini.me>
  - Use map lookups instead of sequential checks in tcpdrop.bt and tcpretrans.bt (cb0969c) by Slavomir Kaslev <kaslevs@vmware.com>
  - Implicitly declare variables to 0 if used but not defined (a408cc2) by Matheus Marchini <mat@mmarchini.me>
  - Sort all integer maps by values, ascending (c378f57) by Dale Hamel <dale.hamel@shopify.com>
  - Change Ubuntu install to LLVM 6.0 (98353bf) by Brendan Gregg <bgregg@netflix.com>
  - ignore EFAULT stack IDs (f080bbf) by Brendan Gregg <bgregg@netflix.com>
  - Usage updates (6de4101) by Brendan Gregg <bgregg@netflix.com>
  - make map stack indentation 4 chars (c1dd418) by Brendan Gregg <bgregg@netflix.com>
  - Print error messages on all `abort()` calls (5c2ca5b) by williangaspar <williangaspar360@gmail.com>
  - Lesson 9: Replace "stack" to "kstack" (1ac56bd) by CavemanWork <yingyun@caveman.work>
  - Use structs with semicolons in tools and documentation (85dba93) by Brendan Gregg <bgregg@netflix.com>
  - Allow semicolon after struct definition (5982c74) by williangaspar <williangaspar360@gmail.com>
  - remove unnecessary newlines in -l (bb4a83c) by Brendan Gregg <bgregg@netflix.com>
  - list sw/hw probes with full names (6f3e1c4) by Brendan Gregg <bgregg@netflix.com>
  - hist: split negative, zero, and one into separate buckets (48c0afb) by Brendan Gregg <bgregg@netflix.com>
  - lhist: interval notation tweak (43e7974) by Brendan Gregg <bgregg@netflix.com>
  - runqlat.bt: remove if semicolon (c10c0dc) by Brendan Gregg <bgregg@netflix.com>
  - Probe list optimizations and improvements (7f84552) by Augusto Caringi <acaringi@redhat.com>
  - Link against system installed bcc (#327) (4c3fbad) by Dan Xu <accounts@dxuuu.xyz>
  - Make semicolon optional after if and unroll blocks (d74d403) by williangaspar <williangaspar360@gmail.com>
  - Avoid crashing if mistakenly just '-d' or '-v' is used (f2f6732) by Augusto Caringi <acaringi@redhat.com>
  - Return cleanly after printing help (1d41717) by Daniel Xu <dxu@dxuuu.xyz>

### Fixed

  - Make sure we create map keys when we have all the typing information (971bd77) by Matheus Marchini <mat@mmarchini.me>
  - Fix for new bpf_attach_kprobe signature (080bef8) by Matheus Marchini <mat@mmarchini.me>
  - Fix string comparison improperly deallocating variables (ffa173a) by williangaspar <williangaspar360@gmail.com>
  - Fix probe keys on maps when the map is used more than one time (df81736) by Matheus Marchini <mat@mmarchini.me>
  - Fix using same variable name on multiple programs (61a14f2) by williangaspar <williangaspar360@gmail.com>
  - Fix build on old compilers (644943a, 1b69272) by Kirill Smelkov <kirr@nexedi.com>
  - Fix build with latest bcc (d64b36a) by williangaspar <williangaspar360@gmail.com>
  - Don't throw warning for undefined types in tracepoint structure definition if `args` is not used (f2ebe1a) by Matheus Marchini <mat@mmarchini.me>
  - Fix for 'redefinition of tracepoint' warning message (baaeade) by Augusto Caringi <acaringi@redhat.com>
  - Minor fixes in our documentation (0667533) by Matheus Marchini <mat@mmarchini.me>
  - Fix string comparison (5e114dd, 63acdb6) by williangaspar <williangaspar360@gmail.com>
  - Prevent empty trigger functions to be optimized away with -O2 (#218) (9f2069b) by Augusto Caringi <acaringi@redhat.com>
  - Fix -l behavior with shortcut probe names (2d30e31) by williangaspar <williangaspar360@gmail.com>
  - Fix alpine docker build (#372) (2b83b67) by Dan Xu <accounts@dxuuu.xyz>
  - Fix tracepoint wildcards (946c785) by Brendan Gregg <bgregg@netflix.com>
  - tests: fix codegen test fot call_hist (342fd6d) by Matheus Marchini <mat@mmarchini.me>
  - docs: fix trivial typos (3da1980) by Xiaozhou Liu <liuxiaozhou@bytedance.com>
  - Fix symbol translation for func, sym, and stack (6276fb5) by Brendan Gregg <bgregg@netflix.com>
  - Fix wrong package name in Ubuntu Dockerfile (f8e67a9) by xbe <xbe@users.noreply.github.com>
  - Fix wrong package name in build instructions (8e597de) by Daniel Xu <dxu@dxuuu.xyz>
  - Fix arguments and error messages for tracepoint shortcut `t` (0eddba7) by williangaspar <williangaspar360@gmail.com>

### Internal

  - Fix 'different signedness' warning messages in codegen call_[uk]stack.cpp (cb25318) by Augusto Caringi <acaringi@redhat.com>
  - Fix 'signedness' warning message in tracepoint_format_parser.cpp (c3e562f) by Augusto Caringi <acaringi@redhat.com>
  - Stop linking against bcc-loader-static (5fbb7a7) by Daniel Xu <dxu@dxuuu.xyz>
  - Speeding up runtime tests (60c5d96) by williangaspar <williangaspar360@gmail.com>
  - docker: make sure debugfs is mounted (7dcfc47) by Zi Shen Lim <zlim.lnx@gmail.com>
  - Better coverage for variable_clear() (34fdded) by williangaspar <williangaspar360@gmail.com>
  - Add missing space (c65e7c1) by puyuegang <puyuegang@gmail.com>
  - Ignore warnings on code generated by bison (a935942) by Matheus Marchini <mat@mmarchini.me>
  - Ignore warnings from LLVM headers (b6c4fd6) by Matheus Marchini <mat@mmarchini.me>
  - Downgrade back to c++14 (f6986d8) by Matheus Marchini <mat@mmarchini.me>
  - Fix 'parameter not used' warning (2401ab3) by Matheus Marchini <mat@mmarchini.me>
  - Fix new build warning msg after c++17 was enabled (e4cbe48) by Augusto Caringi <acaringi@redhat.com>
  - Get rid of cmake CMP0075 policy warning (9b8208a) by Augusto Caringi <acaringi@redhat.com>
  - Use C++17 instead of C++14 (4b4d5dc) by Alex Birch <Birch-san@users.noreply.github.com>
  - Re-enable more build warnings, fix related warnings #316 (8c383dc) by Augusto Caringi <acaringi@redhat.com>
  - Define `__BPF_TRACING__` before building (required for kernel 4.19+) (e0bf01d) by Kirill Smelkov <kirr@nexedi.com>
  - Re-enable subset of build warnings and fix some related warnings #316 (f0f56b0) by Augusto Caringi <acaringi@redhat.com>
  - Cleanup enforce_infinite_rmlimits : removed getrlimit() : Added error description using strerror() (d76465f) by T K Sourab <sourabhtk37@gmail.com>
  - use the new libbcc API: bcc_{create_map, prog_load} when possible (c03c39f) by Xiaozhou Liu <liuxiaozhou@bytedance.com>
  - resources: generate c++ file instead of c file (5e1350b) by Matheus Marchini <mat@mmarchini.me>
  - docker: disable runtime tests on CI (0667b92) by Matheus Marchini <mat@mmarchini.me>
  - Hide -inl.h header from interface (10a43d0) by Daniel Xu <dxu@dxuuu.xyz>

## [0.8.0] - 2019-01-06

This is a release to aid packaging. bpftrace has not reached a 1.0 release
status yet, as there are still development changes and things to fix. But what
is here should be tremendously useful, provided you bear in mind that there
will be some changes made to the programming language and command line options
between now and a 1.0 release, so any tools or documentation written will
become out of date and require changes. If you are anxiously waiting a 1.0
release, please consider contributing so that it can be released sooner.
