# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

#### Added
- Build time dependency on cereal
  - [#1893](https://github.com/iovisor/bpftrace/pull/1893)

#### Changed

#### Deprecated

#### Removed

#### Fixed
- Fix memory leaks in struct types
  - [#1885](https://github.com/iovisor/bpftrace/pull/1885)

#### Tools

#### Documentation

## [0.13.0] 2021-07-01

#### Added
- Warn if attaching a kprobe to a non-traceable function
  - [#1835](https://github.com/iovisor/bpftrace/pull/1835)
- Support for `-k[k]` and `elapsed` in `iter` probes
  - [#1882](https://github.com/iovisor/bpftrace/pull/1882)

#### Changed
- Disallow accessing common tracepoint fields
  - [#1810](https://github.com/iovisor/bpftrace/pull/1810)
- Improve JSON printing (nested structs)
  - [#1778](https://github.com/iovisor/bpftrace/pull/1778)
- Return 1 from tracepoint probes
  - [#1857](https://github.com/iovisor/bpftrace/pull/1857)
- Preserve original order of struct types
  - [#1850](https://github.com/iovisor/bpftrace/pull/1850)
- Forbid casting from/to struct types
  - [#1873](https://github.com/iovisor/bpftrace/pull/1873)

#### Deprecated

#### Removed

#### Fixed
- Fix single arg wildcard probe listing
  - [#1775](https://github.com/iovisor/bpftrace/pull/1775)
- Fix --info reporting wrong libbpf build info
  - [#1776](https://github.com/iovisor/bpftrace/pull/1776)
- Reduce frequency of lost stack traces
  - [#1812](https://github.com/iovisor/bpftrace/pull/1812)
- Make kaddr() report failure for unknown kernel symbols
  - [#1836](https://github.com/iovisor/bpftrace/pull/1836)
- Fix false non-traceable function warnings
  - [#1866](https://github.com/iovisor/bpftrace/pull/1866)
- Fix memory leak in clang parser
  - [#1878](https://github.com/iovisor/bpftrace/pull/1878)

#### Tools

#### Documentation

## [0.12.1] 2021-04-16

Incorrect --info output bug fix release

## [0.12.0] 2021-04-01

#### Added
- Add path builtin
  - [#1492](https://github.com/iovisor/bpftrace/pull/1492)
- Allow wildcards for tracepoint categories
  - [#1445](https://github.com/iovisor/bpftrace/pull/1445)
- Add wildcard support for kfunc probe types
  - [#1410](https://github.com/iovisor/bpftrace/pull/1410)
- Add builtin function: `strftime`
  - [#1387](https://github.com/iovisor/bpftrace/pull/1387)
- Fix `printf` not allowing format specifiers to be directly followed by
  alphabetic characters
  - [#1414](https://github.com/iovisor/bpftrace/pull/1414)
- Fix `top` and `div` arguments of `print()` not working for Type::avg maps
  - [#1416](https://github.com/iovisor/bpftrace/pull/1416)
- Add an option to disable warning messages
  - [#1444](https://github.com/iovisor/bpftrace/pull/1444)
- Support scientific notation for integer literals
  - [#1476](https://github.com/iovisor/bpftrace/pull/1476)
- List retprobes
  - [#1484](https://github.com/iovisor/bpftrace/pull/1484)
- Resolve unknown typedefs using BTF and give a hint when a type cannot be found
  - [#1485](https://github.com/iovisor/bpftrace/pull/1485)
- Support multi-matched globbed targets for uprobe and ustd probes
  - [#1499](https://github.com/iovisor/bpftrace/pull/1499)
- Positional parameters: support numbers as strings and params as string literals
  - [#1514](https://github.com/iovisor/bpftrace/pull/1514)
- Support for tracepoint __data_loc fields
  - [#1542](https://github.com/iovisor/bpftrace/pull/1542)
- Set addrspace info for various builtins
  - [#1504](https://github.com/iovisor/bpftrace/pull/1504)
- Support watchpoint for kernel space address
  - [#1552](https://github.com/iovisor/bpftrace/pull/1552)
- Support for pointer to pointer
  - [#1557](https://github.com/iovisor/bpftrace/pull/1557)
- Support for uprobe refcounts
  - [#1567](https://github.com/iovisor/bpftrace/pull/1567)
- Add basic options and documentations for fuzzing
  - [#1601](https://github.com/iovisor/bpftrace/pull/1601)
- Disable `str($# + 1)`
  - [#1619](https://github.com/iovisor/bpftrace/issues/1619)
- Array improvements (support assignment to variables and usage as a map key)
  - [#1656](https://github.com/iovisor/bpftrace/pull/1656)
- Add builtin function: `macaddr`
  - [#1647](https://github.com/iovisor/bpftrace/pull/1647)
- Add support for usdt arguments utilising the index register and scale
  - [#1684](https://github.com/iovisor/bpftrace/pull/1684)
- Add basic mips64 support
  - [#1599](https://github.com/iovisor/bpftrace/pull/1599)
- Printing structures
  - [#1705](https://github.com/iovisor/bpftrace/pull/1705)
- Array indexing on pointers
  - [#1739](https://github.com/iovisor/bpftrace/pull/1739)

#### Changed
- Warn if using `print` on `stats` maps with top and div arguments
  - [#1433](https://github.com/iovisor/bpftrace/pull/1433)
- Prefer BTF data if available to resolve tracepoint arguments
  - [#1439](https://github.com/iovisor/bpftrace/pull/1439)
- Improve error messages for kfunc probe types
  - [#1451](https://github.com/iovisor/bpftrace/pull/1451)
- Better handling of empty usdt namespaces
  - [#1486](https://github.com/iovisor/bpftrace/pull/1486)
- Switch `nsecs` to `ktime_get_boot_ns`
  - [#1475](https://github.com/iovisor/bpftrace/pull/1475)
- Tracepoint __data_loc fields are renamed from `args->data_loc_name` to `args->name`
  - [#1542](https://github.com/iovisor/bpftrace/pull/1542)
- Change a part of the message of '-v' output
  - [#1553](https://github.com/iovisor/bpftrace/pull/1553)
- Improve tuple assignment error message
  - [#1563](https://github.com/iovisor/bpftrace/pull/1563)
- Remove "BTF: using data from ..." message when using -v flag
  - [#1554](https://github.com/iovisor/bpftrace/pull/1554)
- Add -q option for quiet
  - [#1616](https://github.com/iovisor/bpftrace/pull/1616)
- Optimize unknown/incomplete types resolution
  - [#1571](https://github.com/iovisor/bpftrace/pull/1571)
- Do not check size of the format string of `printf`
  - [#1538](https://github.com/iovisor/bpftrace/pull/1538)
- Unify semantics of wildcards in probe listing and attachement
  - [#1549](https://github.com/iovisor/bpftrace/pull/1549)
- Improve codegen for structs and arrays
  - [#1705](https://github.com/iovisor/bpftrace/pull/1705)
- Do not unpack in-kernel headers if system has BTF
  - [#1740](https://github.com/iovisor/bpftrace/pull/1740)

#### Deprecated

#### Removed
- Disable some kfunc probes whose tracing crashes
  - [#1432](https://github.com/iovisor/bpftrace/pull/1432)

#### Fixed
- Fix negative overflow bug and unstable tests in PR #1416
  - [#1436](https://github.com/iovisor/bpftrace/pull/1436)
- Fix `print` outputs nothing when used on hist() maps with large top args
  - [#1437](https://github.com/iovisor/bpftrace/pull/1437)
- Fix array indexing regression
  - [#1457](https://github.com/iovisor/bpftrace/pull/1457)
- Fix type resolution for struct field access via variables
  - [#1450](https://github.com/iovisor/bpftrace/pull/1450)
- Fix wrong setting of vmlinux_location.raw when offset kprobe used
  - [#1530](https://github.com/iovisor/bpftrace/pull/1530)
- Fix pointer arithmetic for positional parameters
  - [#1514](https://github.com/iovisor/bpftrace/pull/1514)
- SEGV when using perf format for stacks
  - [#1524](https://github.com/iovisor/bpftrace/pull/1524)
- Fix llvm errors of PositonalParameter
  - [#1565](https://github.com/iovisor/bpftrace/pull/1565)
- Error if Positional Params num is zero
  - [#1568](https://github.com/iovisor/bpftrace/issues/1568)
- Fix LNOT
  - [#1570](https://github.com/iovisor/bpftrace/pull/1570)
- Fix invalid cast handling in tuple
  - [#1572](https://github.com/iovisor/bpftrace/pull/1572)
- Check string comparison size
  - [#1573](https://github.com/iovisor/bpftrace/pull/1573)
- Fix a possible integer overflow
  - [#1580](https://github.com/iovisor/bpftrace/pull/1580)
- Printing of small integers with `printf`
  - [#1532](https://github.com/iovisor/bpftrace/pull/1532)
- Fix bitfield access for big endian
  - [#1628](https://github.com/iovisor/bpftrace/pull/1628)
- Error if using negative length in str() and buf()
  - [#1621](https://github.com/iovisor/bpftrace/pull/1621)
- Only create int type Identifier when it is used in sizeof()
  - [#1622](https://github.com/iovisor/bpftrace/pull/1622)
- Check exponent value can be expressed in uint64_t
  - [#1623](https://github.com/iovisor/bpftrace/pull/1623)
- Fix tracing of usdt probes across namespaces
  - [#1637](https://github.com/iovisor/bpftrace/pull/1637)
- Disable reg() for kfunc
  - [#1646](https://github.com/iovisor/bpftrace/pull/1646)
- Fix several undefined behavior
  - [#1645](https://github.com/iovisor/bpftrace/pull/1645)
- Fix invalid size crash when using strftime() inside a tuple
  - [#1658](https://github.com/iovisor/bpftrace/pull/1658)
- Don't create a tuple if an element size if zero
  - [#1653](https://github.com/iovisor/bpftrace/pull/1653)
- Support clear() and delete() on a count()-based map without a key
  - [#1639](https://github.com/iovisor/bpftrace/pull/1639)
- Add workaround for too deep or long macros
  - [#1650](https://github.com/iovisor/bpftrace/pull/1650)
- Fix attaching to usdt probes in shared libraries
  - [#1600](https://github.com/iovisor/bpftrace/pull/1600)
- Fix attaching to multiple usdt probe locations with the same label
  - [#1681](https://github.com/iovisor/bpftrace/pull/1681)
- Fix signed extension of usdt arguments to the internal 64-bit integer type
  - [#1684](https://github.com/iovisor/bpftrace/pull/1684)

#### Tools
- Hook up execsnoop.bt script onto `execveat` call
  - [#1490](https://github.com/iovisor/bpftrace/pull/1490)
- Support new capabilities for capable.bt
  - [#1498](https://github.com/iovisor/bpftrace/pull/1498)
- Add disk field to biosnoop
  - [#1660](https://github.com/iovisor/bpftrace/pull/1660)

#### Documentation
- Document uptr() and kptr() function
  - [#1626](https://github.com/iovisor/bpftrace/pull/1626)

## [0.11.4] 2020-11-14

Alpine build bug fix release

## [0.11.3] 2020-11-13

bcc 0.17 support release

### Changed

Detect 7 arg bpf_attach_uprobe() API
- [#1589](https://github.com/iovisor/bpftrace/pull/1589)

## [0.11.2] 2020-10-30

LLVM 11 support release

### Added

Add LLVM11 build support
- [#1578](https://github.com/iovisor/bpftrace/pull/1578)

## [0.11.1] 2020-09-22

Bug fix release for the [Docker build](https://quay.io/repository/iovisor/bpftrace)

### Fixed

- Don't strip END_trigger
  - [#1513](https://github.com/iovisor/bpftrace/pull/1513)

## [0.11.0] 2020-07-15

### All Changes

#### Added

- Allow uprobe placement on arbitrary addresses when --unsafe is used
  - [#1388](https://github.com/iovisor/bpftrace/pull/1388)
- Support for s390x
  - [#1241](https://github.com/iovisor/bpftrace/pull/1241)
- `buf` a new function that makes it possible to safely print arbitrary binary data
  - [#1107](https://github.com/iovisor/bpftrace/pull/1107)
- A new function, `sizeof`, which returns the size of an expression, similar to  `sizeof` in C
  - [#1269](https://github.com/iovisor/bpftrace/pull/1269)
- C style while loop support, `while ($a < 100) { $a++ }`
  - [#1066](https://github.com/iovisor/bpftrace/pull/1066)
- Using a BTF enum value will pull in the entire enum definition
  - [#1274](https://github.com/iovisor/bpftrace/pull/1274)
- Add support of using positional params in unroll and increase the unroll limit to 100
  - [#1286](https://github.com/iovisor/bpftrace/pull/1286)
- Support for piping scripts in via stdin
  - [#1310](https://github.com/iovisor/bpftrace/pull/1310)
- Don't require <linux/types.h> if --btf is specified
  - [#1315](https://github.com/iovisor/bpftrace/pull/1315)
- Silence errors about `modprobe` not being found
  - [#1314](https://github.com/iovisor/bpftrace/pull/1314)
- With --btf, do not use <linux/types.h> for resolving tracepoint defs
  - [#1318](https://github.com/iovisor/bpftrace/pull/1318)
- Add environment variable, BPFTRACE_PERF_RB_PAGES, to tune perf ring buffer size
  - [#1329](https://github.com/iovisor/bpftrace/pull/1329)
- Add --usdt-file-activation to activate usdt semaphores by file name
  - [#1317](https://github.com/iovisor/bpftrace/pull/1317)
- Introduce `-k` and `-kk` options. Emit a warning when a bpf helper returns an error
  - [#1276](https://github.com/iovisor/bpftrace/pull/1276)
- Add tuples to language
  - [#1326](https://github.com/iovisor/bpftrace/pull/1326)
- Add support for listing struct/union/enum definitions using BTF
  - [#1340](https://github.com/iovisor/bpftrace/pull/1340)
- Add libbpf build into in --info
  - [#1367](https://github.com/iovisor/bpftrace/pull/1367)
- Add support for time units `us` and `hz` for probe `interval`
  - [#1377](https://github.com/iovisor/bpftrace/pull/1377)
- Add support for non-map print()
  - [#1381](https://github.com/iovisor/bpftrace/pull/1381)
- Enable `printf`, `cat` and `system` to have more than 7 arguments
  - [#1404](https://github.com/iovisor/bpftrace/pull/1404)
- Enable the `ternary` operator to evaluate builtin calls
  - [#1405](https://github.com/iovisor/bpftrace/pull/1405)


#### Changed

- Require C++17 and CMake 3.8 for building bpftrace
  - [#1200](https://github.com/iovisor/bpftrace/pull/1200)
  - [#1259](https://github.com/iovisor/bpftrace/pull/1259)
- Allow positional parameters in probe attachpoint definitions
  - [#1328](https://github.com/iovisor/bpftrace/pull/1328)
- Only list uprobe and usdt probes when `-p` is given
  - [#1340](https://github.com/iovisor/bpftrace/pull/1340)
- Remove address space memory limit
  - [#1358](https://github.com/iovisor/bpftrace/pull/1358)

#### Deprecated

#### Removed

- Drop LLVM 5 support
  - [#1215](https://github.com/iovisor/bpftrace/issues/1215)
- Remove the --btf option
  - [#1669](https://github.com/iovisor/bpftrace/pull/1669)

#### Fixed

- Various big endian related fixes
  - [#1241](https://github.com/iovisor/bpftrace/pull/1241)
- Type check the `cond` of if and ternary statements
  - [#1229](https://github.com/iovisor/bpftrace/pull/1229)
- Fix usdt reads in various architecture
  - [#1325](https://github.com/iovisor/bpftrace/pull/1325)
- Attach to duplicated USDT markers
  - [#1341](https://github.com/iovisor/bpftrace/pull/1341)
- Fix `KBUILD_MODNAME`
  - [#1352](https://github.com/iovisor/bpftrace/pull/1352)
- Fix `ntop()` not accepting tracepoint arguments
  - [#1365](https://github.com/iovisor/bpftrace/pull/1365)
- Fix attaching to usdt probes in multiple binaries
  - [#1356](https://github.com/iovisor/bpftrace/pull/1356)
- Decrement usdt semaphore count after bpftrace execution
  - [#1370](https://github.com/iovisor/bpftrace/pull/1370)
- Reduce high memory consumption when using usdt semaphore
  - [#1374](https://github.com/iovisor/bpftrace/pull/1374)
- Remove registers that are not in struct pt_regs (x86-64)
  - [#1383](https://github.com/iovisor/bpftrace/issues/1383)
- Ignore trailing kernel module annotation for k[ret]probe's
  - [#1413](https://github.com/iovisor/bpftrace/pull/1413)

#### Tools

#### Documentation

- Clean up README
  - [#1273](https://github.com/iovisor/bpftrace/pull/1273)
- Add missing `struct` keyword to examples in the one liner tutorial
  - [#1275](https://github.com/iovisor/bpftrace/pull/1275)

## [0.10.0] 2020-04-12

### Highlights

#### kfuncs

Improved kprobes which are near zero overhead and use BTF to derive argument
names and types:

```
bpftrace -e 'kfunc:fget { printf("fd %d\n", args->fd);  }'
```

#### C++ Symbol demangling

bpftrace can now demangle C++ symbols in binaries:

```
bpftrace -e 'uprobe:./a.out:"foo()" {printf("ok\n");}
```

#### if else control flow

Support for `if else` has been added, making it possible to write:

```
if (cond) {
  ...
} else if (cond) {
  ...
}
```

Instead of:

```
if (cond) {
  ...
} else {
  if (cond) {
    ...
  }
}
```

#### LLVM 9 & 10

Support for LLVM 9 and LLVM 10 has been added.

#### Docker images

Docker images containing a static build are now available on [quay.io](https://quay.io/repository/iovisor/bpftrace).

### All Changes

#### Added

  - Add kfunc/kretfunc description to docs/reference_guide.md (e3b9518b) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add kfunc/kretfunc probe tests (bbf2083a) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add test_btf class to setup BTF data (ecbd66b7) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Fortify exported functions with has_data check (083bcf9f) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Detect btf feature via BTF class (a9450425) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add support to filter kfunc list (a98b3f02) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - List kfunc functions (75a0f9c7) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Generate load code for kfunc/kretfunc arguments (30f699b1) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Resolve kfunc arguments in semantic analyser (de2f6c1d) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Resolve kfunc arguments in BTF field analyser (8cd3fb50) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add single_provider_type function (3a6325e5) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Factor out builtin_args_tracepoint function (e33c246e) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add BTF::resolve_args function to resolve kfunc arguments (69c8fd45) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Load and attach kfunc/kretfunc programs (126a9edd) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add missing ProbeType::watchpoint to probetypeName function (343165b1) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Allow to specify kernel include dirs (1e987f45) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Feature detect `probe_read_{kernel,user}` (b7c236f9) by bas smit &lt;bas@baslab.org&gt;
  - Add support for using demangled symbols in uretprobe names (269033de) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Implement `else if` control flow (34fc2801) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - detect lockdown mode (37d28c26) by bas smit &lt;bas@baslab.org&gt;
  - Extend info flag with system/build info (73abef68) by bas smit &lt;bas@baslab.org&gt;
  - Add support for C++ mangled symbols in uprobe names #687 (e8656cbd) by Augusto Caringi &lt;acaringi@redhat.com&gt;

#### Changed

  - Allow hex/octal positional parameters (ef20128b) by bas smit &lt;bas@baslab.org&gt;
  - Allow negative positional parameters (babf057e) by bas smit &lt;bas@baslab.org&gt;
  - Make positionalparameters literal to avoid warnings (0859fc6b) by bas smit &lt;bas@baslab.org&gt;
  - Make `exit()` terminate current probe (6334c23d) by bas smit &lt;bas@baslab.org&gt;
  - Improve an error message when trying to use 'args' other than tracepoint (e303048c) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Disable a symbol name cache if ASLR is enabled and `-c` option is not given (4651255b) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Remove deprecated builtins (2667b8a2) by bas smit &lt;bas@baslab.org&gt;

#### Fixed

  - reject invalid pid argument (cebc5978) by bas smit &lt;bas@baslab.org&gt;
  - Fix positional parameter error (1b4febee) by bas smit &lt;bas@baslab.org&gt;
  - Emit better tracepoint parser errors (f5217821) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix if comparison (8f8c9cb4) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Do not keep open BEGIN/END probes (19d90057) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Check the length of ap.mode (a388dc14) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Fix ternary comparison (360be8cf) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Cast LNOT result (890f5930) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Gracefully handle long position param overflow (6f26a863) by Vlad Artamonov &lt;742047+vladdy@users.noreply.github.com&gt;
  - Error if wildcards are used in "category" of tracepoint (3bfdec94) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Fix reading USDT probe arguments on AArch64 (ee5314ba) by Nick Gasson &lt;nick.gasson@arm.com&gt;
  - Remove type qualifiers from a cast_type (4ad2bf19) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Fix printf argument offsets (2d2f2332) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Warn if Type::string size is not matched when assignment (4638b968) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Print Type::string and Type::array size information along with type information (03a837e7) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Consider a short Type::string value (684513ed) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Consider a non null-terminated Type::string value (13614152) by Masanori Misono &lt;m.misono760@gmail.com&gt;

#### Tools

  - oomkill: fix kprobe arg (675727a4) by Xiaozhou Liu &lt;liuxiaozhou@bytedance.com&gt;
  - Fix 'signed operands for /' warning in naptime.bt (c8f4a6d8) by Augusto Caringi &lt;acaringi@redhat.com&gt;

#### Documentation

  - Fix example links to only search bpftrace repo (71c9d29e) by Martin Schmidt &lt;martin.schmidt@epita.fr&gt;
  - Remove example link to a runtime test (560454a1) by Martin Schmidt &lt;martin.schmidt@epita.fr&gt;
  - Add link to example for interval and BEGIN/END (badf5653) by Martin Schmidt &lt;martin.schmidt@epita.fr&gt;
  - Add link to example for profile (ea6f706a) by Martin Schmidt &lt;martin.schmidt@epita.fr&gt;
  - Add links to examples for tracepoints (f6a3d26a) by Martin Schmidt &lt;martin.schmidt@epita.fr&gt;
  - Add links to examples for uprobe/uretprobe (5dd4bd8d) by Martin Schmidt &lt;martin.schmidt@epita.fr&gt;
  - Add links to examples for kprobe/kretprobe (c580ef26) by Martin Schmidt &lt;martin.schmidt@epita.fr&gt;
  - When installing from source on ubuntu and Fedora, non-root users need to add 'sudo' when executing 'make install' (3030046b) by mazhen   &lt;mz1999@gmail.com&gt;
  - docs: Add documentation for integer casts (f087abbd) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Docs: Fix broken link (f76b8bbb) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - Docs: Add missing builtin functions (fd08a932) by Adam Jensen &lt;acjensen@gmail.com&gt;

#### Internal

  - Remove codegen tests warning (f18746af) by bas smit &lt;bas@baslab.org&gt;
  - build: document libbcc linking (#1252) (4dadd515) by bas smit &lt;bas@baslab.org&gt;
  - cmake: bail on unsupported architectures (4ae387f0) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Revert "Only link agains libbpf if it exists (#1247)" (04ecb731) by bas smit &lt;bas@baslab.org&gt;
  - Only link agains libbpf if it exists (#1247) (a3febcb8) by bas smit &lt;bas@baslab.org&gt;
  - Align libbpf.h (229eef6c) by bas smit &lt;bas@baslab.org&gt;
  - Sync libbpf with v5.6 (0b369fe6) by bas smit &lt;bas@baslab.org&gt;
  - Add runtime tests for ternary (2efcdb29) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Use BPFtrace::error for TracepointFormatParser errors (#1243) (9106e10c) by Martin Schmidt &lt;martin.schmidt@epita.fr&gt;
  - codegen: Send map id instead of ident string for async events (9a063adc) by bas smit &lt;bas@baslab.org&gt;
  - ci: Add LLVM 10 (696e16ce) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Add codegen test for LLVM 10 (33fe3ee4) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Suppress -Winconsistent-missing-override warning (2044c53d) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Use CreateMemCpy that takes MaybeAlign in LLVM 10 (a67fd22d) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Don't over-read usdt arguments (1711ec70) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add proper bcc prefix for bcc headers (977d5851) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Use urandom instead of random (23603bfc) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - tests: fix llmv 5 tests (449b33a4) by bas smit &lt;bas@baslab.org&gt;
  - codegen: correctly copy and "usym" map (f7a9d9e2) by bas smit &lt;bas@baslab.org&gt;
  - codegen: Use map type in perf_event signature (0a27eeb5) by bas smit &lt;bas@baslab.org&gt;
  - codegen: avoid usym copy on map assignment (25116d21) by bas smit &lt;bas@baslab.org&gt;
  - codegen: deduplicate usym code (078a8236) by bas smit &lt;bas@baslab.org&gt;
  - codegen: fix `strncmp` type issues (e523e2c7) by bas smit &lt;bas@baslab.org&gt;
  - codegen: ensure `getmapkey` stores with equal types (1822cfde) by bas smit &lt;bas@baslab.org&gt;
  - codegen: fix deleteElem typing issues (0c6403bc) by bas smit &lt;bas@baslab.org&gt;
  - codegen: clang-format `join` (e641b115) by bas smit &lt;bas@baslab.org&gt;
  - codegen: memset takes an i8 value (d2a70f98) by bas smit &lt;bas@baslab.org&gt;
  - codegen: remove useless literal handling from `signal` (3bbbfe24) by bas smit &lt;bas@baslab.org&gt;
  - codegen: fix `probe_read` typing issue (eca43df2) by bas smit &lt;bas@baslab.org&gt;
  - codegen: fix sarg type issue (09152138) by bas smit &lt;bas@baslab.org&gt;
  - codegen: fix `probe_read_str` typing issues (914c87e2) by bas smit &lt;bas@baslab.org&gt;
  - codegen: fix reg typing issue (0c66f2f5) by bas smit &lt;bas@baslab.org&gt;
  - parser: Do not remove empty probe arguments (ae4fe7fb) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - cmake: Link against libz when searching for btf_dump__new (6323d8fb) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - snapcraft: add arm64 to build architectures (2b0faa3e) by Colin Ian King &lt;colin.king@canonical.com&gt;
  - cmake: Control manpages generation (ef39ed0f) by Ovidiu Panait &lt;ovpanait@gmail.com&gt;
  - Don't check str arg length for cgroupid (aa94d9b3) by Chris Hunt &lt;chrahunt@gmail.com&gt;
  - Track current function name during analysis (d1f23cab) by Chris Hunt &lt;chrahunt@gmail.com&gt;
  - Remove unused srclines_ (ce9c4179) by Chris Hunt &lt;chrahunt@gmail.com&gt;
  - Remove unused print_map_lhist (7c32b827) by Chris Hunt &lt;chrahunt@gmail.com&gt;
  - Remove leftover print_hist declaration (63f4f029) by Chris Hunt &lt;chrahunt@gmail.com&gt;
  - Remove leftover print_lhist declaration (8008c5a9) by Chris Hunt &lt;chrahunt@gmail.com&gt;
  - Add apt-transport-https for xenial build (8bcf0c04) by Dale Hamel &lt;dale.hamel@shopify.com&gt;
  - Add the snapcraft yaml rules to allow bpftrace to be built as a snap. (c2eceeb3) by Colin Ian King &lt;colin.king@canonical.com&gt;
  - Revert "Require C++17 to build" (24f97308) by bas smit &lt;bas@baslab.org&gt;
  - Fix tracepoint expansion regression (b4f0c204) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - codegen: fix  `map` typing (11814f29) by bas smit &lt;bas@baslab.org&gt;
  - codegen: Update LLVM5 codegen tests (c4f147d3) by bas smit &lt;bas@baslab.org&gt;
  - codegen: fix argX type issue (c04bad20) by bas smit &lt;bas@baslab.org&gt;
  - codegen: Fix comm typing issues (5926429d) by bas smit &lt;bas@baslab.org&gt;
  - codegen: Fix stackid typing issues (a7ba4a1e) by bas smit &lt;bas@baslab.org&gt;
  - codegen: Fix exit typing issues (f676b9c5) by bas smit &lt;bas@baslab.org&gt;
  - codegen: Fix ntop typing issues (ac792f58) by bas smit &lt;bas@baslab.org&gt;
  - codegen: Fix usym typing issues (2e84b52d) by bas smit &lt;bas@baslab.org&gt;
  - irbuilder: Add struct storage (1fbccf1b) by bas smit &lt;bas@baslab.org&gt;
  - Strengthen tracepoint format parsing (a2e3d5db) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - cmake: use *_LIBRARIES when testing for libbfd version (b1200771) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Handle escaped double quotes in AttachPointParser (b98b281d) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Support `:`s in quoted string (c230fc42) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add parser tests for trailing non-numeric characters (c0b8644f) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Update AttachPoint::name to print out watchpoints correctly (dd2312c7) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Unify ast::AttachPoint::addr and ast::AttachPoint::address (71f4205f) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix semantic analyser unit tests (39d4a493) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix runtime tests (1612af97) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Update callee interfaces (78c04b01) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Move AttachPoint parsing logic out of bison (43a72e37) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - tests: cmake: Fix build with ninja (f1fc5190) by Ovidiu Panait &lt;ovpanait@gmail.com&gt;
  - bpffeature: move macros to header (860ac6d4) by bas smit &lt;bas@baslab.org&gt;
  - bpffeature: delete copy/move constructors/assign (ac5e0025) by bas smit &lt;bas@baslab.org&gt;
  - bpffeature: cleanup `report` (af780eb1) by bas smit &lt;bas@baslab.org&gt;
  - bpffeature: detect supported program types (ce5bbb78) by bas smit &lt;bas@baslab.org&gt;
  - bpffeature: detect supported map types (437df58d) by bas smit &lt;bas@baslab.org&gt;
  - bpffeature: remove boilerplate (ac4ad41c) by bas smit &lt;bas@baslab.org&gt;
  - Avoid calling "slow" regex constructor (fc88784e) by bas smit &lt;bas@baslab.org&gt;
  - CreateMemSet: llvm10: Fix compilation errors (6f81111c) by Ovidiu Panait &lt;ovidiu.panait@windriver.com&gt;
  - Discard return value for emitAndFinalize() (29caf4b7) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Require C++17 to build (458bf66d) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Make docker run command more generic (#1182) (c67730c4) by Connor Nelson &lt;Connor@ConnorNelson.com&gt;
  - Use host network when building docker image (23c29ff1) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - fix typo (92f25f95) by zeil &lt;nonamezeil@gmail.com&gt;
  - Resolve USDT binaries relative to mount namespace (3bb4a9fd) by Dale Hamel &lt;dale.hamel@shopify.com&gt;
  - Add docker images as options in install.md (30756be7) by Dale Hamel &lt;dale.hamel@srvthe.net&gt;
  - Add "edge" build, push master to :latest and :edge (b0e6bdc7) by Dale Hamel &lt;dale.hamel@shopify.com&gt;
  - ast: add missing parameter name (f156a0fb) by bas smit &lt;bas@baslab.org&gt;
  - Add the Japanese translation version of the one-liner tutorial (78621fb1) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Revert "No need to promote scalars to 64-bit" (9a9d1451) by Dale Hamel &lt;dale.hamel@shopify.com&gt;
  - fix build error (ed48e795) by bas smit &lt;bas@baslab.org&gt;
  - Make BEFORE clause in runtime tests synchronous (77f93dbc) by Dale Hamel &lt;dale.hamel@shopify.com&gt;
  - Only need to rebuild codegen tests if C++ files change (d0792c06) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Replace tabs with spaces (f4e377a1) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - No need to promote scalars to 64-bit (8af25ae9) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Regenerate codegen_includes.cpp when files it references are updated (d6d0e836) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - ci: Add LLVM 9 (42dab3c9) by bas smit &lt;bas@baslab.org&gt;
  - codegen: add LLVM-9 rewriter exceptions (681d1850) by bas smit &lt;bas@baslab.org&gt;
  - codegen: LLVM9 rewriter (3ec8af95) by bas smit &lt;bas@baslab.org&gt;
  - codegen: Rewrite tests (aefc89e7) by bas smit &lt;bas@baslab.org&gt;
  - codegen: Remove version dependence from codegen (cd3ab819) by bas smit &lt;bas@baslab.org&gt;
  - Add STATIC_LIBC=ON to Docker build scripts (6ef3af3c) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Support pushing docker images to quay.io from github actions (b8ab21ae) by Dale Hamel &lt;dale.hamel@shopify.com&gt;
  - Add xenial to CI build (153e61ef) by Ace Eldeib &lt;alexeldeib@gmail.com&gt;
  - Only send IRC notifications for build failures on master (471e79b7) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - vagrant: fix formatting (e8a14566) by bas smit &lt;bas@baslab.org&gt;
  - vagrant: Add fedora 31 (c2354a78) by bas smit &lt;bas@baslab.org&gt;
  - vagrant: Update ubuntu boxes (9610895c) by bas smit &lt;bas@baslab.org&gt;
  - Add Dockerfile.release for bpftrace docker image on quay.io (c2568ee5) by Dale Hamel &lt;dale.hamel@shopify.com&gt;
  - Mark context accesses as volatile (56d4721e) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Cast ctx automatically depending on a program type (0e4282e1) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Access context fields directly (3a910814) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Error if trying to use context as a map key/value (b7d2510b) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Introduce Type::ctx (f05b4cda) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - No need to check result of check_assignment (f04c1ad9) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Add workaround to remove duplicate entries in uprobe symbols listing (8f5e90f4) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - cmake: add GNUInstallDirs support (2f380013) by Ovidiu Panait &lt;ovpanait@gmail.com&gt;
  - Allow running tests as non-root (again) (efa2da20) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Report kernel instruction limit (76770de3) by bas smit &lt;bas@baslab.org&gt;
  - Add missing <string> include to btf.h (145041ec) by Augusto Caringi &lt;acaringi@redhat.com&gt;

## [0.9.4] 2020-02-04

### Highlights

  - New calls: `signal`, `override`, `strncmp`
  - Support for attaching to `kprobes` at an offset
  - Support for struct bitfields

### All Changes

#### Added
  - Add support to attach kprobe to offset (e31e398) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Add `--info` flag (afafbf5) by bas smit &lt;bas@baslab.org&gt;
  - Mark 'override_return' as unsafe (49cd031) by bas smit &lt;bas@baslab.org&gt;
  - Implement bpf_override_return (784c64e) by bas smit &lt;bas@baslab.org&gt;
  - arch: Add support for powerpc64 registers (472f5ed) by Sandipan Das &lt;sandipan@linux.ibm.com&gt;
  - Add source line information to error messages (46e62c0) by bas smit &lt;bas@baslab.org&gt;
  - Support octal and hexadecimal escape sequences in string (873d7ba) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Implement `signal` (32bb577) by bas smit &lt;bas@baslab.org&gt;
  - Make `signal` unsafe (be676b5) by bas smit &lt;bas@baslab.org&gt;
  - Implement strncmp (a1d0263) by Jay Kamat &lt;jaygkamat@gmail.com&gt;
  - Add builtin: cpid (cae4dcf) by bas smit &lt;bas@baslab.org&gt;
  - Allow uprobe offset on quoted attach points (6432609) by bas smit &lt;bas@baslab.org&gt;
  - Allow string literals as signal specifiers (0230f98) by bas smit &lt;bas@baslab.org&gt;
  - Implement bitfield support (8822cc2) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;

#### Changed
  - Take first binary match for PATH lookup on uprobe and USDT (ec5c2c3) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Infer `uaddr` pointer type from ELF symbol size (59b0659) by bas smit &lt;bas@baslab.org&gt;
  - Rename `override_return` to `override` (96cb4b5) by bas smit &lt;bas@baslab.org&gt;
  - Runtime feature testing (17f3c82) by bas smit &lt;bas@baslab.org&gt;
  - Silenced unsigned/signed comparison warning (75101f9) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - error message for verification buffer size (41c0ab8) by Gordon Marler &lt;gmarler@bloomberg.net&gt;
  - Reimplement `elapsed` using a hidden map (2613ea6) by bas smit &lt;bas@baslab.org&gt;
  - Remove dependency on 'command' shell builtin (3f7a94a) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - Make parsing fail if lexing fails (d092cb1) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Limit increment/decrement to variables (c126441) by bas smit &lt;bas@baslab.org&gt;
  - Only warn about missing BTF info in debug mode (f84ae5c) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Allow uretprobe at an address (f0785b5) by bas smit &lt;bas@baslab.org&gt;
  - fix uprobe address on short name (f7ed963) by bas smit &lt;bas@baslab.org&gt;
  - Reverse return value of strncmp (384640e) by Jay Kamat &lt;jaygkamat@gmail.com&gt;
  - Make strcmp return 0 on match (8d9069c) by bas smit &lt;bas@baslab.org&gt;
  - Differentiate between regular structs and typedef'd structs (8d34209) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;

#### Fixed
  - Support "." in attach point function argument (c532159) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - clang_parser: workaround for asm_inline in 5.4+ kernel headers (c30e4dd) by Andreas Gerstmayr &lt;agerstmayr@redhat.com&gt;
  - Consider signed array (9bb6a8b) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Support anonymous struct/union in BTF::type_of() (36d9914) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Allow resolving binary paths in different mount ns (124e569) by Dale Hamel &lt;dale.hamel@shopify.com&gt;
  - Avoid useless allocations in strncmp (551664e) by bas smit &lt;bas@baslab.org&gt;
  - Avoid comparing past string length (b10dc32) by bas smit &lt;bas@baslab.org&gt;
  - Call llvm.lifetime.end after memcpy if the expression is not a variable (8b2d219) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - bug: Strip newlines from log message (361d1fc) by bas smit &lt;bas@baslab.org&gt;
  - Fix buggy signed binop warnings (e87897c) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Reuse `cat` and `system` ID when expanding probes (79aada5) by bas smit &lt;bas@baslab.org&gt;
  - Remove unneeded `probe_read`s from `strcmp` (43b4e4c) by bas smit &lt;bas@baslab.org&gt;
  - Fix func variable in uprobe (d864f18) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Add space for the error message about kernel.perf_event_max_stack (de2a7a8) by Kenta Tada &lt;Kenta.Tada@sony.com&gt;
  - Improve uprobe/usdt visitor error handling and messaging (5005902) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - Fix some semantic analyser crashes (b11dc75) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Fix codegen for modulo operation (fe0ed5a) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;

#### Documentation
  - Document `override_return` (b83b51d) by bas smit &lt;bas@baslab.org&gt;
  - Add documentation on BTF (6623f25) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - docs: limit to 105 chars (91e9dad) by bas smit &lt;bas@baslab.org&gt;
  - docs: Remove double shebang (da8b10c) by bas smit &lt;bas@baslab.org&gt;
  - docs: improve readability of code snippets (34a394a) by bas smit &lt;bas@baslab.org&gt;
  - docs: remove unneeded html elements (06d8662) by bas smit &lt;bas@baslab.org&gt;
  - Fix typos (e5ad6b9) by Michael Prokop &lt;michael.prokop@synpro.solutions&gt;
  - One-liner tutorial: Use "struct" when casting (7a5624c) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - docs: Add centos 7 repo (1b4cb8f) by bas smit &lt;bas@baslab.org&gt;
  - docs: Fix typo (b38dbd0) by bas smit &lt;bas@baslab.org&gt;
  - Move debug flags closer to each other in help message (df61049) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add binutils dependency to documentation (c57204c) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add documentation on release procedure (#981) (528fd6e) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - fix: Minor spelling correction (b3a6aee) by Jason Wohlgemuth &lt;jhwohlgemuth@users.noreply.github.com&gt;
  - Document `signal` (d5f3c75) by bas smit &lt;bas@baslab.org&gt;
  - INSTALL.md: Fix TOC link (1ab0a71) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Amend sizes in documentation and provide date (ddd10fe) by Dale Hamel &lt;dale.hamel@shopify.com&gt;
  - Docs: add missing TOC entry (8c1d4e9) by bas smit &lt;bas@baslab.org&gt;
  - Add the chinese version for one liners tutorial (15a930e) by supersojo &lt;suyanjun218@163.com&gt;

#### Internal
  - Reorganize tests/ directory (193177b) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix typing issues in `CreateMapUpdateElem` (e86b9bb) by bas smit &lt;bas@baslab.org&gt;
  - Fix typing issues in `CreateMapLookup` (14af118) by bas smit &lt;bas@baslab.org&gt;
  - Fix build: Add namespace to BPF_FUNC_override_return (b6de734) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Unify vmlinux and BTF location list (1d39776) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Disable probe.kprobe_offset_fail_size runtime test in CI (1497434) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - fmt: update formatting in clang_parser.cpp (aefc424) by Andreas Gerstmayr &lt;agerstmayr@redhat.com&gt;
  - Use constexpr (b59c3a7) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Make use of feature testing (b01f89c) by bas smit &lt;bas@baslab.org&gt;
  - Import libbpf (132e1ee) by bas smit &lt;bas@baslab.org&gt;
  - Rename BPFTRACE_BTF_TEST to BPFTRACE_BTF (5bbeb31) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Add test for anonymous struct/union processing using BTF (240f59a) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Switch tests suite to `bcc_foreach_sym` (a251477) by bas smit &lt;bas@baslab.org&gt;
  - Make resolve_binary_paths include non-executable shared objects in its return. (c3d1095) by Michał Gregorczyk &lt;michalgr@fb.com&gt;
  - Remove full static builds from travis (4fe9064) by Dale Hamel &lt;dale.hamel@srvthe.net&gt;
  - Move ast.h definitions into ast.cpp (f0dd0b4) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Use subprocess.Popen text mode (47de78b) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix debian libclang only linking (a9a2f0f) by Dale Hamel &lt;dale.hamel@srvthe.net&gt;
  - Build static+libc images using github actions (4794aba) by Dale Hamel &lt;dale.hamel@srvthe.net&gt;
  - Enable static+glibc builds and embedding LLVM deps (b1ae710) by Dale Hamel &lt;dale.hamel@shopify.com&gt;
  - Create StderrSilencer helper class to redirect stderr (b59b97a) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add missing semicolon (add4117) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - ast: codegen: Add abstraction for stack pointer offset (d19614d) by Sandipan Das &lt;sandipan@linux.ibm.com&gt;
  - clang-format: avoid breaking indent in irbuilderbpf.h (5b6d236) by bas smit &lt;bas@baslab.org&gt;
  - Non-invasive formatting of src/*.h (98328f1) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Clang Format: Update line-break penalties (30d5b8d) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - correct for clang-format check (bb30265) by Gordon Marler &lt;gmarler@bloomberg.net&gt;
  - Add requested msg prefix (f3327bd) by Gordon Marler &lt;gmarler@bloomberg.net&gt;
  - add requested changes. (c9453b5) by Gordon Marler &lt;gmarler@bloomberg.net&gt;
  - Show current log size in msg as starting point (7942b9d) by Gordon Marler &lt;gmarler@bloomberg.net&gt;
  - Fix CI clang-format (13556f9) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Make ninja work with build system (76bb97a) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Clang Format: switch/case bracketing style fixes (f4e46b2) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Clang Format: Don't wrap braces after namespace (4b26e3f) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Add non-literal strncmp test (1c41333) by bas smit &lt;bas@baslab.org&gt;
  - Rename literal test (4295985) by bas smit &lt;bas@baslab.org&gt;
  - refactor CreateMapLookupElem (7b7ab95) by bas smit &lt;bas@baslab.org&gt;
  - Add a semantic and runtime test to test task_struct field accesses (8519550) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Use `struct task_struct` instead of `task_struct` (d39db3a) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - BTF leftover for full type rename (5088682) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Create a single is_numeric() function in utils (374ca46) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Warn if cmake is less than 3.13 when building with ASAN (ad3b9f3) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Remove unnecessary division (81b7c0a) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add build option, BUILD_ASAN, to turn on address sanitizer (04d015e) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Properly indent cmake config (24a7695) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Use mocks consistently in codegen tests so they don't require root to run (b261833) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Enable -Werror on CI builds (2f0f5db) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - CMakeLists cleanups (6b8d7ad) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Disable deprecated ORCv1 warning in llvm (607b8af) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Normalize code (0878020) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Pass location to uprobe+offset probe (8c1a355) by bas smit &lt;bas@baslab.org&gt;
  - Use symbolic constants instead of numeric literal (457aab9) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add clang-format rule to travis CI (3b9e959) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Turn off clang-format for specific long lists (bcbfaa0) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add .clang-format file (b04e478) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Change reinterpret_cast to static cast and fix formatting (03d2d67) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Add PER_CPU detection helper (594fd34) by bas smit &lt;bas@baslab.org&gt;
  - Store the BPF map type in the map object (2e850c5) by bas smit &lt;bas@baslab.org&gt;
  - format: align parser (b3680e6) by bas smit &lt;bas@baslab.org&gt;
  - Make ASSERTs in helper functions fail the parent testcase (ddaa482) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Add dependency on testprogs and bpftrace to runtime tests (7870091) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add custom target for testprogs (d799e83) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Move testprogs cmake definition before runtime test definitions (6783448) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add tests for resolve_binary_path (8fb727a) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - Fix tests to run without $PATH (c1c60c2) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - Add runtime tests for ambiguous wildcard matches (cca9040) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - Add regression tests for modulo operation (0a1cb65) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Don't take reference of a pointer (61ba68a) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Silence test suite (8d1f691) by bas smit &lt;bas@baslab.org&gt;
  - Disable builtin.cgroup runtime test in CI (8277876) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add a RUNTIME_TEST_DISABLE environment to runtime tests (6c984ea) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add script to compare tool codegen between builds (d95a2d1) by bas smit &lt;bas@baslab.org&gt;
  - Minor btf cleanups (a10479b) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add FieldAnalyser to the clang parser tests (13b06d2) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Iterate only over detected types in BTF::c_def (409d7ad) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add BPFtrace::btf_set_ to replace global BTF type set (06a09ca) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add BTF::type_of function (4378e24) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Adding FieldAnalyser class (ec3c621) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Move BTF object into BPFtrace class (fdf3940) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add runtime test (db81d25) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add clang_parser test (6cae624) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Use struct instead of class (fbe3bf6) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Make `strncmp` codegen unsigned (af54c9b) by bas smit &lt;bas@baslab.org&gt;
  - Avoid shift/reduce warnings (3761904) by bas smit &lt;bas@baslab.org&gt;
  - Treat stackmode as identifier (e018da5) by bas smit &lt;bas@baslab.org&gt;
  - Define all `call`s in the lexer to avoid redefinition (b8ddf25) by bas smit &lt;bas@baslab.org&gt;
  - Remove `_` suffix from local variables (34d4654) by bas smit &lt;bas@baslab.org&gt;
  - Add regression test for #957 (253cfd6) by bas smit &lt;bas@baslab.org&gt;
  - Fix paths in tests (a8dcb02) by bas smit &lt;bas@baslab.org&gt;
  - Allow runtime tests to be ran from any directory (9139bed) by bas smit &lt;bas@baslab.org&gt;
  - Link libiberty during static builds (aa8c7ba) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - cpid vector -> single (52ff6e3) by bas smit &lt;bas@baslab.org&gt;
  - 0.9.3 Changelog (f4ea282) by bas smit &lt;bas@baslab.org&gt;
  - Bump to 0.9.3 (3d1e022) by bas smit &lt;bas@baslab.org&gt;
  - Add `signal` tests (95cba2b) by bas smit &lt;bas@baslab.org&gt;
  - Add missing kernel option in INSTALL.md (099d1c9) by Edouard Dausque &lt;git@edouard.dausque.net&gt;
  - Make printing the LLVM IR from a debugger easier (d534295) by bas smit &lt;bas@baslab.org&gt;
  - Make `uprobes - list probes by pid` test more quiet (b2a570a) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - vagrant: add binutils-dev dependency (2e73e04) by Matheus Marchini &lt;mmarchini@netflix.com&gt;
  - Fix maptype bugs (028c869) by bas smit &lt;bas@baslab.org&gt;
  - Disable -Winconsistent-missing-override in mock.h (d3cb095) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Disable -Wcast-qual for bpf/btf.h (b308a9c) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Import used headers (979992e) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Fix modernize-deprecated-headers warnings (b09836b) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Fix -Wcast-align (ce45470) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Fix -Wdelete-abstract-non-virtual-dtor (cb78da3) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Fix -Wstring-plus-int (3e52a3d) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Fix -Wunreachable-code-loop-increment (f354911) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Fix -Wbraced-scalar-init (6fc82ed) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Fix -Wmismatched-tags (e29a4f2) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Fix -Wformat-security (cc3ef62) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Fix some compiler warnings (9a85f10) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;

## [0.9.3] 2019-11-22

### Highlights

  - Allow attaching to uprobes at an offset
  - BTF support
  - integer casts
  - integer pointer casts

### All Changes

#### Added
  - Add support to cast to a pointer of integer (#942) (8b60006) by Masanori Misono &lt;m.misono760@gmail.com&gt;
  - Add sargX builtin (9dc6024) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - Add support to specify symbol with offset to uprobe (33e887f) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - add threadsnoop tool (f021967) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - add tcpsynbl tool (0cbc301) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - add tcplife tool (51d8852) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - add swapin tool (c80753b) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - add setuids tool (439311a) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - add naptime tool (572de59) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - add biostacks tool (162bc63) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - Add check if uprobe is aligned (e2c65bd) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Support wildcards in probe path (#879) (2a361cc) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - Add --btf option (ec931fa) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Introduce int casts (ee82e64) by bas smit &lt;bas@baslab.org&gt;
  - utils: unpack kheaders.tar.xz if necessary (#768) (896fafb) by Matt Mullins &lt;mokomull@gmail.com&gt;
  - Add support to check for libbpf package (8e0800c) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add signed types (53cf421) by bas smit &lt;bas@baslab.org&gt;
  - Add location support to builtins (a79e5a6) by bas smit &lt;bas@baslab.org&gt;
  - Add location support to calls (c1b2a91) by bas smit &lt;bas@baslab.org&gt;
  - Add location support to the AST (67c208d) by bas smit &lt;bas@baslab.org&gt;
  - Highlight bpftrace source files (cfbaa2f) by Paul Chaignon &lt;paul.chaignon@orange.com&gt;
  - Add travis CI build icon to README.md (50375e2) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add IRC badge to README (a20af57) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;

#### Changed
  - Use the same shebang for all tools (78eb451) by bas smit &lt;bas@baslab.org&gt;
  - Change exit() to send SIGTERM to child processes (649cc86) by Matheus Marchini &lt;mmarchini@netflix.com&gt;
  - Make `stats` and `avg` signed (809dc46) by bas smit &lt;bas@baslab.org&gt;
  - Refactor error printer to make severity level configurable (676a6a7) by bas smit &lt;bas@baslab.org&gt;
  - Make output line-buffered by default (#894) (78e64ba) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - cmake: don't use language extensions (like gnu++14) (4ce4afc) by Matheus Marchini &lt;mmarchini@netflix.com&gt;
  - add file extension on README (545901c) by sangyun-han &lt;sangyun628@gmail.com&gt;
  - build: don't set -std flag manually (3cbc482) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Don't use random value on stack (b67452b) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - codegen: ensure logical OR and AND works with non-64-bit integers (69cbd85) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Allow child process to exit on attach_probe failure (#868) (ecf1bc8) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - json output: Make output more consistent (#874) (9d1269b) by Dan Xu &lt;dxu@dxuuu.xyz&gt;
  - Do not generate extra load for ++/-- for maps/variables (3f79fad) by Jiri Olsa &lt;jolsa@kernel.org&gt;

#### Fixed
  - semantic_analyser: validate use of calls as map keys (b54c085) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - codegen: fix rhs type check for binop (2d87213) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix map field access (a9acf92) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Correctly parse enums (59d0b0d) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Allow build from uncommon bcc installation (9986329) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Fix sigint handling under heavy load (0058d41) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Assign default value to elem_type to avoid undefined behavior. (a0b8722) by Florian Kuebler &lt;kuebler@google.com&gt;
  - Strip trailing newline from error message (5315eee) by bas smit &lt;bas@baslab.org&gt;
  - Use strerror to improve `cgroupid` error message (72de290) by bas smit &lt;bas@baslab.org&gt;
  - Initialize member variable (4dd8bb8) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix umask build issue (#861) (24de62a) by Michael Würtinger &lt;michael@wuertinger.de&gt;
  - Handle SIGTERM gracefully (#857) (fb47632) by Dan Xu &lt;dxu@dxuuu.xyz&gt;
  - json output: suppress output if map is not initialized (348975b) by Andreas Gerstmayr &lt;agerstmayr@redhat.com&gt;
  - fix 'designated initializers' build errors (#847) (4910e75) by Alek P &lt;alek-p@users.noreply.github.com&gt;
  - remove invalid 'unused attribute' (9bf8204) by Matheus Marchini &lt;mat@mmarchini.me&gt;

#### Documentation
  - Mention sargX builtin in docs (352e983) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - Update reference guide (65c97fd) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Docs: fix inconsistent install script option (a65e3d8) by Daniel T. Lee &lt;danieltimlee@gmail.com&gt;
  - docs: Fix mismatch between code and example (2499437) by bas smit &lt;bas@baslab.org&gt;
  - fix typo in example text - correct name of script (891021b) by sangyun-han &lt;sangyun628@gmail.com&gt;
  - Add openSUSE package status link into install.md (#859) (613b42f) by James Wang &lt;jnwang@suse.com&gt;
  - Fix a typo in reference_guide (e7420eb) by James Wang &lt;jnwang@suse.com&gt;
  - Ubuntu instructions: add minimum release version (413c1a0) by Peter Sanford &lt;psanford@sanford.io&gt;

#### Internal
  - Add tests for sargX builtin (774a7a6) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - Add test (0c08b1d) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Avoid leaking state between cmake tests (625269f) by bas smit &lt;bas@baslab.org&gt;
  - Avoid testing for FOUR_ARGS_SIGNATURE on systems without bfd (cd1d231) by bas smit &lt;bas@baslab.org&gt;
  - Unset `CMAKE_REQUIRED_LIBRARIES` to avoid influencing tests (ab0665b) by bas smit &lt;bas@baslab.org&gt;
  - Define PACKAGE to make libbfd happy (d165396) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix 'may be used uninitialized' build warning in bfd-disasm.cpp (ffd203b) by Augusto Caringi   &lt;acaringi@redhat.com&gt;
  - Change "variable.tracepoint arg casts in predicates" runtime test (9aae057) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - bfd-disasm: fix LIBBFD_DISASM_FOUR_ARGS_SIGNATURE (7d62627) by Matheus Marchini &lt;mmarchini@netflix.com&gt;
  - semantic_analyser: fix gcc build error on xenial (0e6014a) by Matheus Marchini &lt;mmarchini@netflix.com&gt;
  - Prevent forks from notifying the IRC channel (ca93440) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add runtime tests for uprobe offset/address (d9c2bab) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Bypass the uprobe align check in unsafe mode (18b9635) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Adding tests for uprobe offset definitions (d894d0e) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add BfdDisasm class (8198628) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add Disasm class (6f7bc6f) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add support to check for libbfd/libopcodes libraries (542f2b9) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add resolve_offset_uprobe functions (7be4143) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add address and func_offset to ast::AttachPoint and Probe classes (893201a) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Fix `sigint under heavy load` runtime test (4f7fd67) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Notify irc channel on build failures (83b5684) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add BTF class (43530aa) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Read every BTF type (67dbe3f) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Disable codegen.logical_and_or_different_type test in alpine CI (5271e6c) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Warn when doing signed division (#910) (fff3b05) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add short option for --btf and update usage (88dbe47) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add BTF tests (47621bb) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add ClangParser::parse_btf_definitions function (54cf4ab) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add SizedType::operator!= function (8cb79f9) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add ClangParserHandler::check_diagnostics function (3e75475) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add ClangParser::visit_children function (4842ccf) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add BTF::c_def function (02a2d0d) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add Expression::resolve string set (0779333) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Add curtask task_struct cast type for field access (80cb0d7) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - test: fix watchpoint runtime test flakiness (88fc1b8) by Matheus Marchini &lt;mmarchini@netflix.com&gt;
  - Disable sign checking for division binop (8084463) by bas smit &lt;bas@baslab.org&gt;
  - Add ability to test for warnings (b19ebb6) by bas smit &lt;bas@baslab.org&gt;
  - Revert "Signed types (#834)" (6613a14) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Signed types (#834) (446facb) by bas smit &lt;bas@baslab.org&gt;
  - test: fix flaky 32-bit tp runtime test (c0d94c8) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - travis: use bionic and enable runtime tests (57c5a55) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - test: print bpftrace script when codegen test fails (b0c4902) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - tests: add test for cat with fmt str (#842) (b3143a6) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Fix tests (#844) (fd0ec92) by bas smit &lt;bas@baslab.org&gt;

## [0.9.2] 2019-07-31

### Highlights

 - New environment variables (BPFTRACE_NO_USER_SYMBOLS, BPFTRACE_LOG_SIZE)
 - New probe type: memory `watchpoint`
 - Support for JSON output

### All Changes

#### Added
 - Add vargs support for cat() builtin (similar to system) (7f1aa7b) by Augusto Caringi &lt;acaringi@redhat.com&gt;
 - Add memory watchpoint probe type (#790) (854cd4b) by Dan Xu &lt;dxu@dxuuu.xyz&gt;
 - Add support for Go symbol names to uaddr (#805) (e6eb3dd) by Jason Keene &lt;jasonkeene@gmail.com&gt;
 - add option for JSON output (5c6f20a) by Andreas Gerstmayr &lt;andreas@gerstmayr.me&gt;
 - Add $# for number of positional arguments (ec8b61a) by Mark Drayton &lt;mdrayton@gmail.com&gt;
 - Add BPFTRACE_NO_USER_SYMBOLS environment variable (#800) (41d2c9f) by Dan Xu &lt;dxu@dxuuu.xyz&gt;
 - Add line numbers to parser error messages (a584752, 2233ea7) by bas smit &lt;bas@baslab.org&gt;
 - Add new environment variable BPFTRACE_LOG_SIZE (2f7dc75, 7de1e84, 2f7dc75) by Ray Jenkins &lt;ray.jenkins@segment.com&gt;

#### Changed
 - Terminate when map creation fails (6936ca6) by bas smit &lt;bas@baslab.org&gt;
 - Print more descriptive error message on uprobe stat failure (0737ec8) by Dan Xu &lt;dxu@dxuuu.xyz&gt;
 - Allow '#' in attach point path (2dfbc93) by Dan Xu &lt;dxu@dxuuu.xyz&gt;
 - Disable `func`, `retval` and `reg` for tracepoints since tracepoints can't access this information (7bfc0f8) by bas smit &lt;bas@baslab.org&gt;

#### Fixed
 - Skip keys which were removed during iteration on `print` (bfd1c07) by Andreas Gerstmayr &lt;agerstmayr@redhat.com&gt;
 - Fix exiting prematurely on strace attach (a584752..0e97b2c) by Jay Kamat &lt;jaygkamat@gmail.com&gt;
 - Fix unused variable warnings (9d07eb5) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
 - Fix alignment issues on `ntop` (2006424) by Matheus Marchini &lt;mat@mmarchini.me&gt;
 - Fix BEGIN being triggered multiple times when bpftrace is run a second time (14bc835) by bas smit &lt;bas@baslab.org&gt;
 - Fix crash when using $0 (b41d66d) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
 - Fix tcp tools printing errors (206b36c) by bas smit &lt;bas@baslab.org&gt;

#### Documentation
 - Update Ubuntu install instructions (4e3ffc3) by Brendan Gregg &lt;bgregg@netflix.com&gt;
 - Clarify help message for `-o` (d6e9478) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
 - `opensnoop.bt` was incorrectly linked to load.bt (d74fae0) by southpawflo &lt;16946610+southpawflo@users.noreply.github.com&gt;
 - Document multiple attach points for probes (21bc5bf) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
 - Fix incorrect reference to the `probe` key (83d473c) by Jeremy Baumont &lt;jeremy.baumont@gmail.com&gt;

#### Internal
 - Fix failing test (086c018) by bas smit &lt;bas@baslab.org&gt;
 - Collapse bcc symbol resolvers by process executable (63ff8b0) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
 - Remove unneeded probe read (7d0aa99) by bas smit &lt;bas@baslab.org&gt;
 - Fix runtime test parser to not break with commented out tests (#824) (b73c963) by Augusto Mecking Caringi &lt;acaringi@redhat.com&gt;
 - bpftrace: optimize resolve_kname (#765) (ec5278d) by Matheus Marchini &lt;mat@mmarchini.me&gt;
 - Resolve symbol names using bcc_elf_foreach_sym (#811) (a2d9298) by Jason Keene &lt;jasonkeene@gmail.com&gt;
 - Add basic editorconfig for defining style (#775) (5b20829) by Jay Kamat &lt;jaygkamat@gmail.com&gt;
 - Auto-generate list of includes for codegen tests (e3b8ecd) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
 - Do not emit GEP instruction when pushing string literals to stack (#667) (e98530c) by Michał Gregorczyk &lt;michalgr@users.noreply.github.com&gt;
 - tool style tweaks (8bb0940) by Brendan Gregg &lt;bgregg@netflix.com&gt;
 - Clean up unused variable (#787) (8627e84) by Dan Xu &lt;dxu@dxuuu.xyz&gt;
 - Make member variables end with underscores (c76a8e4) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
 - Fail in case there's unresolved type in definitions (ecb7a1b, 2239756, a6a4fb3) by Jiri Olsa &lt;jolsa@kernel.org&gt;

## [0.9.1] 2019-06-25

### Highlights

  - Introduce compound assignment operators (`+=` and friends) (7f26468) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Add support for arrays and IPv6 for the `ntop` builtin function (c9dd10f) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Add basic support to enums (treat them as constants) (e4cb6ce) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Add macro definition support (8826470,af67b56,14e892b) by Matheus Marchini &lt;mat@mmarchini.me&gt;, Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;
  - Add support for arrays and IPv6 for the `ntop` builtin function (c9dd10f) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Allow comparison of two string variables (7c8e8ed) by williangaspar &lt;williangaspar360@gmail.com&gt;
  - Add pre and post behavior to ++ and -- operators (f2e1345...9fea147) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - [**BREAKING CHANGE**] Ban kprobes that cause CPU deadlocks (40cf190) by Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;
  - [**BREAKING CHANGE**] Add unsafe-mode and make default execution mode safe-mode (981c3cf,4ce68cd) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;

### All Changes

#### Added

  - Introduce compound assignment operators (`+=` and friends) (7f26468) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Add KBUILD_MODNAME (a540fba) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - Add flags for include paths and files (`--include` and `-I`, respectively) (632652f) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - List uprobes with -l (122ef6e) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Add BPFTRACE_MAX_PROBES environment variable (ddb79df) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Add option to redirect trace output to file (462a811) by bas smit &lt;bas@baslab.org&gt;
  - Add script to check kernel requirements (ac19743) by bas smit &lt;bas@baslab.org&gt;
  - Add USDT wildcard matching support (82dbe4e...3725edf,648a65a) by Dale Hamel &lt;dale.hamel@srvthe.net&gt;
  - Add support for arrays and IPv6 for the `ntop` builtin function (c9dd10f,24a463f) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Add 'cat' builtin (ae1cfc9,ef9baf8) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Add array indexing operator [] for one-dimensional, constant arrays (ec664a1) by Dale Hamel &lt;dalehamel@users.noreply.github.com&gt;
  - Allow dots to truncate fields in `printf` (0f636c9) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - Add `BPFTRACE_MAP_KEYS_MAX` environment variable, and increase default map keys limit to 4096 (fab8bf6) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - Add support for delimiters in join() statement (eb40386) by Jason Koch &lt;jkoch@netflix.com&gt;
  - Add basic support to enums (treat them as constants) (e4cb6ce) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Add macro definition support (8826470,af67b56,14e892b) by Matheus Marchini &lt;mat@mmarchini.me&gt;, Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;
  - Add hardware:branch-misses (9631623) by Jason Koch &lt;jkoch@netflix.com&gt;
  - Allow comparison of two string variables (7c8e8ed) by williangaspar &lt;williangaspar360@gmail.com&gt;

#### Changed

  - Add pre and post behavior to ++ and -- operators (f2e1345...9fea147) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Parse negative integer literals correctly (108068f) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Tools improvements (9dbee04,a189c36) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - USAGE message trim (18d63b0) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - Allow `probe` builtin for `BEGIN` and `END` probes (3741efe) by bas smit &lt;bas@baslab.org&gt;
  - Default -d and -dd output to stdout (ecea569) by Jay Kamat &lt;jaygkamat@gmail.com&gt;
  - Return with error code if clang finds an error while parsing structs/enums/macros/includes (364849d) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Restore map key validation (7826ee3) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Add `/usr/include` to default header search path (32dd14b) by Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;
  - More information in error message when failing to open script file (3b06e5f) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - [**BREAKING CHANGE**] Add unsafe-mode and make default execution mode safe-mode (981c3cf,4ce68cd) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Safety measure for LLVM out of memory issue (6b53e4a) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - Allow non-zero lhist min value (51fdb6a) by bas smit &lt;bas@baslab.org&gt;
  - Improvements in startup speed (5ed8717,1ffb50f) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - When using -c, spawn the child process only when the tracing is ready (e442e9d) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Allow more pointers as ints (3abc93e) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - Validate that PID (received via `-p`) is an integer (48206ad) by Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;
  - Promote map keys to 64-bit (e06e39d) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - Add hint when traced PID is not running (9edb3e1) by Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;
  - Allow pointers in printf, mapkeys, and filters (0202412,280f1c6) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - Allow ksym() lookups on function pointers (2139d46) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - [**BREAKING CHANGE**] Ban kprobes that cause CPU deadlocks (40cf190) by Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;

#### Fixed

  - Workaround for asm goto in Kernel 5+ headers (60263e1) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Properly handle invalid `args` utilization (13c2e2e) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Fix abort caused by lhist with incorrect number of arguments (41036b9) by bas smit &lt;bas@baslab.org&gt;
  - Fix anonymous struct parsing (ea63e8b) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Fix code generation for bitwise and logical not on integer values (f522296) by synth0 &lt;synthkaf@outlook.com&gt;
  - Fix typo in type mismatch error message (83924f8) by Jay Kamat &lt;jaygkamat@gmail.com&gt;
  - Fix clearing action for some aggregations (dcd657e) by Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;
  - Fix possible crash if an invalid char is used in search (c4c6894) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Fix headers includes by using -isystem rather than -I (32daaa2) by Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;
  - Fix exit() function bypassing END probe processing #228 (f63e1df,e4c418e,5cce746) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Fix order in which probes fire (a4bf870) by John Gallagher &lt;john.gallagher@delphix.com&gt;
  - Stop throwing 'failed to initialize usdt context for path' error message (1fa3d3c) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Fix stringification of ntop keys in maps (598050e) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Fix parsing of forward-decl structs inside structs (354c919) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Fix struct definition from headers (4564d55) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Avoid crash if incorrect command line option is used (aa24f29) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Fix clang_parser for LLVM 8+ (80ce138) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Fix semicolon being required in some cases after if statements (13de974) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Throw error message if argN or retval is used with incorrect probe type (b40354c) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Fix USDT listing (`-l`) without a search pattern (af01fac) by Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;
  - Add missing space to error message (e1f5f14) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Fix unroll in some cases (mostly when the generated code was large) (702145c) by Matheus Marchini &lt;mat@mmarchini.me&gt;

#### Documentation

  - Added info on clang environment variables (7676530) by Richard Elling &lt;Richard.Elling@RichardElling.com&gt;
  - Fix snap instructions. (3877e46) by George Slavin &lt;george.r.slavin@gmail.com&gt;
  - Fix ustack documentation (5eeeb10) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Replace stack with kstack (49e01e0) by Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;
  - Fix TOC in the reference guide (05eb170) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Fix broken links in docs (c215c61,845f9b6) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix inaccurate tutorial on listing (a4aeaa5) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Add documentation for BEGIN/END probes (81de93a) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Update build instructions for Ubuntu (38b9620) by bas smit &lt;bas@baslab.org&gt;
  - INSTALL.md: update required dependency for usdt (5fc438e) by Zi Shen Lim &lt;zlim.lnx@gmail.com&gt;
  - Fix ++ and -- text on undefined variables (47ab5cd) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Reference guide small fixes (0d9c1a4) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Add instructions to install on Gentoo (3c23187) by Patrick McLean &lt;chutzpah@gentoo.org&gt;
  - Add install instructions for Ubuntu snap package (0982bb6) by George Slavin &lt;george.r.slavin@gmail.com&gt;
  - Fix spelling mistake (a45869f) by George Slavin &lt;george.r.slavin@gmail.com&gt;
  - Fix 'one liners tutorial': use 'openat' instead of 'open' in examples (0cce55c) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Add contributing section to the README (2a08468) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Standardise documentation on the bpftrace name (135a4d3) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Update install instructions (505b50a) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;

#### Internal

  - [tests] add missing tests to codegen.cpp (012ebda) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - tests: add runtime tests for regression bugs (ee57b6f) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - vagrant: add Ubuntu 19.04 box (60e6d0a) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - docker: add Fedora 30 (9ccafa0) by Zi Shen Lim &lt;zlim.lnx@gmail.com&gt;
  - Add Vagrantfile for ubuntu (b221f79) by bas smit &lt;bas@baslab.org&gt;
  - tests: fix and improve runtime tests (c7b3b2f) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Clean up includes in clang_parser (374c240) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Remove double `check_nargs` call (c226c10) by bas smit &lt;bas@baslab.org&gt;
  - Fix call.system runtime test (3b4f578) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix call.str runtime test (8afbc22) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix k[ret]probe_order runtime tests (27a334c) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Remove old TODO (5be3752) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Add clang_parser::parse_fail test (6fd7aac) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Fix some bugs with positional parameters (13fb175) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Fix runtime tests (a05ee59) by bas smit &lt;bas@baslab.org&gt;
  - Enable multiline matching for runtime test regex (c8763e4) by bas smit &lt;bas@baslab.org&gt;
  - Add environment var support to runtime tests (543513e) by bas smit &lt;bas@baslab.org&gt;
  - Disable codegen.printf_offsets test for LLVM5 CI build (ea8a7e4) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Fix LLVM 5 tests (938e79b) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Refactor find_wildcard_matches() to allow for proper testing (371c7cf) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - tests: Use Python 3 for integration tests + test fix (#651) (4b0e477) by Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;
  - Add --unsafe to more runtime tests (8b2234a) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix 'ignoring return value' build warning (bdc9f16) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Fix 'signed overflow' related build warning (0ece2a9) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Fix UnboundLocalError on skipped test (03958cb) by John Gallagher &lt;john.gallagher@delphix.com&gt;
  - Use getopt_long instead of getopt (d732298) by Daniel Xu &lt;dxu@dxuuu.xyz&gt;
  - Fix docs typo (05bf095) by bas smit &lt;bas@baslab.org&gt;
  - check explicitly for systemtap sys/sdt.h and ignore if not present (831633d) by Jason Koch &lt;jkoch@netflix.com&gt;
  - Suppress build warning in GCC >=8 caused by #474 (71d1cd5) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Remove more tabs (e9594dd) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Convert tabs to spaces (585e8b5) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Add existence tests for kstack, kstack() and ustack() (954d93d) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - [tests] more runtime tests enhancements (#586) (249c7a1) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Codegen: Fix assigning non-struct "internal" values to maps (4020a5c) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Fix typo on LLVM_REQUESTED_VERSION macro in CMakeLists.txt (82dbe4e) by Quentin Monnet &lt;quentin.monnet@netronome.com&gt;
  - Fix build warning (a77becb) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - [tests] allow tests to be skipped if a given condition is not met (59fa32a) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - [tests] make other.if_compare_and_print_string less flaky (840bbb3) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Fix compile warnings and mark more functions as const (cfb058d) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Misc readability fixes (9581e01) by Fangrui Song &lt;i@maskray.me&gt;
  - build: unify dockerfiles under a bionic image (445fb61) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - [tests] fix and enhance runtime tests (ea5deb9) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - [tests] add test script to run tools with -d (4ff113d) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - [clang_parser] decouple kernel cflags from the parser method (ad753d5) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Address TODO items related to objdump dependency (382b9b7) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - Fall back to objdump/grep if bcc is older (fdd02ec) by Adam Jensen &lt;acjensen@gmail.com&gt;
  - [clang_parser] pass BPFtrace as arg instead of StructMap (a0af75f) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - [ast] introduce Identifier type to AST (389d55f) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - use CMAKE_SYSTEM_PROCESSOR when selecting whether to include x86_64 or aarch64 sources (0ea7a63) by Michał Gregorczyk &lt;michalgr@fb.com&gt;
  - Clearify error message for mismatched llvm. (9b77fee) by George Slavin &lt;george.r.slavin@gmail.com&gt;
  - Add more info to LLVM mismatch error message (1e3b1be) by George Slavin &lt;george.r.slavin@gmail.com&gt;
  - Allow 0 as kernel version during first attempt to call bcc_prog_load (13499ac) by Michał Gregorczyk &lt;michalgr@fb.com&gt;
  - Fix bpftrace_VERSION_MINOR in CMakeLists.txt (8 -> 9) (13321eb) by Matheus Marchini &lt;mat@mmarchini.me&gt;
  - Fix version information when not building inside a git repo (#489) (1f33126) by Augusto Caringi &lt;acaringi@redhat.com&gt;
  - Do not try to load bpf program with unknown kernel version (2c00b7f) by Michał Gregorczyk &lt;michalgr@fb.com&gt;
  - Add better checks for llvm version (4fe081e) by George Slavin &lt;george.r.slavin@gmail.com&gt;
  - Fix deprecated stack warning in builtin_stack test (a1aaed8) by George Slavin &lt;george.r.slavin@gmail.com&gt;
  - add test for 32-bit tp args (77f7cb7) by Brendan Gregg &lt;bgregg@netflix.com&gt;
  - tests: add some basic integration tests (e9805af) by Javier Honduvilla Coto &lt;javierhonduco@gmail.com&gt;
  - Fix and simplify lexer.l (57bae63) by Fangrui Song &lt;i@maskray.me&gt;
  - Fix 2 clang warnings: -Wmismatched-tags and -Wpessimizing-move (18da040) by Fangrui Song &lt;i@maskray.me&gt;
  - Revert "Stop linking against bcc-loader-static" (5b6352c) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - fix typo on BPF_FUNC_get_current_cgroup_id missing message (27371c3) by Jason Koch &lt;jkoch@netflix.com&gt;
  - propagate HAVE_GET_CURRENT_CGROUP_ID to ast modules (57e30da) by Jason Koch &lt;jkoch@netflix.com&gt;
  - Add missing include (5763dc2) by Michał Gregorczyk &lt;michalgr@fb.com&gt;
  - No need for `if` when we're not doing anything (a65ad14) by Alastair Robertson &lt;alastair@ajor.co.uk&gt;
  - Make indirect* related data static (24d9dd2) by Jiri Olsa &lt;jolsa@kernel.org&gt;
  - Fix issues, add tests and improve reliability of positional parameters (acec163,f2e1345) by Matheus Marchini &lt;mat@mmarchini.me&gt;

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
