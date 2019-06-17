# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

  - Fail in case there's unresolved type in definitions (ecb7a1b) by Jiri Olsa &lt;jolsa@kernel.org&gt;
    - Reverted in 2239756, waiting for a PR to fix an issue we found before re-enabling it

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
