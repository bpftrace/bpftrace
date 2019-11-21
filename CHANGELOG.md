# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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
