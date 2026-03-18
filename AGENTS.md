# AGENTS.md

This file provides context for AI agents when working on the bpftrace codebase.

## Project overview

bpftrace is a high-level tracing language for Linux eBPF. It uses LLVM as a
compiler backend to generate BPF bytecode, and libbpf/bcc for kernel
interaction. The language prioritizes conciseness, readability, and
clean abstraction over eBPF complexity. Written in C++20.

## Build

See [docs/developers.md](docs/developers.md#building) for full build
instructions. Before running any tests, verify the `build/` directory and
test binaries exist. If they don't, build first.

Quick reference (Nix, preferred):

```
nix develop          # enter dev shell
cmake -B build -DCMAKE_BUILD_TYPE=Debug
make -C build -j$(nproc)
```

The built binary is at `build/src/bpftrace`.

## Tests

All contributions must not break existing tests and should add new tests when
relevant. See [tests/README.md](tests/README.md) for the full test reference
(test types, directives, runtime variables, etc.).

Quick reference:

```
./build/tests/bpftrace_test                          # unit tests
./build/tests/bpftrace_test --gtest_filter='Parser.*' # filtered unit tests
sudo ./build/tests/self-tests.sh                      # self tests
sudo ./build/tests/runtime-tests.sh                   # runtime tests
sudo ./build/tests/runtime-tests.sh --filter="^uprobe" # filtered runtime tests
sudo ./build/tests/tools-parsing-test.sh              # tool parsing tests
```

## Code formatting

- C++ code: `clang-format` with the repo's `.clang-format` config. Run
  `git clang-format upstream/master` to format changed code. Every commit
  must be correctly formatted (no separate "fix formatting" commits).
- bpftrace scripts (`.bt` files): format with `bpftrace --fmt` or
  `scripts/bpftrace_tidy.sh`.

## Code style and conventions

- C++ code: Run this script which will fix clang tidy issues: `./scripts/clang_tidy.sh -u`
- C++20 standard, 80-column line limit, 2-space indentation.
- Variables: `snake_case`. Private class members get a trailing underscore
  (`my_var_`). Public members and struct fields do not.
- Structs: passive data only, all public fields, no methods.
- Classes: everything else.
- Comments: prefer C++ style (`//`) over C style (`/* */`).
- Defer to the [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)
  for anything not specified here.

## Error handling

- Recoverable errors: return values (`Result`, `std::optional`, `int`, `bool`).
  Do NOT use exceptions for recoverable errors.

## Logging

Use the `LOG()` macro with these levels:
- `DEBUG` - always logs (includes file/line info)
- `V1` - only with `-v` flag; for common warnings like "BTF not available"
- `HINT` - tips to resolve a problem (use after WARNING or ERROR)
- `WARNING` - issues that allow execution to continue
- `ERROR` - user errors causing exit; primarily used in `main.cpp`
- `BUG` - aborts; indicates internal/unexpected issues (not user errors)

## Source architecture

The compilation pipeline:
1. **Lexer/Parser** (`src/lexer.l`, `src/parser.yy`) - flex/bison, generates AST
2. **AST passes** (`src/ast/passes/`) - semantic analysis, type checking, AST replacement, macro expansion
3. **Codegen** (`src/ast/passes/codegen_llvm.cpp`, `src/ast/irbuilderbpf.cpp`) - LLVM IR generation
4. **BPF bytecode** (`src/bpfbytecode.cpp`) - compiled BPF programs
5. **Runtime** (`src/bpftrace.cpp`, `src/attached_probe.cpp`) - probe attachment and event handling

Key directories:
- `src/ast/` - AST node definitions, visitors, pass manager
- `src/ast/passes/` - all compiler passes (type_checker, codegen_llvm, field_analyser, etc.)
- `src/stdlib/` - bpftrace standard library
- `src/btf/` - BTF (BPF Type Format) support
- `tests/` - unit tests (GoogleTest), self tests, runtime tests
- `tools/` - example bpftrace tools/scripts
- `docs/` - developer and language documentation

## Design principles

- Prefer user experience elegance over implementation elegance.
- Prefer boring, verbose, removable code over clever premature abstractions.
- Substantial or breaking changes require the RFC process (see CONTRIBUTING.md).
- Performance of BPF programs and runtime is on the critical path; elsewhere,
  simplicity and clarity matter more than performance.

## PR conventions

- One commit per PR (squash + rebase, no merge commits).
- Commit titles should be changelog-worthy.
- User-impacting changes require a `CHANGELOG.md` entry.
- Language changes must update `docs/language.md`, `docs/stdlib.md`, or
  `man/adoc/bpftrace.adoc`. To regenerate the `docs/stdlib.md` run `./scripts/generate_stdlib_docs.py`
- New behavior must be covered by tests.
