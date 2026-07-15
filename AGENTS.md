# AGENTS.md

This file provides repository-specific guidance for AI agents working on the
bpftrace codebase.

## Project overview

bpftrace is a high-level tracing language and userspace tool for Linux eBPF.
It uses LLVM as a compiler backend and libbpf/bcc for kernel interaction.
The project prioritizes concise scripts, readable code, and clean abstractions
over raw eBPF complexity. The codebase is written in C++20.

## Repository setup

- This repository uses git submodules. Fresh clones should be initialized with
  `git submodule update --init --recursive`.
- Prefer the Nix development environment. CI uses Nix, so it is the most
  reliable way to match the supported build and test setup.
- All Nix-based build and test commands should run inside `nix develop` (or via
  `nix develop --command ...`).

## Build

See [`docs/developers.md`](docs/developers.md#building) for the full build
instructions.

Preferred build flow:

```bash
nix develop
cmake -B build -DCMAKE_BUILD_TYPE=Debug
make -C build -j$(nproc)
```

Distro-native builds are also supported once dependencies are installed:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
make -C build -j$(nproc)
```

Build outputs:

- Main binary: `build/src/bpftrace`
- Unit test binary: `build/tests/bpftrace_test`

Before running tests, make sure the `build/` directory and expected test
binaries exist. If they do not, build first.

## Tests

Every contribution should avoid breaking existing tests and should add new tests
when relevant. See [`tests/README.md`](tests/README.md) for the complete test
reference, including directives and runtime variables.

Common test commands:

```bash
./build/tests/bpftrace_test
./build/tests/bpftrace_test --gtest_filter='Parser.*'
sudo ./build/tests/self-tests.sh
sudo --preserve-env=PATH --preserve-env=PYTHONPATH ./build/tests/runtime-tests.sh
sudo ./build/tests/runtime-tests.sh --filter='^uprobe.*:-list'
sudo ./build/tests/tools-parsing-test.sh
```

Test categories:

- Unit tests: GoogleTest-based tests in `tests/*.cpp`
- Self tests: `test:` probe scripts in `tests/self`
- Runtime tests: framework-driven tests in `tests/runtime`
- Tool parsing tests: validation for shipped tools in `tools/`

If you change language behavior, code generation, runtime behavior, or shipped
stdlib/tools content, update or add the relevant tests.

## Formatting and style

- C++ formatting uses `clang-format` with the repository's `.clang-format`.
  `git clang-format upstream/master` is the preferred way to format changes.
- bpftrace scripts (`.bt`) should be formatted with `bpftrace --fmt` or
  `scripts/bpftrace_tidy.sh`.
- Avoid separate "fix formatting" commits; each commit should already be
  formatted correctly.
- Run `./scripts/clang_tidy.sh -u` when you need to address clang-tidy issues.

Core coding conventions:

- C++20, 80-column limit, 2-space indentation
- Prefer `snake_case` for variables
- Private class members use a trailing underscore (`member_`)
- Public members and struct fields do not use a trailing underscore
- Use `struct` only for passive data objects; use `class` otherwise
- Prefer C++-style comments (`//`) in C++ sources
- Defer to [`docs/coding_guidelines.md`](docs/coding_guidelines.md) and then the
  C++ Core Guidelines when a rule is not covered elsewhere

## Error handling and logging

- Recoverable errors should be propagated through return values such as
  `Result`, `std::optional`, `int`, or `bool`
- Do not use exceptions for recoverable errors
- For unrecoverable user-facing failures, prefer throwing
  `FatalUserException`

Use the `LOG()` macro with the established levels:

- `DEBUG`: always logs and includes file/line information
- `V1`: verbose-only logging for common warnings
- `HINT`: follow-up guidance after a warning or error
- `WARNING`: non-fatal issues that allow execution to continue
- `ERROR`: invalid user input or usage that causes exit
- `BUG`: internal unexpected failures that abort

## Source architecture

The main pipeline is:

1. Parser (`src/parser.cpp`, `src/parser.h`) builds the AST
2. AST passes (`src/ast/passes/`) perform semantic analysis and transforms
3. Code generation (`src/ast/passes/codegen_llvm.cpp`,
   `src/ast/irbuilderbpf.cpp`) emits LLVM IR
4. BPF bytecode generation (`src/bpfbytecode.cpp`) builds BPF programs
5. Runtime components (`src/bpftrace.cpp`, `src/attached_probe.cpp`) attach
   probes and process events

Key directories:

- `src/ast/` - AST nodes, visitors, and pass manager
- `src/ast/passes/` - compiler passes such as type checking and codegen
- `src/btf/` - BTF support
- `src/stdlib/` - bundled standard library content
- `tests/` - unit, self, runtime, and tool parsing tests
- `tools/` - example and packaged bpftrace tools
- `docs/` - developer and language documentation
- `man/` - manual page sources

## Design and contribution expectations

- Prefer user experience elegance over implementation cleverness
- Prefer simple, explicit, removable code over premature abstractions
- Performance is critical on the BPF/runtime path; elsewhere, prioritize
  clarity and maintainability
- Substantial or breaking changes should follow the RFC process described in
  [`CONTRIBUTING.md`](CONTRIBUTING.md)

## Documentation and PR conventions

- User-impacting changes require a `CHANGELOG.md` entry
- Language changes must update the relevant user-facing docs in
  `docs/language.md`, `docs/stdlib.md`, or `man/adoc/bpftrace.adoc`
- Regenerate `docs/stdlib.md` with `./scripts/generate_stdlib_docs.py` when
  changing documented stdlib behavior
- New behavior should be covered by tests
- Pull requests are expected to be squash-merged so the final PR results in one
  changelog-worthy commit on `master`

## Related references

- [`README.md`](README.md)
- [`docs/developers.md`](docs/developers.md)
- [`docs/coding_guidelines.md`](docs/coding_guidelines.md)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`tests/README.md`](tests/README.md)
