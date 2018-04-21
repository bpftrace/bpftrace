# BPFtrace Tests

Tests can be run with the `bpftrace_test` executable.

The code generation tests are based on the output of the latest stable version of LLVM, so may give errors if run with an older LLVM. They can be excluded by running:

`bpftrace_test --gtest_filter=-codegen*`
