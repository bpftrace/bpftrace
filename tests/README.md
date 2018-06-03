# BPFtrace Tests

Tests can be run with the `bpftrace_test` executable.

The code generation tests are based on the output of LLVM 5, so may give errors if run with different version. They can be excluded by running:

`bpftrace_test --gtest_filter=-codegen*`
