# BPFtrace Tests

There is 2 test suite in the project.

## Unit test

These tests can be run with the `bpftrace_test` executable.

The code generation tests are based on the output of LLVM 5, so may give errors if run with different version. They can be excluded by running:

`bpftrace_test --gtest_filter=-codegen*`

## Runtime

  Runtime tests will call bpftrace executable.
  * Default run: `sudo make runtime-tests` inside your build folder
  * Alternative Run: `sudo ./tests/runtime-tests.sh` inside your build folder
  * Change path to bpftrace executable: Edit the `/etc/environment` file by adding the variable `BPFTRACE_PATH=path/to/bpftrace`
