# bpftrace Tests

There are two test suites in the project.

## Unit tests

These tests can be run with the `bpftrace_test` executable.

The code generation tests are based on the output of LLVM 5, so may give errors if run with different version. They can be excluded by running:

`bpftrace_test --gtest_filter=-codegen*`

## Runtime tests

Runtime tests will call the bpftrace executable.
* Run: `sudo make runtime-tests` inside your build folder
* By default, runtime-tests will look for the executable in the build folder. You can set a value to the environment variable `BPFTRACE_RUNTIME_TEST_EXECUTABLE` to customize it

### Test programs

You can add test programs for your runtime tests by placing a `.c` file corresponding to your test program in `tests/testprogs`.

The test file `tests/testprogs/my_test.c` will result in an executable that you can call and probe in your runtime test at `./testprogs/my_test`

This intended to be useful for testing uprobes and USDT probes, or using uprobes to verify some other behavior in bpftrace.
