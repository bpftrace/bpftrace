# bpftrace Tests

There are two test suites in the project.

## Unit tests

These tests can be run with the `bpftrace_test` executable.

### Codegen tests

The codegen tests verify that the optimized IR matches our expectations.

The tests are defined as C++ files in the `tests/codegen` directory and look like:

```
TEST(codegen, call_avg)
{
  test("kprobe:f { @x = avg(pid) }", NAME);
}
```

The `test` function does all the heavy lifting and is defined in
`tests/codegen/common.h`. It compiles the specified program (first argument) and
compares it (string compare) with the expected result, a file named by the
second argument. The `NAME` macro holds the test name,  which is `call_avg` in
this case.

#### Updating

Run `./scripts/update_codegen_tests.sh` after making codegen changes up update
the expected LLVM IR.

Alternatively (if you need more control over which tests are updated), if the
test is run with `BPFTRACE_UPDATE_TESTS=1` the `test` helper will update the IR
instead of running the tests.

## Runtime tests

Runtime tests will call the bpftrace executable.
* Run: `sudo make runtime-tests` inside your build folder
* By default, runtime-tests will look for the executable in the build folder. You can set a value to the environment variable `BPFTRACE_RUNTIME_TEST_EXECUTABLE` to customize it

If you need to run a test program to probe (eg, uprobe/USDT), you can use the
`BEFORE` clause. The test scripts will wait for the test program to have a pid.

The BEFORE clause will block up to the TIMEOUT waiting for a PID matching the
basename of the last space-separated token. For instance, if the BEFORE clause
is `./testprogs/usdt_test`, it will wait for a processed called `usdt_test`.
If it is `./testprogs/mountns_wrapper usdt_test` it will also wait for a
process called `usdt_test`. This approach is invalidated if a test program
requires arguments in the future, but so far test programs are simple and
separate minimal programs to test tracing functionality, and argument passing
hasn't been required. If test programs need arguments, a more sophisticated
approach will be necessary.

### Test programs

You can add test programs for your runtime tests by placing a `.c` file corresponding to your test program in `tests/testprogs`.

You can add test libraries for your runtime tests by placing a `.c` file corresponding to your test library in `tests/testlibs`.

The test file `tests/testprogs/my_test.c` will result in an executable that you can call and probe in your runtime test at `./testprogs/my_test`

This is intended to be useful for testing uprobes and USDT probes, or using uprobes to verify some other behavior in bpftrace. It can also
be used to tightly control what code paths are triggered in the system.
