# bpftrace Tests

## Unit tests

These tests can be run with the `bpftrace_test` executable.
Tests can be selected with the `--gtest_filter` flag or the `GTEST_FILTER`
environment variable, see `--help` for more information.

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

Runtime tests are grouped into "suites". A suite is usually a single file. The
name of the file is the name of the suite.

### Runtime test directives

Each runtime testcase consists of multiple directives. In no particular order:

* `NAME`: Name of the test case. This field is required.
* `RUN`: Run the command in a shell. See "Runtime variables" below for
  available placeholders. This XOR the `PROG` field is required
* `PROG`: Run the provided bpftrace program. This directive is preferred over
  `RUN` unless you must pass flags or create a shell pipeline.  This XOR the
  `RUN` field is required
* `EXPECT`: The expected output. Python regular expressions are supported. This
  field is required.
* `TIMEOUT`: The timeout for the testcase (in seconds). This field is required.
* `BEFORE`: Run the command in a shell before running bpftrace. The command
  will be terminated after testcase is over.
* `AFTER`: Run the command in a shell after running bpftrace. The command will
  be terminated after the testcase is over.
* `MIN_KERNEL`: Skip the test unless the host's kernel version is >= the
  provided kernel version. Try not to use this directive as kernel versions may
  be misleading (backported kernel features, for example)
* `REQUIRES`: Run a command in a shell. If it succeeds, run the testcase.
  Else, skip the testcase.
* `ENV`: Run bpftrace invocation with additional environment variables. Must be
  in format NAME=VALUE. Supports multiple values separated by spaces.
* `ARCH`: Only run testcase on provided architectures. Supports `|` to logical
  OR multiple arches.
* `REQUIRES_FEATURE`: Only run testcase if the following bpftrace feature is
  built in. See `bpftrace --info` and `runtime/engine/runner.py` for more
  details. Also supports negative features (by prefixing `!` before feature).
* `WILL_FAIL`: Mark that this test case will exit uncleanly (ie exit code != 0)

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

### Runtime variables

Runtime variables are placeholders that the runtime test engine will fill out
before running the test. These exist b/c the values of the variables are generally
not known until test time. The following runtime variables are available for the
`RUN` directive:

* `{{BPFTRACE}}`: Path to bpftrace executable
* `{{BPFTRACE_AOTRT}}`: Path to bpftrace ahead-of-time runtime executable
* `{{BEFORE_PID}}`: Process ID of the process in `BEFORE` directive

### Test programs

You can add test programs for your runtime tests by placing a `.c` file corresponding to your test program in `tests/testprogs`.

You can add test libraries for your runtime tests by placing a `.c` file corresponding to your test library in `tests/testlibs`.

The test file `tests/testprogs/my_test.c` will result in an executable that you can call and probe in your runtime test at `./testprogs/my_test`

This is intended to be useful for testing uprobes and USDT probes, or using uprobes to verify some other behavior in bpftrace. It can also
be used to tightly control what code paths are triggered in the system.

## Tool parsing tests

`./tests/tools-parsing-test.sh`

The tool parsing tests ensure that the tools shipped with bpftrace are valid and
can run. The actual output is not validated.

### Flags and variables

The following environment variables can be set to modify the behaviour of the
test suite

- `BPFTRACE_EXECUTABLE`: location of the bpftrace executable, if left unset the
  script attempts to autodetect it.
- `TOOLS_TEST_DISABLE`: comma separated list of tools to skip, e.g.
  `vfscount.bt,swapin.bt`
- `TOOLS_TEST_OLDVERSION`: tests the tools/old version of these tools instead.
