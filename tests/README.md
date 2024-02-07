# bpftrace Tests

There are three different types of tests: [unit](#unit-tests), [runtime](#runtime-tests), and [tool parsing](#tool-parsing-tests).

Every contribution should (1) not break the existing tests and (2) introduce new tests if relevant.

## Unit tests

Unit tests for individual components (semantic analyser, codegen, etc.) are based on the GoogleTest framework. These tests can be run with the `bpftrace_test` executable. Tests can be selected with the `--gtest_filter` flag or the `GTEST_FILTER` environment variable, see `--help` for more information. These are located in `tests/*.cpp` and are executed by `<builddir>/tests/bpftrace_test`.

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

These tests run as part of the normal suite of unit tests if you are running LLVM 12.
If not, you need to install 'nix' and run these tests via this script:
`./tests/codegen-tests.sh`.

#### Updating

**LLVM 12**

If you are running LLVM 12 or want to only update specific tests with `--gtest_filter`
run `<builddir>/tests/bpftrace_test` with `BPFTRACE_UPDATE_TESTS=1` and the `test`
helper will update the IR instead of running the tests.

**Not LLVM 12**

Run `./tests/codegen-tests.sh -u`. This updates all the codegen tests.

## Runtime tests

Runtime tests will call the bpftrace executable. These are located in `tests/runtime` and are managed by a custom framework.

* Run: `sudo make runtime_tests` inside your build directory or `sudo <builddir>/tests/runtime-tests.sh`
* Use the `TEST_FILTER` environment variable (or the `--filter` arg when running `runtime-tests.sh`) to only run a subset of the tests e.g. `TEST_FILTER="uprobe.*" sudo make runtime-tests`
* There are environment variables to override paths for the bpftrace executables, if necessary. See runtime-tests.sh for details.

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
* `EXPECT`: The expected output. Python regular expressions are supported.
   One or more `EXPECT` and `EXPECT_NONE` or a single `EXPECT_FILE` or 
   `EXPECT_JSON` is required.
* `EXPECT_NONE`: The negation of `EXPECT`, which also supports Python regular 
   expressions.
* `EXPECT_FILE`: A file containing the expected output, matched as plain
   text after stripping initial and final empty lines
* `EXPECT_JSON`: A json file containing the expected output, matched after
   converting the output and the file to a dict (thus ignoring field order).
* `TIMEOUT`: The timeout for the testcase (in seconds). This field is required.
* `BEFORE`: Run the command in a shell before running bpftrace. The command
  will be terminated after testcase is over. Can be used multiple times,
  commands will run in parallel.
* `AFTER`: Run the command in a shell after running bpftrace (after the probes
  are attached). The command will be terminated after the testcase is over.
* `CLEANUP`: Run the command in a shell after test is over. This holds any
  cleanup command to free resources after test completes.
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
* `NEW_PIDNS`: This will execute the `BEFORE`, the bpftrace (`RUN` or `PROG`),
  and the `AFTER` commands in a new pid namespace that mounts proc. At least one
  `BEFORE` is required.

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

Tools parsing tests run every tool in the `tools/` directory and ensure that the tools shipped with bpftrace are valid and can run. The validity of tools outputs is not checked at the moment.

Tests can be executed by: `sudo <builddir>/tests/tools-parsing-test.sh`

### Flags and variables

The following environment variables can be set to modify the behaviour of the
test suite

- `BPFTRACE_EXECUTABLE`: location of the bpftrace executable, if left unset the
  script attempts to autodetect it.
- `TOOLS_TEST_DISABLE`: comma separated list of tools to skip, e.g.
  `vfscount.bt,swapin.bt`
- `TOOLS_TEST_OLDVERSION`: tests the tools/old version of these tools instead.
