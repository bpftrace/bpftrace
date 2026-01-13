#!/usr/bin/env -S python3 -u

"""
This script is the entrypoint for the CI.

To make CI errors easier to reproduce locally, please limit
this script to using only the standard library on a recent-ish
python 3 release.

Please also be conservative with what tools you expect on the host
system when subprocessing out. Safe things to expect are `git` and
`nix`. Note that when running subprocessing _inside_ the nix env
you are free to use whatever the flake provides.
"""

from collections import namedtuple
from enum import Enum
from functools import lru_cache
from io import StringIO
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Callable, Dict, List, Optional, Self, Union

BUILD_DIR = "build-ci"

#
# Knobs CI might use. We choose to use env vars b/c it's less
# messy than propagating flags everywhere.
#

# Default nix target is empty string which by convention is the
# latest LLVM release we support
NIX_TARGET = os.environ.get("NIX_TARGET", "")
CMAKE_BUILD_TYPE = os.environ.get("CMAKE_BUILD_TYPE", "Release")
RUN_TESTS = os.environ.get("RUN_TESTS", "1")
RUN_AOT_TESTS = os.environ.get("RUN_AOT_TESTS", "0")
CC = os.environ.get("CC", "cc")
CXX = os.environ.get("CXX", "c++")
CI = os.environ.get("CI", "false")
NIX_TARGET_KERNEL = os.environ.get("NIX_TARGET_KERNEL", "")
TOOLS_TEST_OLDVERSION = os.environ.get("TOOLS_TEST_OLDVERSION", "")
TOOLS_TEST_DISABLE = os.environ.get("TOOLS_TEST_DISABLE", "")
AOT_ALLOWLIST_FILE = os.environ.get("AOT_ALLOWLIST_FILE", "")
RUNTIME_TESTS_FILTER = os.environ.get("RUNTIME_TESTS_FILTER", "")


class TestStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


TestResult = namedtuple("TestResult", ["test_name", "status"])


def truthy(value: str) -> bool:
    v = value.strip().lower()
    return v == "true" or v == "1"


@lru_cache(maxsize=1)
def root() -> Path:
    """Return the absolute path root of git repo"""
    output = subprocess.check_output(["git", "rev-parse", "--show-toplevel"])
    return Path(output.decode("utf-8").strip())


def _which(cmd: str) -> Path:
    p = shutil.which(cmd)
    if not p:
        raise RuntimeError(f"Failed to find binary: {cmd}")

    return Path(p)


@lru_cache(maxsize=1)
def nix() -> Path:
    """Return the absolute path of nix binary in host env"""
    return _which("nix")


@lru_cache(maxsize=1)
def sudo() -> Path:
    """Return the absolute path of sudo binary in host env"""
    return _which("sudo")


class FoldOutput:
    """
    GitHub Actions output folding context manager.

    Will automatically fold output for all operations. In an ideal world we'd
    like to leave the failed operations unfolded, but there's currently no way
    to do this in GHA without buffering output.
    """

    def __init__(self, name: str):
        self.name = name
        self.in_ci = truthy(CI)

    def __enter__(self) -> Self:
        if self.in_ci:
            # Start a collapsible section in GitHub Actions logs
            print(f"::group::{self.name}")
        else:
            print(f"\n======= {self.name} ======")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.in_ci:
            print("::endgroup::")


def shell(
    cmd: List[str],
    as_root: bool = False,
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
):
    """
    Runs the specified command in the proper nix development
    environment.

    Note that output is sent to our inherited stderr/stdout and
    that any errors immediately raise an exception.
    """
    c: List[Union[str, Path]] = [
        nix(),
        "develop",
    ]

    if NIX_TARGET:
        c.append(NIX_TARGET)

    if not env:
        env = {}

    # Nix needs to know the home dir
    if "HOME" in os.environ:
        env["HOME"] = os.environ["HOME"]

    c.append("--command")
    if as_root:
        c += [
            sudo(),
            # We need to preserve path so that default root PATH is not
            # generated. If that occurs, then commands run in nix env
            # can escape and use host system binaries. This creates some
            # very hard to debug errors in CI.
            #
            # And yes, I realize that we should probably be using nix's
            # sandboxing via checkPhase, but unfortunately that does not
            # play nice with root or writing temporary files. So that
            # requires further investigation.
            "--preserve-env=PATH",
            "--preserve-env=PYTHONPATH",
            "--preserve-env=" + ",".join([n for n in env]),
        ]
    c += cmd

    subprocess.run(
        c,
        cwd=cwd if cwd else root(),
        check=True,
        # Explicitly clear the environment so that any commands run
        # inside the nix environment cannot accidentally depend on
        # host environment. There are known very-hard-to-debug issues
        # that occur in CI when the envirionment escapes.
        env=env,
    )


def configure():
    """Run cmake configure step"""
    with FoldOutput("configure"):
        # fmt: off
        c = [
            "cmake",
            "-B",
            BUILD_DIR,

            # Dynamic configs
            f"-DCMAKE_C_COMPILER={CC}",
            f"-DCMAKE_CXX_COMPILER={CXX}",
            f"-DCMAKE_BUILD_TYPE={CMAKE_BUILD_TYPE}",

            # Static configs
            f"-DCMAKE_VERBOSE_MAKEFILE=1",
            f"-DBUILD_TESTING=1",
            f"-DENABLE_SKB_OUTPUT=1",
            f"-DBUILD_ASAN=1",
            f"-DHARDENED_STDLIB=1",
        ]
        # fmt: on

        shell(c)


def build():
    """Build everything"""
    with FoldOutput("build"):
        cpus = multiprocessing.cpu_count()
        shell(["make", "-C", BUILD_DIR, "-j", str(cpus)], env={"AFL_USE_ASAN": "1"})


def test_one(name: str, cond: Callable[[], bool], fn: Callable[[], None]) -> TestResult:
    """Runs a single test suite and returns the result"""
    status = TestStatus.PASSED

    if cond():
        try:
            with FoldOutput(name):
                fn()
        except subprocess.CalledProcessError:
            status = TestStatus.FAILED
    else:
        status = TestStatus.SKIPPED

    return TestResult(test_name=name, status=status)


def tests_finish(results: List[TestResult]):
    """Process test results and output status"""
    skipped = sum(1 for r in results if r.status == TestStatus.SKIPPED)
    passed = sum(1 for r in results if r.status == TestStatus.PASSED)
    failed = sum(1 for r in results if r.status == TestStatus.FAILED)
    failed_names = [r.test_name for r in results if r.status == TestStatus.FAILED]
    total_run = passed + failed

    output = StringIO()
    print("\n======= Results =======", file=output)
    if skipped:
        print(f"{skipped} suite(s) skipped", file=output)
    if failed:
        print(f"{failed}/{total_run} suites(s) failed: {failed_names}", file=output)
    else:
        print(f"{passed}/{total_run} suites(s) passed", file=output)
    print("=======================", file=output)

    if failed:
        raise RuntimeError(output.getvalue())
    else:
        print(output.getvalue())


def run_with_kernel(script):
    if NIX_TARGET_KERNEL:
        # Bring kernel into nix store then grab the path
        subprocess.run([nix(), "build", NIX_TARGET_KERNEL], check=True)
        eval = subprocess.run(
            [nix(), "eval", "--raw", NIX_TARGET_KERNEL],
            check=True,
            capture_output=True,
            text=True,
        )

        # nf_tables and xfs are necessary for testing kernel modules BTF support
        modules = ["kvm", "nf_tables", "xfs"]
        modprobe = f"modprobe -d {eval.stdout} -a {' '.join(modules)}"

        c = f"{modprobe} && {' '.join(script)}"
        cmd = ["vmtest", "-k", f"{eval.stdout}/bzImage", c]
    else:
        cmd = script

    shell(
        cmd,
        # Don't need root if running tests in a VM
        as_root=not NIX_TARGET_KERNEL,
        cwd=Path(BUILD_DIR),
        env={
            "CI": CI,
            "RUNTIME_TEST_COLOR": "yes",
            # Disable UI to make CI and manual runs behave identically
            "VMTEST_NO_UI": "1",
        },
    )


def run_self_tests():
    """Runs self tests, under a controlled kernel if requested"""
    run_with_kernel(["./tests/self-tests.sh"])


def run_runtime_tests():
    """Runs runtime tests, under a controlled kernel if requested"""
    cmd = ["./tests/runtime-tests.sh"]
    if RUNTIME_TESTS_FILTER:
        cmd.append(f"--filter=\"{RUNTIME_TESTS_FILTER}\"")
    run_with_kernel(cmd)


def fuzz():
    """
    Run a basic fuzz smoke test.
    """
    # Make basic inputs and output directories.
    Path(BUILD_DIR, "inputs").mkdir(exist_ok=True)
    Path(BUILD_DIR, "outputs").mkdir(exist_ok=True)

    # For now, seed the inputs directly with a trivial program. These can be
    # codified differently in the future, but this is sufficient for a basic
    # fuzz smoke test. Actual fuzzing should have a wide variety of inputs.
    Path(BUILD_DIR, "inputs", "seed.bt").write_text("BEGIN {}")

    results = [
        test_one(
            "fuzz",
            lambda: truthy(RUN_TESTS),
            lambda: shell(
                # fmt: off
                cmd = [
                    "afl-fuzz",
                    "-M", "0",
                    "-m", "none",
                    "-i", "inputs",
                    "-o", "outputs",
                    "-E", "10", # 10 execs, smoke test only.
                    "-t", "60000",
                    "--",
                    "src/bpftrace",
                    "--test=codegen",
                    "@@",
                ],
                env = {
                    "AFL_NO_AFFINITY": "1",
                    "ASAN_OPTIONS": "abort_on_error=1,symbolize=0",
                    "BPFTRACE_BTF": "",
                    "BPFTRACE_AVAILABLE_FUNCTIONS_TEST": "",
                    # This setting [1] is used to skip the core pattern check,
                    # so crashes may be missed. Since this is just a smoke
                    # test, we use this rather than change the system state.
                    # [1] https://github.com/mirrorer/afl/blob/master/docs/env_variables.txt
                    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "",
                },
                cwd=Path(BUILD_DIR),
                # fmt: on
            ),
        ),
    ]

    tests_finish(results)


def test():
    """
    Run all requested tests

    Note we're not using `ctest` b/c it's kinda a pain to work with.
    We don't use any of it's advanced features but still suffer from
    it's limitations, like not being able to flexibly configure test
    runners (we need `sudo` for some suites). It also buffers output
    rather oddly.
    """
    results = []

    results.append(
        test_one(
            "bpftrace_test",
            lambda: truthy(RUN_TESTS),
            lambda: shell(
                ["gtest-parallel", "./tests/bpftrace_test"],
                cwd=Path(BUILD_DIR),
                env={"GTEST_COLOR": "yes"},
            ),
        )
    )
    results.append(
        test_one(
            "self-tests.sh",
            lambda: truthy(RUN_TESTS),
            run_self_tests,
        )
    )
    results.append(
        test_one(
            "runtime-tests.sh",
            lambda: truthy(RUN_TESTS),
            run_runtime_tests,
        )
    )
    results.append(
        test_one(
            "tools-parsing-test.sh",
            lambda: truthy(RUN_TESTS),
            lambda: shell(
                [
                    "./tests/tools-parsing-test.sh",
                ],
                as_root=True,
                cwd=Path(BUILD_DIR),
                env={
                    "TOOLS_TEST_OLDVERSION": TOOLS_TEST_OLDVERSION,
                    "TOOLS_TEST_DISABLE": TOOLS_TEST_DISABLE,
                },
            ),
        )
    )
    results.append(
        test_one(
            "runtime-tests.sh (AOT)",
            lambda: truthy(RUN_AOT_TESTS),
            lambda: shell(
                (
                    [
                        "./tests/runtime-tests.sh",
                        "--run-aot-tests",
                        "--filter",
                        "aot.*",
                    ]
                    + [
                        "--allowlist_file",
                        f"{root()}/{AOT_ALLOWLIST_FILE}",
                    ]
                    if AOT_ALLOWLIST_FILE
                    else []
                ),
                as_root=True,
                cwd=Path(BUILD_DIR),
                env={
                    "CI": CI,
                    "RUNTIME_TEST_COLOR": "yes",
                },
            ),
        )
    )

    tests_finish(results)


def main():
    configure()
    build()
    if CC.startswith("afl-"):
        fuzz()
    else:
        test()


if __name__ == "__main__":
    main()
