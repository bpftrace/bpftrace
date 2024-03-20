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
from typing import Callable, Dict, List, Optional, Union

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
RUN_MEMLEAK_TEST = os.environ.get("RUN_MEMLEAK_TEST", "0")
CC = os.environ.get("CC", "cc")
CXX = os.environ.get("CXX", "c++")
GTEST_COLOR = os.environ.get("GTEST_COLOR", "auto")
CI = os.environ.get("CI", "false")
RUNTIME_TEST_COLOR = os.environ.get("RUNTIME_TEST_COLOR", "auto")
TOOLS_TEST_OLDVERSION = os.environ.get("TOOLS_TEST_OLDVERSION", "")
TOOLS_TEST_DISABLE = os.environ.get("TOOLS_TEST_DISABLE", "")


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

    c.append("--command")
    if as_root:
        to_preserve = ",".join([n for n in env]) if env else []
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
            # Also preserve any caller specified env vars
            f"--preserve-env={to_preserve}",
        ]
    c += cmd

    if not env:
        env = {}

    # Nix needs to know the home dir
    if "HOME" in os.environ:
        env["HOME"] = os.environ["HOME"]

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
    # fmt: off
    c = [
        "cmake",
        "-B",
        BUILD_DIR,

        # Dynamic configs
        f"-DCMAKE_C_COMPILER={CC}",
        f"-DCMAKE_CXX_COMPILER={CXX}",
        f"-DCMAKE_BUILD_TYPE={CMAKE_BUILD_TYPE}",
        f"-DBUILD_ASAN={RUN_MEMLEAK_TEST}",

        # Static configs
        f"-DCMAKE_VERBOSE_MAKEFILE=1",
        f"-DBUILD_TESTING=1",
        f"-DENABLE_SKB_OUTPUT=1",
        f"-DALLOW_UNSAFE_PROBE=0",
    ]
    # fmt: on

    shell(c)


def build():
    """Build everything"""
    cpus = multiprocessing.cpu_count()
    shell(["make", "-C", BUILD_DIR, "-j", str(cpus)])


def test_one(name: str, cond: Callable[[], bool], fn: Callable[[], None]) -> TestResult:
    """Runs a single test suite and returns the result"""
    status = TestStatus.PASSED

    if cond():
        print(f"\n======= {name} ======")
        try:
            fn()
        except subprocess.CalledProcessError as e:
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
                ["./tests/bpftrace_test"],
                cwd=Path(BUILD_DIR),
                env={"GTEST_COLOR": GTEST_COLOR},
            ),
        )
    )
    results.append(
        test_one(
            "runtime-tests.sh",
            lambda: truthy(RUN_TESTS),
            lambda: shell(
                ["./tests/runtime-tests.sh"],
                as_root=True,
                cwd=Path(BUILD_DIR),
                env={
                    "CI": CI,
                    "RUNTIME_TEST_COLOR": RUNTIME_TEST_COLOR,
                },
            ),
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
            "memleak-tests.sh.sh",
            lambda: truthy(RUN_MEMLEAK_TEST),
            lambda: shell(
                ["./tests/memleak-tests.sh"], as_root=True, cwd=Path(BUILD_DIR)
            ),
        )
    )

    tests_finish(results)


def main():
    configure()
    build()
    test()


if __name__ == "__main__":
    main()
