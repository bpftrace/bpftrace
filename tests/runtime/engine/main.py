#!/usr/bin/env python3

import argparse
from datetime import timedelta
import math
import os
import re
import time

from parser import TestParser, UnknownFieldError, RequiredFieldError
from runner import Runner, ok, fail, warn

TEST_FILTER = os.getenv("TEST_FILTER")

def main(test_filter, skiplist_file, run_aot_tests):
    if not test_filter:
        test_filter = ".*"

    skiplist = set()
    if skiplist_file:
        with open(skiplist_file, 'r') as f:
            for line in f:
                skiplist.add(line.strip())

    try:
        test_suite = sorted(TestParser.read_all(run_aot_tests))
        test_suite = [ (n, sorted(t)) for n, t in test_suite ]
    except (UnknownFieldError, RequiredFieldError) as error:
        print(fail(str(error)))
        exit(1)

    # Apply filter
    filtered_suites = []
    for fname, tests in test_suite:
        filtered_tests = [t for t in tests if re.search(test_filter, "{}.{}".format(fname, t.name))]
        if len(filtered_tests) != 0:
            filtered_suites.append((fname, filtered_tests))
    test_suite = filtered_suites

    total_tests = 0
    for fname, suite_tests in test_suite:
        total_tests += len(suite_tests)

    failed_tests = []
    timeouted_tests = []


    print(ok("[==========]") + " Running %d tests from %d test cases.\n" % (total_tests, len(test_suite)))

    start_time = time.time()
    skipped_tests = []
    for fname, tests in test_suite:
        print(ok("[----------]") + " %d tests from %s" % (len(tests), fname))
        for test in tests:
            if f"{fname}.{test.name}" in skiplist:
                skipped_tests.append((fname, test, Runner.SKIP_IN_SKIPLIST))
                continue
            status = Runner.run_test(test)
            if Runner.skipped(status):
                skipped_tests.append((fname, test, status))
            if Runner.failed(status):
                failed_tests.append("%s.%s" % (fname, test.name))
            if Runner.timeouted(status):
                timeouted_tests.append("%s.%s" % (fname, test.name))
        # TODO(mmarchini) elapsed time per test suite and per test (like gtest)
        print(ok("[----------]") + " %d tests from %s\n" % (len(tests), fname))
    elapsed = time.time() - start_time
    total_tests -= len(skipped_tests)

    print(ok("[==========]") + " %d tests from %d test cases ran. (%s ms total)" % (total_tests, len(test_suite), math.ceil(elapsed * 1000)))
    print(ok("[  PASSED  ]") + " %d tests." % (total_tests - len(failed_tests)))

    if skipped_tests:
        print(warn("[   SKIP   ]") + " %d tests, listed below:" % len(skipped_tests))
        for test_suite, test, status in skipped_tests:
            print(warn("[   SKIP   ]") + " %s.%s (%s)" % (test_suite, test.name, Runner.skip_reason(test, status)))

    if failed_tests or timeouted_tests:
        print(fail("[  FAILED  ]") + " %d tests, listed below:" % (len(failed_tests) + len(timeouted_tests)))
        for failed_test in failed_tests:
            print(fail("[  FAILED  ]") + " %s" % failed_test)
        for timeouted_test in timeouted_tests:
            print(fail("[  TIMEOUT ]") + " %s" % timeouted_test)

    if failed_tests:
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Runtime tests for bpftrace.')
    parser.add_argument('--filter', type=str, dest='test_filter',
                        help='Run only specified runtime test. Format should be "<test feature/test group>.<testcase name>"')
    parser.add_argument('--skiplist_file', type=str,
                        help='Path to file containing tests to skip. Format is one test per line. Subtracts tests from --filter.')
    parser.add_argument('--run-aot-tests', action='store_true',
                        help='Run ahead-of-time compilation tests. Note this would roughly double test time.')

    args = parser.parse_args()

    main(args.test_filter or TEST_FILTER, args.skiplist_file, args.run_aot_tests)
