#!/usr/bin/python3

import time
from datetime import timedelta
import argparse

from parser import TestParser, UnknownFieldError, RequiredFieldError
from runner import Runner, ok, fail, warn


def main(test_filter, run_aot_tests):
    if not test_filter:
        test_filter = "*"

    try:
        test_suite = sorted(TestParser.read_all(test_filter, run_aot_tests))
        test_suite = [ (n, sorted(t)) for n, t in test_suite ]
    except (UnknownFieldError, RequiredFieldError) as error:
        print(fail(str(error)))
        exit(1)

    total_tests = 0
    for fname, suite_tests in test_suite:
        total_tests += len(suite_tests)

    failed_tests = []


    print(ok("[==========]") + " Running %d tests from %d test cases.\n" % (total_tests, len(test_suite)))

    start_time = time.time()
    skipped_tests = []
    for fname, tests in test_suite:
        print(ok("[----------]") + " %d tests from %s" % (len(tests), fname))
        for test in tests:
            status = Runner.run_test(test)
            if Runner.skipped(status):
                skipped_tests.append((fname, test, status))
            if Runner.failed(status):
                failed_tests.append("%s.%s" % (fname, test.name))
        # TODO(mmarchini) elapsed time per test suite and per test (like gtest)
        print(ok("[----------]") + " %d tests from %s\n" % (len(tests), fname))
    elapsed = time.time() - start_time
    total_tests -= len(skipped_tests)

    # TODO(mmarchini) pretty print time
    print(ok("[==========]") + " %d tests from %d test cases ran. (%s total)" % (total_tests, len(test_suite), elapsed))
    print(ok("[  PASSED  ]") + " %d tests." % (total_tests - len(failed_tests)))

    if skipped_tests:
        print(warn("[   SKIP   ]") + " %d tests, listed below:" % len(skipped_tests))
        for test_suite, test, status in skipped_tests:
            print(warn("[   SKIP   ]") + " %s.%s (%s)" % (test_suite, test.name, Runner.skip_reason(test, status)))

    if failed_tests:
        print(fail("[  FAILED  ]") + " %d tests, listed below:" % len(failed_tests))
        for failed_test in failed_tests:
            print(fail("[  FAILED  ]") + " %s" % failed_test)

    if failed_tests:
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Runtime tests for bpftrace.')
    parser.add_argument('--filter', dest='tests_filter',
                        help='filter runtime tests')
    parser.add_argument('--run-aot-tests', action='store_true',
                        help='Run ahead-of-time compliation tests. Note this would roughly double test time.')

    args = parser.parse_args()

    main(args.tests_filter, args.run_aot_tests)
