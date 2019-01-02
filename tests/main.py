#!/usr/bin/python

import os
from os import environ
import time
from datetime import timedelta

from utils import Utils
from parser import TestParser


def main():
    test_suite = TestParser.read_all()

    start_time = time.time()

    total_tests = 0
    total_fail = 0

    for fname, tests in test_suite:
        print('Test file: ' + fname + '\n')
        for test in tests:
            success = Utils.run_test(test)
            total_tests += 1
            if not success:
                total_fail += 1
        print('--------------------------------\n')

    elapsed = time.time() - start_time
    print(str(total_tests) + ' tests [fail ' + str(total_fail) + ']')
    print('Done in ' + str(timedelta(seconds=elapsed)) )

    if total_fail > 0:
        exit(1)


if __name__ == "__main__":
    main()
