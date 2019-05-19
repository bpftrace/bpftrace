#!/usr/bin/python3

from fnmatch import fnmatch
from collections import namedtuple
import os

from utils import ERROR_COLOR, NO_COLOR


class RequiredFieldError(Exception):
    pass


class UnknownFieldError(Exception):
    pass


TestStruct = namedtuple('TestStruct', 'name run expect timeout before after suite kernel requirement')


class TestParser(object):
    @staticmethod
    def read_all(test_filter):
        try:
            for root, subdirs, files in os.walk('./runtime'):
                if "scripts" in subdirs:
                    subdirs.remove("scripts")
                for filename in files:
                    if filename.startswith("."):
                        continue
                    parser = TestParser.read(root + '/' + filename, test_filter)
                    if parser[1]:
                        yield parser
        except RequiredFieldError as error:
            print(ERROR_COLOR + str(error) + NO_COLOR)

    @staticmethod
    def read(file_name, test_filter):
        tests = []
        test_lines = []
        test_suite = file_name.split('/')[-1]
        with open (file_name, 'r') as file:
            for line in file.readlines():
                if line != '\n':
                    test_lines.append(line)
                else:
                    test_struct = TestParser.__read_test_struct(test_lines, test_suite)
                    if fnmatch("%s.%s" % (test_suite, test_struct.name), test_filter):
                        tests.append(test_struct)
                    test_lines = []
            test_struct = TestParser.__read_test_struct(test_lines, test_suite)
            if fnmatch("%s.%s" % (test_suite, test_struct.name), test_filter):
                tests.append(test_struct)

        return (test_suite, tests)

    @staticmethod
    def __read_test_struct(test, test_suite):
        name = ''
        run = ''
        expect = ''
        timeout = ''
        before = ''
        after = ''
        kernel = ''
        requirement = ''

        for item in test:
            item_split = item.split()
            item_name = item_split[0]
            line = ' '.join(item_split[1:])

            if item_name == 'NAME':
                name = line
            elif item_name == 'RUN':
                run = line
            elif item_name == 'EXPECT':
                expect = line
            elif item_name == 'TIMEOUT':
                timeout = int(line.strip(' '))
            elif item_name == 'BEFORE':
                before = line
            elif item_name == 'AFTER':
                after = line
            elif item_name == 'MIN_KERNEL':
                kernel = line
            elif item_name == 'REQUIRES':
                requirement = line
            else:
                raise UnknownFieldError('Field %s is unknown. Suite: %s' % (item_name, test_suite))

        if name == '':
            raise RequiredFieldError('Test NAME is required. Suite: ' + test_suite)
        elif run == '':
            raise RequiredFieldError('Test RUN is required. Suite: ' + test_suite)
        elif expect == '':
            raise RequiredFieldError('Test EXPECT is required. Suite: ' + test_suite)
        elif timeout == '':
            raise RequiredFieldError('Test TIMEOUT is required. Suite: ' + test_suite)

        return TestStruct(name, run, expect, timeout, before, after, test_suite, kernel, requirement)
