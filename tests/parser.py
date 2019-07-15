#!/usr/bin/python3

from fnmatch import fnmatch
from collections import namedtuple
import os

from utils import ERROR_COLOR, NO_COLOR


class RequiredFieldError(Exception):
    pass


class UnknownFieldError(Exception):
    pass


TestStruct = namedtuple('TestStruct', 'name run expect timeout before after suite kernel requirement env')


class TestParser(object):
    @staticmethod
    def read_all(test_filter):
        try:
            for root, subdirs, files in os.walk('./runtime'):
                for ignore_dir in ["scripts", "outputs"]:
                    if ignore_dir in subdirs:
                        subdirs.remove(ignore_dir)
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
            lines = file.readlines()
            line_num = 0
            for line in lines:
                line_num += 1
                if line.startswith("#"):
                    continue
                if line != '\n':
                    test_lines.append(line)
                if line == '\n' or line_num == len(lines):
                    if test_lines:
                        test_struct = TestParser.__read_test_struct(test_lines, test_suite)
                        if fnmatch("%s.%s" % (test_suite, test_struct.name), test_filter):
                            tests.append(test_struct)
                        test_lines = []

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
        env = {}

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
            elif item_name == 'ENV':
                for e in line.split():
                    k, v = e.split('=')
                    env[k]=v
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

        return TestStruct(name, run, expect, timeout, before, after, test_suite, kernel, requirement, env)
