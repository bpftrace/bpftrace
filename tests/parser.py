#!/usr/bin/python

from collections import namedtuple
import os

from utils import ERROR_COLOR, NO_COLOR

class RequiredFieldError(Exception):
    pass

TestStruct = namedtuple('TestStruct', 'name run expect timeout before after')


class TestParser(object):
    @staticmethod
    def read_all():
        try:
            for root, _, files in os.walk('./runtime'):
                for filename in files:
                    yield TestParser.read(root + '/' + filename)
        except RequiredFieldError as error:
            print(ERROR_COLOR + str(error) + NO_COLOR)

    @staticmethod
    def read(file_name):
        tests = []
        test_lines = []
        with open (file_name, 'r') as file:
            for line in file.readlines():
                if line != '\n':
                    test_lines.append(line)
                else:
                    tests.append(TestParser.__read_test_struct(test_lines, file_name))
                    test_lines = []
            tests.append(TestParser.__read_test_struct(test_lines, file_name))

        return (file_name.split('/')[-1], tests)

    @staticmethod
    def __read_test_struct(test, file_name):
        name = ''
        run = ''
        expect = ''
        timeout = ''
        before = ''
        after = ''

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

        if name == '':
            raise RequiredFieldError('Test NAME is required. File: ' + file_name)
        elif run == '':
            raise RequiredFieldError('Test RUN is required. File: ' + file_name)
        elif expect == '':
            raise RequiredFieldError('Test EXPECT is required. File: ' + file_name)
        elif timeout == '':
            raise RequiredFieldError('Test TIMEOUT is required. File: ' + file_name)

        return TestStruct(name, run, expect, timeout, before, after)
