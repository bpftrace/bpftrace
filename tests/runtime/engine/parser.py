#!/usr/bin/python3

from fnmatch import fnmatch
from collections import namedtuple
import os
import platform


class RequiredFieldError(Exception):
    pass


class UnknownFieldError(Exception):
    pass


TestStruct = namedtuple('TestStruct', 'name run expect timeout before after suite kernel requirement env arch, feature_requirement neg_feature_requirement')


class TestParser(object):
    @staticmethod
    def read_all(test_filter):
        for root, subdirs, files in os.walk('./runtime'):
            for ignore_dir in ["engine", "scripts", "outputs"]:
                if ignore_dir in subdirs:
                    subdirs.remove(ignore_dir)
            for filename in files:
                if filename.startswith("."):
                    continue
                parser = TestParser.read(root + '/' + filename, test_filter)
                if parser[1]:
                    yield parser

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
                        if fnmatch("%s.%s" % (test_suite, test_struct.name), test_filter) and \
                           (not test_struct.arch or (platform.machine().lower() in test_struct.arch)):
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
        arch = []
        feature_requirement = set()
        neg_feature_requirement = set()

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
            elif item_name == 'ARCH':
                arch = [x.strip() for x in line.split("|")]
            elif item_name == 'REQUIRES_FEATURE':
                features = {"loop", "btf", "probe_read_kernel", "dpath", "uprobe_refcount", "signal",  "iter:task", "iter:task_file"}

                for f in line.split(" "):
                    f = f.strip()
                    if f.startswith("!"):
                        neg_feature_requirement.add(f[1:])
                    else:
                        feature_requirement.add(f)

                unknown = (feature_requirement | neg_feature_requirement) - features
                if len(unknown) > 0:
                    raise UnknownFieldError('%s is invalid for REQUIRES_FEATURE. Suite: %s' % (','.join(unknown), test_suite))
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

        return TestStruct(
            name,
            run,
            expect,
            timeout,
            before,
            after,
            test_suite,
            kernel,
            requirement,
            env,
            arch,
            feature_requirement,
            neg_feature_requirement)
