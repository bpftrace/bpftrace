#!/usr/bin/python3

from collections import namedtuple
import os
import platform


class RequiredFieldError(Exception):
    pass


class UnknownFieldError(Exception):
    pass


class InvalidFieldError(Exception):
    pass

class Expect:
  def __init__(self, expect, mode):
    self.expect = expect
    self.mode = mode

TestStruct = namedtuple(
    'TestStruct',
    [
        'name',
        'run',
        'prog',
        'expects',
        'has_exact_expect',
        'timeout',
        'befores',
        'after',
        'cleanup',
        'suite',
        'kernel_min',
        'kernel_max',
        'requirement',
        'env',
        'arch',
        'feature_requirement',
        'neg_feature_requirement',
        'will_fail',
        'new_pidns',
        'skip_if_env_has',
    ],
)


class TestParser(object):
    @staticmethod
    def read_all(run_aot_tests):
        aot_tests = []

        for root, subdirs, files in os.walk('./runtime'):
            for ignore_dir in ["engine", "scripts", "outputs"]:
                if ignore_dir in subdirs:
                    subdirs.remove(ignore_dir)
            for filename in files:
                if filename.startswith("."):
                    continue
                parser = TestParser.read(root + '/' + filename)
                if parser[1]:
                    if run_aot_tests:
                        for test in parser[1]:
                            # Only reuse tests that use PROG directive
                            if not test.prog:
                                continue

                            # _replace() creates a new instance w/ specified fields replaced
                            test = test._replace(
                                name='{}.{}'.format(test.suite, test.name),
                                suite='aot')
                            aot_tests.append(test)

                    yield parser

        if run_aot_tests:
            yield ('aot', aot_tests)

    @staticmethod
    def read(file_name):
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
                        if not test_struct.arch or (platform.machine().lower() in test_struct.arch):
                            tests.append(test_struct)
                        test_lines = []

        return (test_suite, tests)

    @staticmethod
    def __read_test_struct(test, test_suite):
        name = ''
        run = ''
        prog = ''
        expects = []
        has_exact_expect = False
        timeout = ''
        befores = []
        after = ''
        cleanup = ''
        kernel_min = ''
        kernel_max = ''
        requirement = []
        env = {}
        arch = []
        feature_requirement = set()
        neg_feature_requirement = set()
        will_fail = False
        new_pidns = False
        skip_if_env_has = None
        prev_item_name = ''

        for item in test:
            if item[:len(prev_item_name) + 1].isspace():
                # Whitespace at beginning of line means it continues from the
                # previous line

                # Remove the leading whitespace and the trailing newline
                line = item[len(prev_item_name) + 1:-1]
                if prev_item_name == 'PROG':
                    prog += '\n' + line
                    continue
                elif prev_item_name == 'EXPECT':
                    expects[-1].expect += '\n' + line
                    continue

            item_split = item.split()
            item_name = item_split[0]
            line = ' '.join(item_split[1:])
            prev_item_name = item_name

            if item_name == 'NAME':
                name = line
            elif item_name == 'RUN':
                run = line
            elif item_name == "PROG":
                prog = line
            elif item_name == 'EXPECT':
                expects.append(Expect(line, 'text'))
            elif item_name == 'EXPECT_NONE':
                expects.append(Expect(line, 'text_none'))
            elif item_name == 'EXPECT_REGEX':
                expects.append(Expect(line, 'regex'))
            elif item_name == 'EXPECT_REGEX_NONE':
                expects.append(Expect(line, 'regex_none'))
            elif item_name == 'EXPECT_FILE':
                has_exact_expect = True
                expects.append(Expect(line, 'file'))
            elif item_name == 'EXPECT_JSON':
                has_exact_expect = True
                expects.append(Expect(line, 'json'))
            elif item_name == 'TIMEOUT':
                timeout = int(line.strip(' '))
            elif item_name == 'BEFORE':
                befores.append(line)
            elif item_name == 'AFTER':
                after = line
            elif item_name == 'CLEANUP':
                cleanup = line
            elif item_name == 'MIN_KERNEL':
                kernel_min = line
            elif item_name == 'MAX_KERNEL':
                kernel_max = line
            elif item_name == 'REQUIRES':
                requirement.append(line)
            elif item_name == 'ENV':
                for e in line.split():
                    k, v = e.split('=')
                    env[k]=v
            elif item_name == 'ARCH':
                arch = [x.strip() for x in line.split("|")]
            elif item_name == 'REQUIRES_FEATURE':
                features = {
                    "loop",
                    "btf",
                    "kfunc",
                    "probe_read_kernel",
                    "dpath",
                    "uprobe_refcount",
                    "signal",
                    "iter",
                    "libpath_resolv",
                    "dwarf",
                    "aot",
                    "kprobe_multi",
                    "uprobe_multi",
                    "skboutput",
                    "get_tai_ns",
                    "get_func_ip",
                    "jiffies64",
                }

                for f in line.split(" "):
                    f = f.strip()
                    if f.startswith("!"):
                        neg_feature_requirement.add(f[1:])
                    else:
                        feature_requirement.add(f)

                unknown = (feature_requirement | neg_feature_requirement) - features
                if len(unknown) > 0:
                    raise UnknownFieldError('%s is invalid for REQUIRES_FEATURE. Suite: %s' % (','.join(unknown), test_suite))
            elif item_name == "WILL_FAIL":
                will_fail = True
            elif item_name == "NEW_PIDNS":
                new_pidns = True
            elif item_name == "SKIP_IF_ENV_HAS":
                parts = line.split("=")
                skip_if_env_has = (parts[0], parts[1])
            else:
                raise UnknownFieldError('Field %s is unknown. Suite: %s' % (item_name, test_suite))

        if name == '':
            raise RequiredFieldError('Test NAME is required. Suite: ' + test_suite)
        elif run == '' and prog == '':
            raise RequiredFieldError('Test RUN or PROG is required. Suite: ' + test_suite)
        elif run != '' and prog != '':
            raise InvalidFieldError('Test RUN and PROG both specified. Suit: ' + test_suite)
        elif len(expects) == 0:
            raise RequiredFieldError('At leat one test EXPECT (or variation) is required. Suite: ' + test_suite)
        elif len(expects) > 1 and has_exact_expect:
            raise InvalidFieldError('EXPECT_JSON or EXPECT_FILE can not be used with other EXPECTs. Suite: ' + test_suite)
        elif timeout == '':
            raise RequiredFieldError('Test TIMEOUT is required. Suite: ' + test_suite)

        return TestStruct(
            name,
            run,
            prog,
            expects,
            has_exact_expect,
            timeout,
            befores,
            after,
            cleanup,
            test_suite,
            kernel_min,
            kernel_max,
            requirement,
            env,
            arch,
            feature_requirement,
            neg_feature_requirement,
            will_fail,
            new_pidns,
            skip_if_env_has,
        )
