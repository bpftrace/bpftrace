#!/usr/bin/python3

import subprocess
import signal
from os import environ, uname, devnull
from distutils.version import LooseVersion
import re

BPF_PATH = environ["BPFTRACE_RUNTIME_TEST_EXECUTABLE"]
ATTACH_TIMEOUT = 5
DEFAULT_TIMEOUT = 5


OK_COLOR = '\033[92m'
WARN_COLOR = '\033[94m'
ERROR_COLOR = '\033[91m'
NO_COLOR = '\033[0m'

# TODO(mmarchini) only add colors if terminal supports it
def colorify(s, color):
    return "%s%s%s" % (color, s, NO_COLOR)

def ok(s):
    return colorify(s, OK_COLOR)

def warn(s):
    return colorify(s, WARN_COLOR)

def fail(s):
    return colorify(s, ERROR_COLOR)

class TimeoutError(Exception):
    pass

class Utils(object):
    PASS = 0
    FAIL = 1
    SKIP_KERNEL_VERSION = 2
    TIMEOUT = 3
    SKIP_REQUIREMENT_UNSATISFIED = 4

    @staticmethod
    def failed(status):
        return status in [Utils.FAIL, Utils.TIMEOUT]

    @staticmethod
    def skipped(status):
        return status in [Utils.SKIP_KERNEL_VERSION, Utils.SKIP_REQUIREMENT_UNSATISFIED]

    @staticmethod
    def skip_reason(test, status):
        if status == Utils.SKIP_KERNEL_VERSION:
            return "min Kernel: %s" % test.kernel
        elif status == Utils.SKIP_REQUIREMENT_UNSATISFIED:
            return "unmet condition: '%s'" % test.requirement
        else:
            raise ValueError("Invalid skip reason: %d" % status)

    @staticmethod
    def prepare_bpf_call(test):
        return BPF_PATH + test.run

    @staticmethod
    def __handler(signum, frame):
        raise TimeoutError('TIMEOUT')

    @staticmethod
    def run_test(test):
        current_kernel = LooseVersion(uname()[2])
        if test.kernel and LooseVersion(test.kernel) > current_kernel:
            print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
            return Utils.SKIP_KERNEL_VERSION

        signal.signal(signal.SIGALRM, Utils.__handler)

        try:
            before = None
            after = None

            print(ok("[ RUN      ] ") + "%s.%s" % (test.suite, test.name))
            if test.requirement:
                with open(devnull, 'w') as dn:
                    if subprocess.call(test.requirement, shell=True, stdout=dn, stderr=dn) != 0:
                        print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
                        return Utils.SKIP_REQUIREMENT_UNSATISFIED

            if test.before:
                before = subprocess.Popen(test.before, shell=True)

            bpf_call = Utils.prepare_bpf_call(test)
            env = {'test': test.name}
            env.update(test.env)
            p = subprocess.Popen(
                bpf_call,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                bufsize=1
            )

            signal.alarm(ATTACH_TIMEOUT)

            output = ""

            while p.poll() is None:
                nextline = p.stdout.readline()
                output += nextline.decode()
                if nextline == "Running...\n":
                    signal.alarm(test.timeout or DEFAULT_TIMEOUT)
                    if not after and test.after:
                        after = subprocess.Popen(test.after, shell=True)
                    break

            output += p.communicate()[0].decode()

            signal.alarm(0)
            result = re.search(test.expect, output)

        except (TimeoutError):
            # Give it a last chance, the test might have worked but the
            # bpftrace process might still be alive
            if p.poll() is None:
                p.kill()
            output += p.communicate()[0].decode()
            result = re.search(test.expect, output)
            if not result:
                print(fail("[  TIMEOUT ] ") + "%s.%s" % (test.suite, test.name))
                print('\tCommand: %s' % bpf_call)
                print('\tTimeout: %s' % test.timeout)
                print('\tCurrent output: %s' % output)
                return Utils.TIMEOUT
        finally:
            if before and before.poll() is None:
                before.kill()

            if after and after.poll() is None:
                after.kill()

        if result:
            print(ok("[       OK ] ") + "%s.%s" % (test.suite, test.name))
            return Utils.PASS
        else:
            print(fail("[  FAILED  ] ") + "%s.%s" % (test.suite, test.name))
            print('\tCommand: ' + bpf_call)
            print('\tExpected: ' + test.expect)
            print('\tFound: ' + output)
            return Utils.FAIL
