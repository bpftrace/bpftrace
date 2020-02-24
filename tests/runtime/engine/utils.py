#!/usr/bin/python3

import subprocess
import signal
import os
import time
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
    SKIP_ENVIRONMENT_DISABLED = 5

    @staticmethod
    def failed(status):
        return status in [Utils.FAIL, Utils.TIMEOUT]

    @staticmethod
    def skipped(status):
        return status in [
            Utils.SKIP_KERNEL_VERSION,
            Utils.SKIP_REQUIREMENT_UNSATISFIED,
            Utils.SKIP_ENVIRONMENT_DISABLED,
        ]

    @staticmethod
    def skip_reason(test, status):
        if status == Utils.SKIP_KERNEL_VERSION:
            return "min Kernel: %s" % test.kernel
        elif status == Utils.SKIP_REQUIREMENT_UNSATISFIED:
            return "unmet condition: '%s'" % test.requirement
        elif status == Utils.SKIP_ENVIRONMENT_DISABLED:
            return "disabled by environment variable"
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

        full_test_name = test.suite + "." + test.name
        if full_test_name in os.getenv("RUNTIME_TEST_DISABLE", "").split(","):
            print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
            return Utils.SKIP_ENVIRONMENT_DISABLED

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
                before = subprocess.Popen(test.before, shell=True, preexec_fn=os.setsid)
                waited=0
                with open(devnull, 'w') as dn:
                    # This might not work for complicated cases, such as if
                    # a test program needs to accept arguments. It covers the
                    # current simple calls with no arguments
                    child_name = os.path.basename(test.before.split()[-1])
                    while subprocess.call(["pidof", child_name], stdout=dn, stderr=dn) != 0:
                        time.sleep(0.1)
                        waited+=0.1
                        if waited > test.timeout:
                            raise TimeoutError('Timed out waiting for BEFORE %s ', test.before)

            bpf_call = Utils.prepare_bpf_call(test)
            env = {'test': test.name}
            env.update(test.env)
            p = subprocess.Popen(
                bpf_call,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                preexec_fn=os.setsid,
                universal_newlines=True,
                bufsize=1
            )

            signal.alarm(ATTACH_TIMEOUT)

            output = ""

            while p.poll() is None:
                nextline = p.stdout.readline()
                output += nextline
                if nextline == "Running...\n":
                    signal.alarm(test.timeout or DEFAULT_TIMEOUT)
                    if not after and test.after:
                        after = subprocess.Popen(test.after, shell=True, preexec_fn=os.setsid)
                    break

            output += p.communicate()[0]

            signal.alarm(0)
            result = re.search(test.expect, output, re.M)

        except (TimeoutError):
            # Give it a last chance, the test might have worked but the
            # bpftrace process might still be alive
            if p.poll() is None:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            output += p.communicate()[0]
            result = re.search(test.expect, output)
            if not result:
                print(fail("[  TIMEOUT ] ") + "%s.%s" % (test.suite, test.name))
                print('\tCommand: %s' % bpf_call)
                print('\tTimeout: %s' % test.timeout)
                print('\tCurrent output: %s' % output)
                return Utils.TIMEOUT
        finally:
            if before and before.poll() is None:
                os.killpg(os.getpgid(before.pid), signal.SIGKILL)

            if after and after.poll() is None:
                os.killpg(os.getpgid(after.pid), signal.SIGKILL)

        if result:
            print(ok("[       OK ] ") + "%s.%s" % (test.suite, test.name))
            return Utils.PASS
        else:
            print(fail("[  FAILED  ] ") + "%s.%s" % (test.suite, test.name))
            print('\tCommand: ' + bpf_call)
            print('\tExpected: ' + test.expect)
            print('\tFound: ' + output)
            return Utils.FAIL
