#!/usr/bin/python3

import subprocess
import signal
import sys
import os
import time
from os import environ, uname, devnull
from distutils.version import LooseVersion
import re
from functools import lru_cache

import cmake_vars

BPF_PATH = environ["BPFTRACE_RUNTIME_TEST_EXECUTABLE"]
ENV_PATH = environ["PATH"]
ATTACH_TIMEOUT = 5
DEFAULT_TIMEOUT = 5


OK_COLOR = '\033[92m'
WARN_COLOR = '\033[94m'
ERROR_COLOR = '\033[91m'
NO_COLOR = '\033[0m'

# TODO(mmarchini) only add colors if terminal supports it
def colorify(s, color):
    return "%s%s%s" % (color, s, NO_COLOR) if sys.stdout.isatty() else s

def ok(s):
    return colorify(s, OK_COLOR)

def warn(s):
    return colorify(s, WARN_COLOR)

def fail(s):
    return colorify(s, ERROR_COLOR)

class TimeoutError(Exception):
    pass

class Runner(object):
    PASS = 0
    FAIL = 1
    SKIP_KERNEL_VERSION_MIN = 2
    TIMEOUT = 3
    SKIP_REQUIREMENT_UNSATISFIED = 4
    SKIP_ENVIRONMENT_DISABLED = 5
    SKIP_FEATURE_REQUIREMENT_UNSATISFIED = 6
    SKIP_AOT_NOT_SUPPORTED = 7
    SKIP_KERNEL_VERSION_MAX = 8

    @staticmethod
    def failed(status):
        return status in [Runner.FAIL, Runner.TIMEOUT]

    @staticmethod
    def skipped(status):
        return status in [
            Runner.SKIP_KERNEL_VERSION_MIN,
            Runner.SKIP_KERNEL_VERSION_MAX,
            Runner.SKIP_REQUIREMENT_UNSATISFIED,
            Runner.SKIP_ENVIRONMENT_DISABLED,
            Runner.SKIP_FEATURE_REQUIREMENT_UNSATISFIED,
            Runner.SKIP_AOT_NOT_SUPPORTED,
        ]

    @staticmethod
    def skip_reason(test, status):
        if status == Runner.SKIP_KERNEL_VERSION_MIN:
            return "min Kernel: %s" % test.kernel_min
        if status == Runner.SKIP_KERNEL_VERSION_MAX:
            return "max Kernel: %s" % test.kernel_max
        elif status == Runner.SKIP_REQUIREMENT_UNSATISFIED:
            return "unmet condition: '%s'" % test.requirement
        elif status == Runner.SKIP_FEATURE_REQUIREMENT_UNSATISFIED:
            neg_reqs = { "!{}".format(f) for f in test.neg_feature_requirement }
            return "missed feature: '%s'" % ','.join(
                (neg_reqs | test.feature_requirement))
        elif status == Runner.SKIP_ENVIRONMENT_DISABLED:
            return "disabled by environment variable"
        elif status == Runner.SKIP_AOT_NOT_SUPPORTED:
            return "aot does not yet support this"
        else:
            raise ValueError("Invalid skip reason: %d" % status)

    @staticmethod
    def prepare_bpf_call(test):
        bpftrace_path = "{}/bpftrace".format(BPF_PATH)
        bpftrace_aotrt_path = "{}/aot/bpftrace-aotrt".format(BPF_PATH)

        if test.run:
            ret = re.sub("{{BPFTRACE}}", bpftrace_path, test.run)
            ret = re.sub("{{BPFTRACE_AOTRT}}", bpftrace_aotrt_path, ret)

            return ret
        else:  # PROG
            # We're only reusing PROG-directive tests for AOT tests
            if test.suite == 'aot':
                return "{} -e '{}' --aot /tmp/tmpprog.btaot && {} /tmp/tmpprog.btaot".format(
                    bpftrace_path, test.prog, bpftrace_aotrt_path)
            else:
                return "{} -e '{}'".format(bpftrace_path, test.prog)

    @staticmethod
    def __handler(signum, frame):
        raise TimeoutError('TIMEOUT')

    @staticmethod
    @lru_cache(maxsize=1)
    def __get_bpffeature():
        cmd = "bpftrace --info"
        p = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={'PATH': "{}:{}".format(BPF_PATH, ENV_PATH)},
            preexec_fn=os.setsid,
            universal_newlines=True,
            bufsize=1
        )
        output = p.communicate()[0]
        bpffeature = {}
        bpffeature["loop"] = output.find("Loop support: yes") != -1
        bpffeature["probe_read_kernel"] = output.find("probe_read_kernel: yes") != -1
        bpffeature["btf"] = output.find("btf (depends on Build:libbpf): yes") != -1
        bpffeature["kfunc"] = output.find("kfunc: yes") != -1
        bpffeature["dpath"] = output.find("dpath: yes") != -1
        bpffeature["uprobe_refcount"] = \
            output.find("uprobe refcount (depends on Build:bcc bpf_attach_uprobe refcount): yes") != -1
        bpffeature["bcc_usdt_addsem"] = output.find("bcc_usdt_addsem: yes") != -1
        bpffeature["signal"] = output.find("send_signal: yes") != -1
        bpffeature["iter:task"] = output.find("iter:task: yes") != -1
        bpffeature["iter:task_file"] = output.find("iter:task_file: yes") != -1
        bpffeature["libpath_resolv"] = output.find("bcc library path resolution: yes") != -1
        bpffeature["dwarf"] = output.find("libdw (DWARF support): yes") != -1
        bpffeature["kprobe_multi"] = output.find("kprobe_multi: yes") != -1
        bpffeature["aot"] = cmake_vars.LIBBCC_BPF_CONTAINS_RUNTIME
        return bpffeature

    @staticmethod
    def run_test(test):
        current_kernel = LooseVersion(uname()[2])
        if test.kernel_min and LooseVersion(test.kernel_min) > current_kernel:
            print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
            return Runner.SKIP_KERNEL_VERSION_MIN

        if test.kernel_max and LooseVersion(test.kernel_max) < current_kernel:
            print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
            return Runner.SKIP_KERNEL_VERSION_MAX

        full_test_name = test.suite + "." + test.name
        if full_test_name in os.getenv("RUNTIME_TEST_DISABLE", "").split(","):
            print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
            return Runner.SKIP_ENVIRONMENT_DISABLED

        signal.signal(signal.SIGALRM, Runner.__handler)

        try:
            before = None
            bpftrace = None
            after = None
            timeout = False

            print(ok("[ RUN      ] ") + "%s.%s" % (test.suite, test.name))
            if test.requirement:
                with open(devnull, 'w') as dn:
                    if subprocess.call(
                        test.requirement,
                        shell=True,
                        stdout=dn,
                        stderr=dn,
                        env={'PATH': "{}:{}".format(BPF_PATH, ENV_PATH)},
                    ) != 0:
                        print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
                        return Runner.SKIP_REQUIREMENT_UNSATISFIED

            if test.feature_requirement or test.neg_feature_requirement:
                bpffeature = Runner.__get_bpffeature()

                for feature in test.feature_requirement:
                    if feature not in bpffeature:
                        raise ValueError("Invalid feature requirement: %s" % feature)
                    elif not bpffeature[feature]:
                        print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
                        return Runner.SKIP_FEATURE_REQUIREMENT_UNSATISFIED

                for feature in test.neg_feature_requirement:
                    if feature not in bpffeature:
                        raise ValueError("Invalid feature requirement: %s" % feature)
                    elif bpffeature[feature]:
                        print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
                        return Runner.SKIP_FEATURE_REQUIREMENT_UNSATISFIED

            if test.before:
                before = subprocess.Popen(test.before, shell=True, preexec_fn=os.setsid)
                waited=0
                with open(devnull, 'w') as dn:
                    # This might not work for complicated cases, such as if
                    # a test program needs to accept arguments. It covers the
                    # current simple calls with no arguments
                    child_name = os.path.basename(test.before.split()[-1])
                    while subprocess.call(["pidof", "-s", child_name], stdout=dn, stderr=dn) != 0:
                        time.sleep(0.1)
                        waited+=0.1
                        if waited > test.timeout:
                            raise TimeoutError('Timed out waiting for BEFORE %s ', test.before)

            bpf_call = Runner.prepare_bpf_call(test)
            if test.before:
                childpid = subprocess.Popen(["pidof", "-s", child_name], stdout=subprocess.PIPE, universal_newlines=True).communicate()[0].strip()
                bpf_call = re.sub("{{BEFORE_PID}}", str(childpid), bpf_call)
            env = {
                'test': test.name,
                '__BPFTRACE_NOTIFY_PROBES_ATTACHED': '1',
                '__BPFTRACE_NOTIFY_AOT_PORTABILITY_DISABLED': '1',
            }
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
            bpftrace = p

            signal.alarm(ATTACH_TIMEOUT)

            output = ""

            while p.poll() is None:
                nextline = p.stdout.readline()
                output += nextline
                if nextline == "__BPFTRACE_NOTIFY_PROBES_ATTACHED\n":
                    signal.alarm(test.timeout or DEFAULT_TIMEOUT)
                    if not after and test.after:
                        after = subprocess.Popen(test.after, shell=True, preexec_fn=os.setsid)
                    break

            output += p.communicate()[0]

            signal.alarm(0)
            result = re.search(test.expect, output, re.M)

        except (TimeoutError):
            # If bpftrace timed out (probably b/c the test case didn't explicitly
            # terminate bpftrace), then we mark the test case as timed out so that
            # we don't check the return code. The return code will probably not be
            # clean b/c we ran the subprocess in shellout mode and the shell won't
            # return a clean exit.
            timeout = True

            # Give it a last chance, the test might have worked but the
            # bpftrace process might still be alive
            #
            # Send a SIGTERM here so bpftrace exits cleanly. We'll send an SIGKILL
            # if SIGTERM didn't do the trick later
            if p.poll() is None:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            output += p.communicate()[0]
            result = re.search(test.expect, output)
            if not result:
                print(fail("[  TIMEOUT ] ") + "%s.%s" % (test.suite, test.name))
                print('\tCommand: %s' % bpf_call)
                print('\tTimeout: %s' % test.timeout)
                print('\tCurrent output: %s' % output)
                return Runner.TIMEOUT
        finally:
            if before and before.poll() is None:
                os.killpg(os.getpgid(before.pid), signal.SIGKILL)

            if bpftrace and bpftrace.poll() is None:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)

            if after and after.poll() is None:
                os.killpg(os.getpgid(after.pid), signal.SIGKILL)

        if p.returncode != 0 and not test.will_fail and not timeout:
            print(fail("[  FAILED  ] ") + "%s.%s" % (test.suite, test.name))
            print('\tCommand: ' + bpf_call)
            print('\tUnclean exit code: ' + str(p.returncode))
            print('\tOutput: ' + output.encode("unicode_escape").decode("utf-8"))
            return Runner.FAIL

        if result:
            print(ok("[       OK ] ") + "%s.%s" % (test.suite, test.name))
            return Runner.PASS
        elif '__BPFTRACE_NOTIFY_AOT_PORTABILITY_DISABLED' in output:
            print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
            return Runner.SKIP_AOT_NOT_SUPPORTED
        else:
            print(fail("[  FAILED  ] ") + "%s.%s" % (test.suite, test.name))
            print('\tCommand: ' + bpf_call)
            print('\tExpected: ' + test.expect)
            print('\tFound: ' + output.encode("unicode_escape").decode("utf-8"))
            return Runner.FAIL
