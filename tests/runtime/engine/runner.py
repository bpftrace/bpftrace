#!/usr/bin/python3

import json
import subprocess
import signal
import sys
import os
import time
from distutils.version import LooseVersion
import re
from functools import lru_cache

import cmake_vars

BPFTRACE_BIN = os.environ["BPFTRACE_RUNTIME_TEST_EXECUTABLE"]
COLOR_SETTING = os.environ.get("RUNTIME_TEST_COLOR", "auto")
ATTACH_TIMEOUT = 10
DEFAULT_TIMEOUT = 5


OK_COLOR = '\033[92m'
WARN_COLOR = '\033[94m'
ERROR_COLOR = '\033[91m'
NO_COLOR = '\033[0m'

def colorify(s, color):
    if COLOR_SETTING == "yes":
        use_color = True
    elif COLOR_SETTING == "auto":
        use_color = sys.stdout.isatty()
    elif COLOR_SETTING == "no":
        use_color = False
    else:
        raise ValueError("Invalid setting for RUNTIME_TEST_COLOR")

    return f"{color}{s}{NO_COLOR}" if use_color else s

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
    SKIP_IN_SKIPLIST = 9

    @staticmethod
    def failed(status):
        return status == Runner.FAIL

    @staticmethod
    def timeouted(status):
        return status == Runner.TIMEOUT

    @staticmethod
    def skipped(status):
        return status in [
            Runner.SKIP_KERNEL_VERSION_MIN,
            Runner.SKIP_KERNEL_VERSION_MAX,
            Runner.SKIP_REQUIREMENT_UNSATISFIED,
            Runner.SKIP_ENVIRONMENT_DISABLED,
            Runner.SKIP_FEATURE_REQUIREMENT_UNSATISFIED,
            Runner.SKIP_AOT_NOT_SUPPORTED,
            Runner.SKIP_IN_SKIPLIST,
        ]

    @staticmethod
    def skip_reason(test, status):
        if status == Runner.SKIP_KERNEL_VERSION_MIN:
            return "min Kernel: %s" % test.kernel_min
        if status == Runner.SKIP_KERNEL_VERSION_MAX:
            return "max Kernel: %s" % test.kernel_max
        elif status == Runner.SKIP_REQUIREMENT_UNSATISFIED:
            return "unmet condition: '%s'" % ' && '.join(test.requirement)
        elif status == Runner.SKIP_FEATURE_REQUIREMENT_UNSATISFIED:
            neg_reqs = { "!{}".format(f) for f in test.neg_feature_requirement }
            return "missed feature: '%s'" % ','.join(
                (neg_reqs | test.feature_requirement))
        elif status == Runner.SKIP_ENVIRONMENT_DISABLED:
            return "disabled by environment variable"
        elif status == Runner.SKIP_AOT_NOT_SUPPORTED:
            return "aot does not yet support this"
        elif status == Runner.SKIP_IN_SKIPLIST:
            return "disabled by entry in skiplist file"
        else:
            raise ValueError("Invalid skip reason: %d" % status)

    @staticmethod
    def prepare_bpf_call(test, nsenter=[]):
        nsenter_prefix = (" ".join(nsenter) + " ") if len(nsenter) > 0 else ""

        if test.run:
            ret = re.sub("{{BPFTRACE}}", BPFTRACE_BIN, test.run)

            return nsenter_prefix + ret
        else:  # PROG
            use_json = "-q -f json" if test.expects[0].mode == "json" else ""
            escaped_prog = test.prog.replace("'", "'\\''")
            cmd = nsenter_prefix + "{} {} -e '{}'".format(BPFTRACE_BIN, use_json, escaped_prog)
            # We're only reusing PROG-directive tests for AOT tests
            if test.suite == 'aot':
                return cmd + " --aot /tmp/tmpprog.btaot && /tmp/tmpprog.btaot"
            else:
                return cmd

    @staticmethod
    def __handler(signum, frame):
        raise TimeoutError('TIMEOUT')

    @staticmethod
    @lru_cache(maxsize=1)
    def __get_bpffeature():
        p = subprocess.Popen(
            [BPFTRACE_BIN, "--info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            universal_newlines=True,
        )
        output = p.communicate()[0]
        bpffeature = {}
        bpffeature["loop"] = output.find("Loop support: yes") != -1
        bpffeature["probe_read_kernel"] = output.find("probe_read_kernel: yes") != -1
        bpffeature["btf"] = output.find("btf: yes") != -1
        bpffeature["kfunc"] = output.find("kfunc: yes") != -1
        bpffeature["dpath"] = output.find("dpath: yes") != -1
        bpffeature["uprobe_refcount"] = \
            output.find("uprobe refcount (depends on Build:bcc bpf_attach_uprobe refcount): yes") != -1
        bpffeature["signal"] = output.find("send_signal: yes") != -1
        bpffeature["iter"] = output.find("iter: yes") != -1
        bpffeature["libpath_resolv"] = output.find("bcc library path resolution: yes") != -1
        bpffeature["dwarf"] = output.find("liblldb (DWARF support): yes") != -1
        bpffeature["kprobe_multi"] = output.find("kprobe_multi: yes") != -1
        bpffeature["uprobe_multi"] = output.find("uprobe_multi: yes") != -1
        bpffeature["aot"] = cmake_vars.LIBBCC_BPF_CONTAINS_RUNTIME
        bpffeature["skboutput"] = output.find("skboutput: yes") != -1
        bpffeature["get_tai_ns"] = output.find("get_ktime_ns: yes") != -1
        bpffeature["get_func_ip"] = output.find("get_func_ip: yes") != -1
        bpffeature["jiffies64"] = output.find("jiffies64: yes") != -1
        return bpffeature


    @staticmethod
    def __wait_for_children(parent_pid, timeout, ps_format, condition):
        with open(os.devnull, 'w') as dn:
            waited=0
            while waited <= timeout:
                run_cmd = ["ps", "--ppid", str(parent_pid), "--no-headers", "-o", ps_format]
                children = subprocess.run(run_cmd,
                                          check=False,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
                if children.returncode == 0 and children.stdout:
                    lines = [line.decode('utf-8') for line in children.stdout.splitlines()]
                    if (condition(lines)):
                        return lines
                else:
                    print(f"__wait_for_children error: {children.stderr}. Return code: {children.returncode}")

                time.sleep(0.1)
                waited+=0.1
        return None


    @staticmethod
    def run_test(test):
        current_kernel = LooseVersion(os.uname()[2])
        if test.kernel_min and LooseVersion(test.kernel_min) > current_kernel:
            print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
            return Runner.SKIP_KERNEL_VERSION_MIN

        if test.kernel_max and LooseVersion(test.kernel_max) < current_kernel:
            print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
            return Runner.SKIP_KERNEL_VERSION_MAX

        if test.skip_if_env_has and os.environ.get(test.skip_if_env_has[0], '') == test.skip_if_env_has[1]:
            print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
            return Runner.SKIP_ENVIRONMENT_DISABLED

        signal.signal(signal.SIGALRM, Runner.__handler)

        p = None
        befores = []
        befores_output = []
        bpftrace = None
        after = None
        after_output = None
        cleanup = None
        # This is only populated if the NEW_PIDNS directive is set
        # and is used to enter the newly created pid namespace for all BEFOREs,
        # the primary RUN or PROG command, and the AFTER.
        nsenter = []
        bpf_call = "[unknown]"
        failed_expects = []

        def get_pid_ns_cmd(cmd):
            return nsenter + [os.path.abspath(x) for x in cmd.split()]

        def check_expect(expect, output):
            try:
                if expect.mode == "text":
                    # Raw text match on an entire line, ignoring leading/trailing whitespace
                    return re.search(f"^\\s*{re.escape(expect.expect)}\\s*$", output, re.M)
                elif expect.mode == "text_none":
                    return not re.search(f"^\\s*{re.escape(expect.expect)}\\s*$", output, re.M)
                elif expect.mode == "regex":
                    return re.search(expect.expect, output, re.M)
                elif expect.mode == "regex_none":
                    return not re.search(expect.expect, output, re.M)
                elif expect.mode == "file":
                    with open(expect.expect) as expect_file:
                        # remove leading and trailing empty lines
                        return output.strip() == expect_file.read().strip()
                else:
                    with open(expect.expect) as expect_file:
                        _, file_extension = os.path.splitext(expect.expect)
                        stripped_output = output.strip()
                        output_lines = stripped_output.splitlines()

                        # ndjson files are new line delimited blocks of json
                        # https://github.com/ndjson/ndjson-spec
                        if file_extension == ".ndjson":
                            stripped_file = expect_file.read().strip()
                            file_lines = stripped_file.splitlines()

                            if len(file_lines) != len(output_lines):
                                return False

                            for x in range(len(file_lines)):
                                if json.loads(output_lines[x]) != json.loads(file_lines[x]):
                                    return False

                            return True

                        if len(output_lines) != 1:
                            print(f"Expected a single line of json ouput. Got {len(output_lines)} lines")
                            return False
                        return json.loads(stripped_output) == json.load(expect_file)


            except Exception as err:
                print("ERROR in check_result: ", err)
                return False

        def check_result(output):
            all_passed = True
            for expect in test.expects:
                if not check_expect(expect, output):
                    all_passed = False
                    failed_expects.append(expect)
            return all_passed

        try:
            result = None
            timeout = False
            output = ""

            print(ok("[ RUN      ] ") + "%s.%s" % (test.suite, test.name))
            if test.requirement:
                for req in test.requirement:
                    with open(os.devnull, 'w') as dn:
                        if subprocess.call(
                            req,
                            shell=True,
                            stdout=dn,
                            stderr=dn,
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

            if test.new_pidns and not test.befores:
                raise ValueError("`NEW_PIDNS` requires at least one `BEFORE` directive as something needs to run in the new pid namespace")

            if test.befores:
                if test.new_pidns:
                    # Use the first BEFORE as the first process in the new pid namespace
                    unshare_out = subprocess.Popen(["unshare", "--fork", "--pid", "--mount-proc", "-r", "--kill-child"] + ["--"] + test.befores[0].split(),
                                                   start_new_session=True, universal_newlines=True,
                                                   stdout=subprocess.PIPE,
                                                   stderr=subprocess.STDOUT)

                    lines = Runner.__wait_for_children(unshare_out.pid, test.timeout, "pid", lambda lines : len(lines) > 0)

                    if not lines:
                        raise TimeoutError(f'Timed out waiting create a new PID namespace')

                    nsenter.extend(["nsenter", "-p", "-m", "-t", lines[0].strip()])

                    # This is the only one we need to add to befores as killing the
                    # unshare process will kill the whole process subtree with "--kill-child"
                    befores.append(unshare_out)
                    for before in test.befores[1:]:
                        child_name = os.path.basename(before.strip().split()[0])[:15]
                        before = subprocess.Popen(get_pid_ns_cmd(before),
                                                start_new_session=True,
                                                universal_newlines=True,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT)
                        # wait for the child of nsenter
                        if not Runner.__wait_for_children(before.pid, test.timeout, "comm", lambda lines : child_name in lines):
                            raise TimeoutError(f'Timed out waiting for BEFORE {before}')
                else:
                    for before in test.befores:
                        before = subprocess.Popen(before.split(),
                                                start_new_session=True,
                                                universal_newlines=True,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT)
                        befores.append(before)

                    child_names = [os.path.basename(x.strip().split()[-1]) for x in test.befores]
                    child_names = sorted((x[:15] for x in child_names))  # cut to comm length

                    def found_all_children(lines):
                        return sorted((line.strip() for line in lines if line != 'ps')) == child_names

                    if not Runner.__wait_for_children(os.getpid(), test.timeout, "comm", found_all_children):
                        raise TimeoutError(f'Timed out waiting for BEFORE(s) {test.befores}')

            bpf_call = Runner.prepare_bpf_call(test, nsenter)
            if test.befores and '{{BEFORE_PID}}' in bpf_call:
                if test.new_pidns:
                    # This can be fixed in the future if needed
                    raise ValueError(f"BEFORE_PID cannot be used with NEW_PIDNS")
                if len(test.befores) > 1:
                    raise ValueError(f"test has {len(test.befores)} BEFORE clauses but BEFORE_PID usage requires exactly one")

                child_name = test.befores[0].strip().split()[-1]
                child_name = os.path.basename(child_name)

                childpid = subprocess.Popen(["pidof", child_name], stdout=subprocess.PIPE, universal_newlines=True).communicate()[0].split()[0]
                bpf_call = re.sub("{{BEFORE_PID}}", str(childpid), bpf_call)
            env = {
                'test': test.name,
                '__BPFTRACE_NOTIFY_PROBES_ATTACHED': '1',
                '__BPFTRACE_NOTIFY_AOT_PORTABILITY_DISABLED': '1',
                'BPFTRACE_VERIFY_LLVM_IR': '1',
                'PATH': os.environ.get('PATH', ''),
            }
            env.update(test.env)
            p = subprocess.Popen(
                bpf_call,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                errors='backslashreplace',
                env=env,
                start_new_session=True,
                universal_newlines=True,
            )
            bpftrace = p

            attached = False
            signal.alarm(ATTACH_TIMEOUT)

            while p.poll() is None:
                nextline = p.stdout.readline()
                output += nextline
                if not attached and nextline == "__BPFTRACE_NOTIFY_PROBES_ATTACHED\n":
                    attached = True
                    if test.has_exact_expect:
                        output = ""  # ignore earlier ouput
                    signal.alarm(test.timeout or DEFAULT_TIMEOUT)
                    if test.after:
                        after_cmd = get_pid_ns_cmd(test.after) if test.new_pidns else test.after
                        after = subprocess.Popen(after_cmd, shell=True,
                                                 start_new_session=True,
                                                 universal_newlines=True,
                                                 stdout=subprocess.PIPE,
                                                 stderr=subprocess.STDOUT)

            signal.alarm(0)
            output += p.stdout.read()
            result = check_result(output)

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
            if p:
                if p.poll() is None:
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                output += p.stdout.read()
                result = check_result(output)

                if not result:
                    print(fail("[  TIMEOUT ] ") + "%s.%s" % (test.suite, test.name))
                    print('\tCommand: %s' % bpf_call)
                    print('\tTimeout: %s' % test.timeout)
                    print('\tCurrent output: %s' % output)
                    return Runner.TIMEOUT
        finally:
            if befores:
                for before in befores:
                    try:
                        befores_output.append(before.communicate(timeout=1)[0])
                    except subprocess.TimeoutExpired:
                        pass # if timed out getting output, there is effectively no output
                    if before.poll() is None:
                        os.killpg(os.getpgid(before.pid), signal.SIGKILL)

            if bpftrace and bpftrace.poll() is None:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)

            if after:
                try:
                    after_output = after.communicate(timeout=1)[0]
                except subprocess.TimeoutExpired:
                        pass # if timed out getting output, there is effectively no output
                if after.poll() is None:
                    os.killpg(os.getpgid(after.pid), signal.SIGKILL)

        if test.cleanup:
            try:
                cleanup = subprocess.run(test.cleanup, shell=True, stderr=subprocess.PIPE,
                                         stdout=subprocess.PIPE, universal_newlines=True)
                cleanup.check_returncode()
            except subprocess.CalledProcessError as e:
                print(fail("[  FAILED  ] ") + "%s.%s" % (test.suite, test.name))
                print('\tCLEANUP error: %s' % e.stderr)
                return Runner.FAIL

        def to_utf8(s):
            return s.encode("unicode_escape").decode("utf-8")

        def print_befores_and_after_output():
            if len(befores_output) > 0:
                for out in befores_output:
                    print(f"\tBefore cmd output: {to_utf8(out)}")
            if after_output is not None:
                print(f"\tAfter cmd output: {to_utf8(after_output)}")

        if '__BPFTRACE_NOTIFY_AOT_PORTABILITY_DISABLED' in to_utf8(output):
            print(warn("[   SKIP   ] ") + "%s.%s" % (test.suite, test.name))
            return Runner.SKIP_AOT_NOT_SUPPORTED

        if p and p.returncode != 0 and not test.will_fail and not timeout:
            print(fail("[  FAILED  ] ") + "%s.%s" % (test.suite, test.name))
            print('\tCommand: ' + bpf_call)
            print('\tUnclean exit code: ' + str(p.returncode))
            print('\tOutput: ' + to_utf8(output))
            print_befores_and_after_output()
            return Runner.FAIL

        if result:
            print(ok("[       OK ] ") + "%s.%s" % (test.suite, test.name))
            return Runner.PASS
        else:
            print(fail("[  FAILED  ] ") + "%s.%s" % (test.suite, test.name))
            print('\tCommand: ' + bpf_call)
            for failed_expect in failed_expects:
                if failed_expect.mode == "text":
                    print('\tExpected: ' + failed_expect.expect)
                    print('\tFound:\n' + to_utf8(output))
                elif failed_expect.mode == "text_none":
                    print('\tExpected no: ' + failed_expect.expect)
                    print('\tFound:\n' + to_utf8(output))
                elif failed_expect.mode == "regex":
                    print('\tExpected REGEX: ' + failed_expect.expect)
                    print('\tFound:\n' + to_utf8(output))
                elif failed_expect.mode == "regex_none":
                    print('\tExpected no REGEX: ' + failed_expect.expect)
                    print('\tFound:\n' + to_utf8(output))
                elif failed_expect.mode == "json":
                    _, file_extension = os.path.splitext(failed_expect.expect)
                    # ndjson files are new line delimited blocks of json
                    # https://github.com/ndjson/ndjson-spec
                    if file_extension == ".ndjson":
                        with open(failed_expect.expect) as expect_file:
                            stripped_file = expect_file.read().strip()
                            file_lines = stripped_file.splitlines()

                            print('\tExpected JSON:\n')
                            for x in file_lines:
                                try:
                                    print(json.dumps(json.loads(x), indent=2))
                                except json.decoder.JSONDecodeError as err:
                                    print("Could not parse JSON: " + str(err)  + '\n' + "Raw Line: " + x)

                        stripped_output = output.strip()
                        output_lines = stripped_output.splitlines()

                        print('\tFound:\n')
                        for x in output_lines:
                            try:
                                print(json.dumps(json.loads(x), indent=2))
                            except json.decoder.JSONDecodeError as err:
                                print("Could not parse JSON: " + str(err) + '\n' + "Raw Output: " + x)
                    else:
                        try:
                            expected = json.dumps(json.loads(open(failed_expect.expect).read()), indent=2)
                        except json.decoder.JSONDecodeError as err:
                            expected = "Could not parse JSON: " + str(err) + '\n' + "Raw File: " + expected
                        try:
                            found = json.dumps(json.loads(output), indent=2)
                        except json.decoder.JSONDecodeError as err:
                            found = "Could not parse JSON: " + str(err) + '\n' + "Raw Output: " + output
                        print('\tExpected JSON:\n' + expected)
                        print('\tFound:\n' + found)
                else:
                    print('\tExpected FILE:\n\t\t' + to_utf8(open(failed_expect.expect).read()))
                    print('\tFound:\n\t\t' + to_utf8(output))
            print_befores_and_after_output()
            return Runner.FAIL
