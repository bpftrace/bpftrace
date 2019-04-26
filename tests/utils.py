import subprocess
import signal
from os import environ, uname
from distutils.version import LooseVersion
import re

BPF_PATH = environ["BPFTRACE_RUNTIME_TEST_EXECUTABLE"]


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
    SKIP = 2
    TIMEOUT = 3

    @staticmethod
    def failed(status):
        return status in [Utils.FAIL, Utils.TIMEOUT]

    @staticmethod
    def skipped(status):
        return status == Utils.SKIP

    @staticmethod
    def prepare_bpf_call(test):
        return ('test={}; '.format(test.name) +
            test.before + ' {}'.format(BPF_PATH) + test.run + ' ' + test.after)

    @staticmethod
    def __handler(signum, frame):
        raise TimeoutError('TIMEOUT')

    @staticmethod
    def run_test(test):
        current_kernel = LooseVersion(uname()[2])
        if test.kernel and LooseVersion(test.kernel) > current_kernel:
            print(warn("[   SKIP   ] ") + "%s.%s" % (test.file_name, test.name))
            return Utils.SKIP

        signal.signal(signal.SIGALRM, Utils.__handler)
        signal.alarm(test.timeout)

        try:
            print(ok("[ RUN      ] ") + "%s.%s" % (test.file_name, test.name))
            bpf_call = Utils.prepare_bpf_call(test)
            p = subprocess.Popen(
                [bpf_call], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            read_max_line = 4
            total_lines_read = 0
            line = '-'
            output = ''

            while (read_max_line > total_lines_read and line):
                line = p.stdout.readline().decode('utf-8', 'ignore')
                output += line + '\n'
                total_lines_read += 1

            result = re.search(test.expect, output)

        except (TimeoutError):
            print(fail("[  TIMEOUT ] ") + "%s.%s" % (test.file_name, test.name))
            print('\tCommand: %s' % bpf_call)
            print('\tTimeout: %s' % test.timeout)
            return Utils.TIMEOUT

        if result:
            print(ok("[       OK ] ") + "%s.%s" % (test.file_name, test.name))
            return Utils.PASS
        else:
            print(fail("[  FAILED  ] ") + "%s.%s" % (test.file_name, test.name))
            print('\tCommand: ' + bpf_call)
            print('\tExpected: ' + test.expect)
            print('\tFound: ' + output)
            return Utils.FAIL
