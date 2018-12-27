import subprocess
import signal
import sys
from os import environ
import re

BPF_PATH = environ["BPFTRACE_RUNTIME_TEST_EXECUTABLE"]


OK_COLOR = '\033[92m'
ERROR_COLOR = '\033[91m'
NO_COLOR = '\033[0m'

class TimeoutError(Exception):
    pass

class Utils(object):
    @staticmethod
    def prepare_bpf_call(test):
        return ('test={}; '.format(test.name) +
            test.before + ' {}'.format(BPF_PATH) + test.run + ' ' + test.after)

    @staticmethod
    def __handler(signum, frame):
        raise TimeoutError('TIMEOUT')

    @staticmethod
    def run_test(test):
        signal.signal(signal.SIGALRM, Utils.__handler)
        signal.alarm(test.timeout)

        try:
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
            print(test.name + ERROR_COLOR + ' ' + ' TIMEOUT ' + NO_COLOR)
            return False

        if result:
            print(test.name + OK_COLOR + ' OK' + NO_COLOR)
            return True
        else:
            print(test.name + ERROR_COLOR + ' ERROR' + NO_COLOR +
                '\n\tExpected: ' + test.expect + '\n\tFound: ' + output)
            return False
