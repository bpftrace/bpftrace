import subprocess
import sys

class Utils():
    @staticmethod
    def run_test(cls, cmd, expected):
        p = subprocess.Popen(
            [cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        cls.assertRegexpMatches(p.stdout.readline(), expected)

    @staticmethod
    def regex_uint(test_name):
        return "^SUCCESS {} [0-9][0-9]*".format(test_name)

    @staticmethod
    def regex_int(test_name):
        return "^SUCCESS {} -?[0-9][0-9]*".format(test_name)

    @staticmethod
    def regex_str(test_name):
        return "^SUCCESS {} .*".format(test_name)
