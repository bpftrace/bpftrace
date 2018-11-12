#!/usr/bin/env python

import unittest
from os import environ

from utils import Utils


class TestVariables(unittest.TestCase):

    def test_global_int(self):
        regex = "@a: 10"
        cmd = ("test=global_int; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1 {@a = 10; printf(\"%d\\n\", @a); exit();}'" +
        " | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_global_string(self):
        regex = "@a: hi"
        cmd = ("test=global_string; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1 {@a = \"hi\"; printf(\"%s\\n\", @a); exit();}'" +
        " | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_local_int(self):
        regex = "a=10"
        cmd = ("test=local_int; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1  {$a = 10; printf(\"a=%d\\n\", $a); exit();}'" +
        " | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_local_string(self):
        regex = "a=hi"
        cmd = ("test=local_string; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1  {$a = \"hi\"; printf(\"a=%s\\n\", $a); exit();}'" +
        " | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_global_associative_arrays(self):
        regex = "@start\\[[0-9]*\\]\\:\\s[0-9]*"
        cmd = ("test=global_arrays; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'kprobe:do_nanosleep { @start[tid] = nsecs; } kretprobe:do_nanosleep /@start[tid] != 0/ " +
        "{ printf(\"slept for %d ms\\n\", (nsecs - @start[tid]) / 1000000); delete(@start[tid]); exit();}'" +
        " | egrep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_scratch(self):
        regex = "@start\\[[0-9]+\\]\\:\\s[0-9]+"
        cmd = ("test=scratch; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'kprobe:do_nanosleep { @start[tid] = nsecs; } kretprobe:do_nanosleep /@start[tid] != 0/ " +
        "{ $delta = nsecs - @start[tid]; printf(\"slept for %d ms\\n\", $delta / 1000000); " +
        "delete(@start[tid]); exit(); }'" +
        " | egrep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)


if __name__ == "__main__":
    unittest.main()
