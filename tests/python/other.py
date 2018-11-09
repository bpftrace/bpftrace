#!/usr/bin/env python

import unittest
from os import environ

from utils import Utils


class TestOther(unittest.TestCase):

    def test_if(self):
		regex = "a=20"
		cmd = ("test=if; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 {$a = 10; if ($a > 2) { $a = 20 }; printf(\"a=%d\\n\", $a); exit();}'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

		regex = "a=10"
		cmd = ("test=if; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 {$a = 10; if ($a < 2) { $a = 20 }; printf(\"a=%d\\n\", $a); exit();}'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_ifelse(self):
		regex = "a=hello"
		cmd = ("test=ifelse; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 {$a = \"\"; if (10 < 2) { $a = \"hi\" } else {$a = \"hello\"}; " +
		"printf(\"a=%s\\n\", $a); exit();}'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

		regex = "a=hi"
		cmd = ("test=ifelse; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 {$a = \"\"; if (10 > 2) { $a = \"hi\" } else {$a = \"hello\"};" +
		"printf(\"a=%s\\n\", $a); exit();}'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_unroll(self):
		regex = "a=21"
		cmd = ("test=unroll; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 {$a = 1; unroll (10) { $a = $a + 2; }; printf(\"a=%d\\n\", $a); exit();}'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

		regex = "unroll maximum value is 20"
		cmd = ("test=unroll_max; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 {$a = 1; unroll (30) { $a = $a + 2; }; printf(\"a=%d\\n\", $a); exit();}'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

		regex = "unroll minimum value is 1"
		cmd = ("test=unroll_min; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 {$a = 1; unroll (0) { $a = $a + 2; }; printf(\"a=%d\\n\", $a); exit();}'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)


if __name__ == "__main__":
    unittest.main()
