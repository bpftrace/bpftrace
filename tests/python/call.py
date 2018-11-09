#!/usr/bin/env python

import unittest
from os import environ

from utils import Utils


class TestCall(unittest.TestCase):

    def test_printf(self):
		regex = "hi!"
		cmd = ("test=printf; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 { printf(\"hi!\\n\"); exit();}' " +
		" | egrep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

		regex = "value: 100"
		cmd = ("test=printf_value; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 { printf(\"value: %d\\n\", 100); exit();}' " +
		" | egrep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_time(self):
		regex = "[0-9]*:[0-9]*:[0-9]*"
		cmd = ("test=time; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 { time(\"%H:%M:%S\\n\"); exit();}' " +
		" | egrep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

		regex = "[0-9]*-[0-9]*"
		cmd = ("test=time_2; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 { time(\"%H-%M:\\n\"); exit();}' " +
		" | egrep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_join(self):
		regex = "echo A"
		cmd = ("test=join; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 { system(\"echo 'A'\"); } kprobe:sys_execve { join(arg1); exit();}' " +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_str(self):
		regex = "P: /bin/sh"
		cmd = ("test=str; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1{ system(\"echo 10\"); } k:sys_execve { printf(\"P: %s\\n\", str(arg0)); exit();}' " +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_sym(self):
		regex = "do_nanosleep"
		cmd = ("test=sym; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'kprobe:do_nanosleep { printf(\"%s\\n\", sym(reg(\"ip\"))); exit();}' " +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_system(self):
		regex = "ok_system"
		cmd = ("test=system; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 { system(\"echo 'ok_system'\"); exit();}' " +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_count(self):
		regex = "@\\[[0-9]*\\]\\:\\s[0-9]*"
		cmd = ("test=count; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:100 { @[sym(reg(\"ip\"))] = count(); exit();}' " +
		" | egrep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_sum(self):
		regex = "@.*\\[.*\\]\\:\\s[0-9]*"
		cmd = ("test=sum; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"' kprobe:vfs_read { @bytes[comm] = sum(arg2); exit();}' " +
		" | egrep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_avg(self):
		regex = "@.*\\[.*\\]\\:\\s[0-9]*"
		cmd = ("test=avg; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'kprobe:vfs_read { @bytes[comm] = avg(arg2); exit();}'" +
		" | egrep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_min(self):
		regex = "@.*\\[.*\\]\\:\\s[0-9]*"
		cmd = ("test=min; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
	    "' kprobe:vfs_read { @bytes[comm] = min(arg2); exit();}' " +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_max(self):
		regex = "@.*\\[.*\\]\\:\\s[0-9]*"
		cmd = ("test=min; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
	    "' kprobe:vfs_read { @bytes[comm] = max(arg2); exit();}' " +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_stats(self):
		regex = "@.*\\[.*\\]\\:\\scount\\s[0-9]*\\,\\saverage\\s[0-9]*\\,\\stotal\\s[0-9]*"
		cmd = ("test=stats; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"' kprobe:vfs_read { @bytes[comm] = stats(arg2); exit();}' " +
		" | egrep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_hist(self):
		regex = "@bytes:"
		cmd = ("test=hist; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"' kretprobe:vfs_read { @bytes = hist(retval); exit();}' " +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

		regex = "\\[.*\\,\\s.*\\]?\\)?\\s"
		cmd = ("test=hist2; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"' kretprobe:vfs_read { @bytes = hist(retval); exit();}' " +
		" | egrep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

    def test_lhist(self):
		regex = "@bytes:"
		cmd = ("test=lhist; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"' kretprobe:vfs_read { @bytes = lhist(retval, 0, 10000, 1000); exit()}' " +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)

		regex = "\\[.*\\,\\s.*\\]?\\)?\\s"
		cmd = ("test=lhist2; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"' kretprobe:vfs_read { @bytes = lhist(retval, 0, 10000, 1000); exit()}' " +
		" | egrep '{}' || echo \"FAILURE $test\"".format(regex))
		Utils.run_test(self, cmd, regex)


if __name__ == "__main__":
    unittest.main()
