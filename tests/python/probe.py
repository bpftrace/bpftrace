#!/usr/bin/env python

import unittest
from os import environ

from utils import Utils


class TestProbe(unittest.TestCase):

    def test_kprobe(self):
        regex = Utils.regex_uint("kprobe")
        cmd = ("test=kprobe; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'kprobe:do_nanosleep { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

        regex = Utils.regex_uint("kprobe2")
        cmd = ("test=kprobe2; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'k:do_nanosleep { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

        regex = "kprobes should not have a target"
        cmd = ("test=kprobe3; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'kprobe:syscalls:sys_exit_nanosleep { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }'" +
        " | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_kretprobe(self):
        regex = Utils.regex_uint("kretprobe")
        cmd = ("test=kretprobe; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'kretprobe:do_nanosleep { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

        regex = Utils.regex_uint("kr")
        cmd = ("test=kr; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'kr:do_nanosleep { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

        regex = "kprobes should not have a target"
        cmd = ("test=pid; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'kretprobe:syscalls:sys_exit_nanosleep { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }'" +
        " | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_uprobe(self):
        regex = "a: 10, b: 20"
        cmd = ("test=uprobe; sleep 1 && ./runtimetest & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'uprobe:./runtimetest:somefunc {printf(\"a: %d, b: %d\", arg0, arg1); exit();}'" +
        " | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_uretprobe(self):
        regex = "ret: 30"
        cmd = ("test=uretprobe; sleep 1 && ./runtimetest & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'uretprobe:./runtimetest:somefunc {printf(\"ret: %d\", retval); exit();} '" +
        " | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_tracepoint(self):
        regex = Utils.regex_uint("tra")
        cmd = ("test=tra; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'tracepoint:syscalls:sys_exit_nanosleep { printf(\"SUCCESS '$test' %d\\n\", gid); exit(); }'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

        regex = Utils.regex_uint("t")
        cmd = ("test=t; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'t:syscalls:sys_exit_nanosleep { printf(\"SUCCESS '$test' %d\\n\", gid); exit(); }'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_profile(self):
        regex = "\\@\\[[0-9]*\\]\\:\\s[0-9]"
        cmd = ("test=profile; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'profile:hz:99 { @[tid] = count(); exit();}'" +
        " | egrep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

        cmd = ("test=p; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'p:hz:99 { @[tid] = count(); exit();}'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

        regex = "profile probe must have an integer frequency"
        cmd = ("test=p_int; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'p:ms:nan { @[tid] = count(); exit();}'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

        regex = "profile probe must have unit of time"
        cmd = ("test=p_time; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'p:unit { @[tid] = count(); exit();}'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_interval(self):
        regex = "\\@syscalls\\:\\s[0-9]*"
        cmd = ("test=interval; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'t:raw_syscalls:sys_enter { @syscalls = count(); } " +
        "interval:s:1 { print(@syscalls); clear(@syscalls); exit();}'" +
        " | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

        cmd = ("test=i; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'t:raw_syscalls:sys_enter { @syscalls = count(); } "+
        "i:s:1 { print(@syscalls); clear(@syscalls); exit();}'" +
        " | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

        regex = "interval probe must have an integer frequency"
        cmd = ("test=i_freq; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'t:raw_syscalls:sys_enter { @syscalls = count(); } " +
        "interval:ms:nan { print(@syscalls); clear(@syscalls); exit();}'" +
        " | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

        regex = "interval probe must have unit of time"
        cmd = ("test=i_time; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'t:raw_syscalls:sys_enter { @syscalls = count(); }" +
        "interval:s { print(@syscalls); clear(@syscalls); exit();}'" +
        " | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_software(self):
        regex = "@\\[.*\\]\\:\\s[0-9]*"
        cmd = ("test=software; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'software:faults:100 { @[comm] = count(); exit();}'" +
		" | egrep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_hardware(self):
        regex = "\\@\\[[0-9]*\\]\\:\\s[0-9]"
        cmd = ("test=hardware; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'hardware:cache-misses:1000000 { @[pid] = count(); exit(); }'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)


if __name__ == "__main__":
    unittest.main()
