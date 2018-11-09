#!/usr/bin/env python

import unittest
from os import environ

from utils import Utils


class TestBuiltin(unittest.TestCase):

    def test_pid(self):
        regex = Utils.regex_uint("pid")
        cmd = ("test=pid; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_tid(self):
        regex = Utils.regex_uint("tid")
        cmd = ("test=tid; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
		"'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", tid); exit(); }'" +
		" | grep '{}' || echo \"FAILURE $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_uid(self):
        regex = Utils.regex_uint("uid")
        cmd = ("test=uid; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", uid); exit(); }'" +
        " | grep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_gid(self):
        regex = Utils.regex_uint("gid")
        cmd = ("test=gid; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", gid); exit(); }'" +
        " | grep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_nsecs(self):
        regex = Utils.regex_int("nsecs")
        cmd = ("test=nsecs; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", nsecs); exit(); }'" +
        " | egrep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_cpu(self):
        regex = Utils.regex_uint("cpu")
        cmd = ("test=cpu; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", cpu); exit(); }'" +
        " | grep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_comm(self):
        regex = Utils.regex_str("comm")
        cmd = ("test=comm; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'k:do_nanosleep { printf(\"SUCCESS '$test' %s\\n\", comm); exit(); }'" +
        " | egrep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_stack(self):
        # grep does not work with mutiple lines
        regex = "^SUCCESS stack"
        cmd = ("test=stack; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'k:do_nanosleep { printf(\"SUCCESS '$test' %s\\n\", stack); exit(); }'" +
        " | grep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_ustack(self):
        # ustack - grep does not work with mutiple lines
        regex = "^SUCCESS ustack"
        cmd = ("test=ustack; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'k:do_nanosleep { printf(\"SUCCESS '$test' %s\\n\", ustack); exit(); }'" +
        " | grep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_arg(self):
        regex = Utils.regex_int("arg0")
        cmd = ("test=arg0; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", arg0); exit(); }'" +
        " | egrep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_retval(self):
        regex = Utils.regex_uint("retval")
        cmd = ("test=retval; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'k:do_nanosleep { printf(\"SUCCESS '$test' %d\\n\", retval); exit(); }'" +
        " | egrep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_func(self):
        regex = Utils.regex_str("func")
        cmd = ("test=func; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'k:do_nanosleep { printf(\"SUCCESS '$test' %s\\n\", func); exit(); }'" +
        " | grep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_username(self):
        regex = Utils.regex_str("username")
        cmd = ("test=username; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1 { printf(\"SUCCESS '$test' %s\\n\", username); exit(); }'" +
        " | grep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_probe(self):
        regex = "^SUCCESS probe kprobe:do_nanosleep"
        cmd = ("test=probe; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'k:do_nanosleep { printf(\"SUCCESS '$test' %s\\n\", probe); exit(); }'" +
        " | grep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_curtask(self):
        regex = Utils.regex_int("curtask")
        cmd = ("test=curtask; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", curtask); exit(); }'" +
         " | egrep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_rand(self):
        regex = Utils.regex_int("rand")
        cmd=("test=rand; {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", rand); exit(); }'" +
        " | egrep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)

    def test_cgroup(self):
        # cgroup - TODO: not working
        regex = Utils.regex_int("cgroup")
        cmd=("test=cgroup; sleep 1 & sleep 15 & {} -e ".format(environ["BPFTRACE_RUNTIME"]) +
        "'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", cgroup); exit(); }'" +
        " | grep '{}' || echo \"FAILURE  $test\"".format(regex))
        Utils.run_test(self, cmd, regex)


if __name__ == "__main__":
    unittest.main()
