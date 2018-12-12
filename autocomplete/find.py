#!/usr/bin/python

import sys
import re
import os
import subprocess

OPTS = ['-l', '-e', '-p', '-v', '-d' '-dd']

VARIABLES = ['count', 'hist', 'lhist', 'nsecs', 'stack', 'ustack']

FUNCTIONS = [
    'printf', 'time', 'join', 'str', 'sym', 'usym', 'kaddr', 'uaddr',
    'reg', 'system', 'exit', 'cgroupid', 'min', 'max', 'stats'
]

PROBES = [
    'kprobe',
    'kretprobe',
    'uprobe',
    'uretprobe',
    'tracepoint',
    'ustd',
    'profile',
    'interval',
    'software',
    'hardware']

SINGLE_NAME_LIST = [OPTS, PROBES, VARIABLES, FUNCTIONS]

def find(name):
    name_split = name.split(':')
    probe_name = name_split[0]
    search = ':'.join(name_split[1:])
    match = ''
    if probe_name == 'kprobe' or probe_name == 'kretprobe':
        match = kprobe_event(search)
    elif probe_name == 'tracepoint':
        search = name_split[1:]
        match = tracepoint_event(search)
    else:
        match = find_single_name(search)

    return match


def kprobe_event(search):
    f = open("/sys/kernel/debug/tracing/available_filter_functions", "r")
    value = filter(lambda x: re.search('^' + search, x), f.readlines())
    f.close
    return value

def tracepoint_event(search_list):
    cmd = 'sudo ../build-release/src/bpftrace -l "tracepoint:*"'
    p = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, error = p.communicate()

    if error != None:
        return []
    else:
        search = ':'.join(search_list)
        search_list.pop()
        replace = ':'.join(search_list) + ':'
        if replace == ':':
            replace = ''

        tool_list = filter(lambda x: re.search('^tracepoint:' + search, x), output.split())
        return [s.replace('tracepoint:' + replace, '') for s in tool_list]

def find_single_name(name):
    total_match = []

    for lst in SINGLE_NAME_LIST:
        total_match += filter(lambda x: re.search('^' + name, x), lst)

    return total_match

def print_result(result):
    for item in result:
        print(item)

def main(argv):
    if len(argv) == 0:
        return 0

    user_input = argv[0]

    if re.search('.+\\:', user_input):
        print_result(find(user_input))
    else:
        print_result(find_single_name(user_input))


if __name__ == '__main__':
    main(sys.argv[1:])
