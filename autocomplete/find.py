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


def find_probe(name):
    name_split = name.split(':')
    probe_name = name_split[0]
    search = ':'.join(name_split[1:])
    match = ''
    if probe_name == 'kprobe' or probe_name == 'kretprobe':
        match = kprobe_event(search)
    elif probe_name == 'tracepoint':
        match = tracepoint_event(search)
    else:
        match = find_single_name(search)

    return match


def kprobe_event(search):
   return probe_event('kprobe', search)


def tracepoint_event(search):
    return probe_event('tracepoint', search)


def probe_event(probe_name, search):
    cmd = 'sudo ./bpftrace -l "' + probe_name + ':*"'
    p = subprocess.Popen(
        [cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, error = p.communicate()

    if error != None:
        return []
    else:
        return filter(lambda x: re.search('^' + probe_name + ':' + search, x), output.split())


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

    if user_input[0] == "'":
        user_input = user_input[1:]

    last_char = len(user_input) - 1
    if user_input[last_char] == "'":
        user_input = user_input[0:last_char]

    if re.search('.+\\:', user_input):
        print_result(find_probe(user_input))
    else:
        print_result(find_single_name(user_input))


if __name__ == '__main__':
    main(sys.argv[1:])
