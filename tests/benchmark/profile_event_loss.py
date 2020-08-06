#!/usr/bin/python3
import os
import sys
import signal
import subprocess
import time
import matplotlib.pyplot as plt


def process_output(lines):
    lost_events = 0
    handled_events = 0
    for line in lines:
        columns = line.split()
        try:
            col1 = columns[0]
            col2 = int(columns[1])
            if (col1 == 'Lost' and col2 > 0):
                lost_events += col2
            if (col1 == 'hello'):
                handled_events += 1
        except IndexError:
            # ignore
            pass

    total = handled_events + lost_events
    loss_rate = lost_events / total
    print(f'handled events: {handled_events!r}')
    print(f'   lost events: {lost_events!r}')
    print(f'  total events: {total!r}')
    print(f'     loss rate: {loss_rate:.2%}')
    return loss_rate


def run(nth, test):
    loss_rate = 0
    is_ringbuf = False
    lines = []
    print(f"*********BEGIN: {nth:d}*********")
    try:
        proc = subprocess.Popen(
            ['bpftrace', test], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(timeout=13)
        lines = out.decode('utf-8').splitlines()
        err_txt = err.decode('utf-8')
        print(err_txt)
        if ('ring buffer' in err_txt):
            is_ringbuf = True
        loss_rate = process_output(lines)
        if proc.returncode:
            print(f'Error in the execution, return code: {proc.returncode:d}')
    except subprocess.TimeoutExpired:
        # bpf ringbuf: to get the # of lost events
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate()
        lines = out.decode('utf-8').splitlines()
        err_txt = err.decode('utf-8')
        print(err_txt)
        if ('ring buffer' in err_txt):
            is_ringbuf = True
        loss_rate = process_output(lines)
        print("Timeout!")
    print("************END*************\n")
    return loss_rate, is_ringbuf


if __name__ == "__main__":
    stats = {}
    is_ringbuf = False
    logname = 'profilelog-' + time.strftime("%Y%m%d-%H%M%S")
    sys.stdout = open(logname, 'w')
    files = os.listdir('./profile')
    nums = [int(x.replace('profile_', '').replace('k.bt', '')) for x in files]
    tests = sorted(zip(files, nums), key=lambda pair: pair[1])
    done = 0
    for test in tests:
        print('Running test: ' + test[0])
        print(str(done) + ' done, ' + str(len(files) - done) + ' to go')
        test_name = os.path.join('./profile', test[0])
        stats[test[1]] = []
        for i in range(6):
            loss_rate, is_ringbuf = run(i, test_name)
            stats[test[1]].append(loss_rate)
            # time.sleep(5) # cool down a bit, not sure if necessary
        print(stats[test[1]])
        print('\n')
        done += 1

    plt.boxplot(stats.values(), positions=list(stats.keys()))
    print(stats.values())
    plt.title('BPF ringbuf' if is_ringbuf else 'BPF perfbuf')
    plt.xlabel('thousand profiling events per sec')
    plt.ylabel('event loss rate')
    plt.ylim(-0.03, 1)
    plt.savefig(logname+'.png', format='png')
    plt.show()
