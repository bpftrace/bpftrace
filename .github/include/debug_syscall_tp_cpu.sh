#!/bin/bash
# TEMPORARY: check whether syscall tracepoint events are lost on specific
# CPUs. Run as root:
#   debug_syscall_tp_cpu.sh <path/to/bpftrace> [rounds]
#
# Execs `true` pinned to each CPU and counts the exec per CPU via:
#   sys_enter  syscalls:sys_enter_execve (perf path, copies user strings)
#   sys_exit   syscalls:sys_exit_execve  (perf path, no user copy)
#   tp         sched:sched_process_exec  (perf path, regular tracepoint)
#   raw        rawtracepoint:sched_process_exec (no perf buffer; control)
set -u

BT=$(realpath "$1")
ROUNDS=${2:-20}
TRUE=$(type -P true)
TASKSET=$(type -P taskset)
NCPUS=$(nproc)

if [[ ! -x $BT ]]; then
  echo "bpftrace binary not found at $1, skipping"
  exit 0
fi

# shellcheck disable=SC2016
PROG='
t:syscalls:sys_enter_execve /comm == "taskset"/ { @sys_enter[cpu] = count(); }
t:syscalls:sys_exit_execve /comm == "true"/ { @sys_exit[cpu] = count(); }
t:sched:sched_process_exec /comm == "true"/ { @tp[cpu] = count(); }
rawtracepoint:sched_process_exec /comm == "true"/ { @raw[cpu] = count(); }
'

run_round() {
  local out pid i cpu
  out=$(mktemp)
  __BPFTRACE_NOTIFY_PROBES_ATTACHED=1 "$BT" -e "$PROG" >"$out" 2>&1 &
  pid=$!
  for ((i = 0; i < 200; i++)); do
    [[ $(<"$out") == *__BPFTRACE_NOTIFY_PROBES_ATTACHED* ]] && break
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.05
  done
  for ((cpu = 0; cpu < NCPUS; cpu++)); do
    for ((i = 0; i < ROUNDS; i++)); do
      "$TASKSET" -c "$cpu" "$TRUE"
    done
  done
  sleep 0.5
  kill -INT "$pid"
  wait "$pid"
  awk -v ncpus="$NCPUS" '
    match($0, /^@([a-z_]+)\[([0-9]+)\]: ([0-9]+)$/, m) { n[m[1], m[2]] = m[3]; next }
    /^@/ || /^$/ || /NOTIFY_PROBES_ATTACHED/ || /^Attached/ { next }
    { print "    " $0 }
    END {
      printf "    %-4s %10s %10s %10s %10s\n", "cpu", "sys_enter", "sys_exit", "tp", "raw"
      for (c = 0; c < ncpus; c++)
        printf "    %-4s %10d %10d %10d %10d\n", c, n["sys_enter", c], n["sys_exit", c], n["tp", c], n["raw", c]
    }' "$out"
  rm -f "$out"
}

echo "=== $(uname -r), $NCPUS cpus, $ROUNDS execs per cpu (expect $ROUNDS everywhere)"
for attempt in 1 2 3; do
  echo "--- attempt $attempt"
  run_round
done
