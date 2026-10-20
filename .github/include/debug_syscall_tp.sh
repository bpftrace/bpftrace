#!/bin/bash
# TEMPORARY: diagnose syscall tracepoint programs that attach but never
# produce output on some GitHub runner kernels. Run as root:
#   debug_syscall_tp.sh <path/to/bpftrace> [iterations]
set -u

BT=$(realpath "$1")
N=${2:-5}
TRUE=$(type -P true)
CAT=$(type -P cat)

if [[ ! -x $BT ]]; then
  echo "bpftrace binary not found at $1, skipping"
  exit 0
fi

declare -A pass fail

echo "::group::environment"
uname -a
echo "nproc: $(nproc)"
echo "possible: $(cat /sys/devices/system/cpu/possible)"
echo "online: $(cat /sys/devices/system/cpu/online)"
cat /sys/kernel/tracing/events/syscalls/sys_enter_execve/format
echo "--- BPF programs already loaded:"
bpftool prog show 2>&1 | head -100
echo "::endgroup::"

sysctl -w kernel.bpf_stats_enabled=1
exec {NAP_FD}<> <(:)

# Everything between attaching and the trigger must avoid exec'ing (the probe
# would fire on it), so only shell builtins are used below.
nap() {
  read -r -t "$1" -u "$NAP_FD" _
}

prog_stats() {
  local pid=$1 f line info
  for f in /proc/"$pid"/fdinfo/*; do
    info=""
    while IFS= read -r line; do
      case $line in
        prog_type* | prog_id* | run_cnt* | recursion_misses*) info+="$line " ;;
      esac
    done <"$f"
    [[ $info == prog_type* ]] && echo "$info"
  done
}

record() {
  local name=$1 ok=$2 out=$3 stats=$4
  if [[ $ok == 1 ]]; then
    pass[$name]=$((${pass[$name]:-0} + 1))
    echo "[ok]   $name"
  else
    fail[$name]=$((${fail[$name]:-0} + 1))
    echo "[FAIL] $name"
    head -n 20 "$out" | sed 's/^/    /'
    while IFS= read -r line; do
      [[ -n $line ]] && echo "    stats: $line"
    done <<<"$stats"
  fi
}

# Mimics the runtime test runner: wait for the attach notification, then run
# the trigger in a new session (subprocess.Popen(shell=True,
# start_new_session=True)).
run_external() {
  local name=$1 delay=$2 expect=$3 prog=$4 trigger=$5
  local out stats="" ok=0 pid i
  out=$(mktemp)
  __BPFTRACE_NOTIFY_PROBES_ATTACHED=1 "$BT" -e "$prog" >"$out" 2>&1 &
  pid=$!
  for ((i = 0; i < 200; i++)); do
    [[ $(<"$out") == *__BPFTRACE_NOTIFY_PROBES_ATTACHED* ]] && break
    kill -0 "$pid" 2>/dev/null || break
    nap 0.05
  done
  nap "$delay"
  setsid sh -c "$trigger" >/dev/null 2>&1
  for ((i = 0; i < 60; i++)); do
    [[ $(<"$out") =~ $expect ]] && { ok=1; break; }
    kill -0 "$pid" 2>/dev/null || break
    nap 0.05
  done
  if [[ $ok == 0 ]] && kill -0 "$pid" 2>/dev/null; then
    stats=$(prog_stats "$pid")
  fi
  kill -INT "$pid" 2>/dev/null
  nap 0.5
  kill -KILL "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  record "$name" "$ok" "$out" "$stats"
  rm -f "$out"
}

run_child() {
  local name=$1 expect=$2 prog=$3 child=$4
  local out ok=0
  out=$(mktemp)
  timeout -s INT -k 5 10 "$BT" -e "$prog" -c "$child" >"$out" 2>&1
  [[ $(<"$out") =~ $expect ]] && ok=1
  record "$name" "$ok" "$out" ""
  rm -f "$out"
}

PROG='t:syscalls:sys_enter_execve { printf("P: %s\n", str(args.filename)); exit(); }'
STACK="config = { max_strlen = 32 } $PROG"
SCRATCH="config = { max_strlen = 64; on_stack_limit = 0 } $PROG"
# shellcheck disable=SC2016
OPENAT_FIELD='t:syscalls:sys_enter_openat /comm == "cat"/ { $i = args.flags; printf("openflags: %d\n", $i); exit(); }'
# shellcheck disable=SC2016
OPENAT_COPY='t:syscalls:sys_enter_openat /comm == "cat"/ { $a = args; printf("openflags: %d\n", $a.flags); exit(); }'

echo "::group::matrix"
for _ in $(seq "$N"); do
  run_external stack/external 0 'P: ' "$STACK" "$TRUE"
  run_external scratch/external 0 'P: ' "$SCRATCH" "$TRUE"
  run_external stack/external+1s 1 'P: ' "$STACK" "$TRUE"
  run_external scratch/external+1s 1 'P: ' "$SCRATCH" "$TRUE"
  run_child stack/-c 'P: ' "$STACK" "$TRUE"
  run_child scratch/-c 'P: ' "$SCRATCH" "$TRUE"
  run_external openat_field/external 0 'openflags: ' "$OPENAT_FIELD" "$CAT /etc/hostname"
  run_external openat_copy/external 0 'openflags: ' "$OPENAT_COPY" "$CAT /etc/hostname"
done
echo "::endgroup::"

echo "=== $(uname -r), $N iterations"
for name in stack/external scratch/external stack/external+1s \
            scratch/external+1s stack/-c scratch/-c \
            openat_field/external openat_copy/external; do
  printf "%-24s pass=%-3s fail=%s\n" "$name" "${pass[$name]:-0}" "${fail[$name]:-0}"
done
