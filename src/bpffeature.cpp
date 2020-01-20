#include <bcc/libbpf.h>
#include <bpffeature.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "utils.h"

namespace libbpf {
#undef __BPF_FUNC_MAPPER
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace {

static bool try_load(const char* name,
                     bpf_prog_type prog_type,
                     struct bpf_insn* insns,
                     size_t len)
{
  int log_size = 40960;
  char logbuf[log_size] = {};
  int loglevel = 0;
  int ret = 0;
  StderrSilencer silencer;
  silencer.silence();
#ifdef HAVE_BCC_PROG_LOAD
  ret = bcc_prog_load(
      prog_type, name, insns, len, "GPL", 0, loglevel, logbuf, log_size);
#else
  ret = bpf_prog_load(
      prog_type, name, insns, len, "GPL", 0, loglevel, logbuf, log_size);
#endif
  if (ret >= 0)
    close(ret);

  return ret >= 0;
}

static bool detect_loop(void)
{
  struct bpf_insn insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 1),
    BPF_JMP_IMM(BPF_JLT, BPF_REG_0, 4, -2),
    BPF_EXIT_INSN(),
  };

  return try_load("test_loop", BPF_PROG_TYPE_TRACEPOINT, insns, sizeof(insns));
}

static bool detect_get_current_cgroup_id(void)
{
  struct bpf_insn insns[] = {
    BPF_RAW_INSN(
        BPF_JMP | BPF_CALL, 0, 0, 0, libbpf::BPF_FUNC_get_current_cgroup_id),
    BPF_EXIT_INSN(),
  };

  return try_load(
      "test_cgroup_id", BPF_PROG_TYPE_TRACEPOINT, insns, sizeof(insns));
}

static bool detect_signal(void)
{
  struct bpf_insn insns[] = {
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, libbpf::BPF_FUNC_send_signal),
    BPF_EXIT_INSN(),
  };

  return try_load("test_signal", BPF_PROG_TYPE_KPROBE, insns, sizeof(insns));
}

BPFfeature::BPFfeature(void)
{
  has_loop_ = detect_loop();
  has_signal_ = detect_signal();
  has_get_current_cgroup_id_ = detect_get_current_cgroup_id();
}

{
}

} // namespace bpftrace
