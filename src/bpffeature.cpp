#include <bcc/libbpf.h>
#include <bpffeature.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "utils.h"

namespace bpftrace {

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
}

BPFfeature::BPFfeature(void)
{
  has_loop_ = detect_loop();
}

bool BPFfeature::has_loop(void)
{
  return has_loop_;
}

bool BPFfeature::has_helper_get_current_cgroup_id(void)
{
#ifdef HAVE_GET_CURRENT_CGROUP_ID
  return true;
#else
  return false;
#endif
}

bool BPFfeature::has_helper_send_signal(void)
{
#ifdef HAVE_SEND_SIGNAL
  return true;
#else
  return false;
#endif
}

} // namespace bpftrace
