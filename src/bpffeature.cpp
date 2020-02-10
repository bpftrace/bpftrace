#include <bcc/libbpf.h>
#include <bpffeature.h>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
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
  constexpr int log_size = 40960;
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

static bool detect_override_return(void)
{
  struct bpf_insn insns[] = {
    BPF_LD_IMM64(BPF_REG_2, 11),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, libbpf::BPF_FUNC_override_return),
    BPF_EXIT_INSN(),
  };

  return try_load(
      "test_override_return", BPF_PROG_TYPE_KPROBE, insns, sizeof(insns));
}

static int detect_instruction_limit(void)
{
  struct bpf_insn insns[] = {
    BPF_LD_IMM64(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  constexpr int log_size = 4096;
  char logbuf[log_size] = {};
  int loglevel = 1;
  int ret = 0;
  {
    // Don't want to spam unit tests with failure messages
    StderrSilencer silencer;
    silencer.silence();

#ifdef HAVE_BCC_PROG_LOAD
    ret = bcc_prog_load(BPF_PROG_TYPE_KPROBE,
                        "ins_count",
                        insns,
                        sizeof(insns),
                        "GPL",
                        0,
                        loglevel,
                        logbuf,
                        log_size);
#else
    ret = bpf_prog_load(BPF_PROG_TYPE_KPROBE,
                        "ins_count",
                        insns,
                        sizeof(insns),
                        "GPL",
                        0,
                        loglevel,
                        logbuf,
                        log_size);
#endif
  }
  if (ret < 0)
    return 0;
  else
    close(ret);

  // Extract limit from the verifier log:
  // processed 2 insns (limit 131072), stack depth 0
  std::string log(logbuf, log_size);
  std::size_t line_start = log.find("processed 2 insns");
  std::size_t begin = log.find("limit", line_start) + /* "limit " = 6*/ 6;
  std::size_t end = log.find(")", begin);
  std::string cnt = log.substr(begin, end - begin);
  return std::stoi(cnt);
}

BPFfeature::BPFfeature(void)
{
  has_loop_ = detect_loop();
  has_signal_ = detect_signal();
  has_get_current_cgroup_id_ = detect_get_current_cgroup_id();
  has_override_return_ = detect_override_return();
  insns_limit_ = detect_instruction_limit();
}

std::string BPFfeature::report(void)
{
  std::stringstream buf;
  auto to_str = [](bool f) -> std::string { return f ? "yes" : "no"; };
  buf << "Kernel helpers" << std::endl
      << "  get_current_cgroup_id: "
      << to_str(has_helper_get_current_cgroup_id()) << std::endl
      << "  send_signal: " << to_str(has_helper_send_signal()) << std::endl
      << "  override_return: " << to_str(has_helper_override_return())
      << std::endl
      << std::endl
      << "Kernel features" << std::endl
      << "  Instruction limit: "
      << (insns_limit_ ? std::to_string(insns_limit_) : "?") << std::endl
      << "  Loop support: " << to_str(has_loop()) << std::endl
      << std::endl;
  return buf.str();
}

} // namespace bpftrace
