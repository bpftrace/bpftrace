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

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define EMIT_HELPER_TEST(name, progtype)                                       \
  bool BPFfeature::has_helper_##name(void)                                     \
  {                                                                            \
    if (!has_##name##_)                                                        \
      has_##name##_ = std::make_unique<bool>(                                  \
          detect_helper(libbpf::BPF_FUNC_##name, (progtype)));                 \
    return *(has_##name##_).get();                                             \
  }

#define EMIT_MAP_TEST(var, maptype)                                            \
  bool BPFfeature::has_map_##var(void)                                         \
  {                                                                            \
    if (!map_##var##_)                                                         \
      map_##var##_ = std::make_unique<bool>(detect_map((maptype)));            \
    return *(map_##var##_).get();                                              \
  }

#define EMIT_PROG_TEST(var, progtype)                                          \
  bool BPFfeature::has_prog_##var(void)                                        \
  {                                                                            \
    if (!prog_##var##_)                                                        \
      prog_##var##_ = std::make_unique<bool>(detect_prog_type((progtype)));    \
    return *(prog_##var##_).get();                                             \
  }

static bool try_load(const char* name,
                     bpf_prog_type prog_type,
                     struct bpf_insn* insns,
                     size_t insns_cnt,
                     int loglevel,
                     char* logbuf,
                     size_t logbuf_size)
{
  int ret = 0;
  StderrSilencer silencer;
  silencer.silence();
#ifdef HAVE_BCC_PROG_LOAD
  ret = bcc_prog_load(
#else
  ret = bpf_prog_load(
#endif
      prog_type,
      name,
      insns,
      insns_cnt * sizeof(struct bpf_insn),
      "GPL",
      0, /* version */
      loglevel,
      logbuf,
      logbuf_size);
  if (ret >= 0)
    close(ret);

  return ret >= 0;
}

static bool try_load(bpf_prog_type prog_type,
                     struct bpf_insn* insns,
                     size_t len)
{
  constexpr int log_size = 4096;
  char logbuf[log_size] = {};
  return try_load(nullptr, prog_type, insns, len, 0, logbuf, log_size);
}

static bool detect_helper(enum libbpf::bpf_func_id func_id,
                          enum bpf_prog_type prog_type)
{
  // Stolen from libbpf's  bpf_probe_helper
  char logbuf[4096] = {};
  struct bpf_insn insns[] = {
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, func_id),
    BPF_EXIT_INSN(),
  };

  try_load(nullptr, prog_type, insns, ARRAY_SIZE(insns), 1, logbuf, 4096);
  if (errno == EPERM)
    return false;

  return (strstr(logbuf, "invalid func ") == nullptr) &&
         (strstr(logbuf, "unknown func ") == nullptr);
}

static bool detect_prog_type(enum bpf_prog_type prog_type)
{
  struct bpf_insn insns[] = { BPF_MOV64_IMM(BPF_REG_0, 0), BPF_EXIT_INSN() };
  return try_load(prog_type, insns, ARRAY_SIZE(insns));
}

static bool detect_map(enum bpf_map_type map_type)
{
  int key_size = 4;
  int value_size = 4;
  int max_entries = 1;
  int flags = 0;
  int map_fd = 0;

  switch (map_type)
  {
    case BPF_MAP_TYPE_STACK_TRACE:
      value_size = 8;
      break;
    default:
      break;
  }

#ifdef HAVE_BCC_CREATE_MAP
  map_fd = bcc_create_map(
#else
  map_fd = bpf_create_map(
#endif
      map_type, nullptr, key_size, value_size, max_entries, flags);

  if (map_fd >= 0)
    close(map_fd);

  return map_fd >= 0;
}

bool BPFfeature::has_loop(void)
{
  if (has_loop_)
    return *has_loop_.get();

  struct bpf_insn insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 1),
    BPF_JMP_IMM(BPF_JLT, BPF_REG_0, 4, -2),
    BPF_EXIT_INSN(),
  };

  has_loop_ = std::make_unique<bool>(
      try_load(BPF_PROG_TYPE_TRACEPOINT, insns, ARRAY_SIZE(insns)));

  return has_loop();
}

EMIT_HELPER_TEST(send_signal, BPF_PROG_TYPE_KPROBE);
EMIT_HELPER_TEST(override_return, BPF_PROG_TYPE_KPROBE);
EMIT_HELPER_TEST(get_current_cgroup_id, BPF_PROG_TYPE_KPROBE);
EMIT_MAP_TEST(array, BPF_MAP_TYPE_ARRAY);
EMIT_MAP_TEST(hash, BPF_MAP_TYPE_HASH);
EMIT_MAP_TEST(percpu_array, BPF_MAP_TYPE_PERCPU_ARRAY);
EMIT_MAP_TEST(percpu_hash, BPF_MAP_TYPE_ARRAY);
EMIT_MAP_TEST(stack_trace, BPF_MAP_TYPE_STACK_TRACE);
EMIT_MAP_TEST(perf_event_array, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
EMIT_PROG_TEST(kprobe, BPF_PROG_TYPE_KPROBE);
EMIT_PROG_TEST(tracepoint, BPF_PROG_TYPE_TRACEPOINT);
EMIT_PROG_TEST(perf_event, BPF_PROG_TYPE_PERF_EVENT);

int BPFfeature::instruction_limit(void)
{
  if (!insns_limit_)
  {
    struct bpf_insn insns[] = {
      BPF_LD_IMM64(BPF_REG_0, 0),
      BPF_EXIT_INSN(),
    };

    constexpr int logsize = 4096;

    char logbuf[logsize] = {};
    bool res = try_load(nullptr,
                        BPF_PROG_TYPE_KPROBE,
                        insns,
                        ARRAY_SIZE(insns),
                        1,
                        logbuf,
                        logsize);
    if (!res)
      insns_limit_ = std::make_unique<int>(-1);

    // Extract limit from the verifier log:
    // processed 2 insns (limit 131072), stack depth 0
    std::string log(logbuf, logsize);
    std::size_t line_start = log.find("processed 2 insns");
    if (line_start != std::string::npos)
    {
      std::size_t begin = log.find("limit", line_start) + /* "limit " = 6*/ 6;
      std::size_t end = log.find(")", begin);
      std::string cnt = log.substr(begin, end - begin);
      insns_limit_ = std::make_unique<int>(std::stoi(cnt));
    }
    else
    {
      insns_limit_ = std::make_unique<int>(-1);
    }
  }

  return *insns_limit_.get();
}

std::string BPFfeature::report(void)
{
  std::stringstream buf;
  auto to_str = [](bool f) -> std::string { return f ? "yes\n" : "no\n"; };

  buf << "Kernel helpers" << std::endl
      << "  get_current_cgroup_id: "
      << to_str(has_helper_get_current_cgroup_id())
      << "  send_signal: " << to_str(has_helper_send_signal())
      << "  override_return: " << to_str(has_helper_override_return())
      << std::endl;

  buf << "Kernel features" << std::endl
      << "  Instruction limit: " << instruction_limit() << std::endl
      << "  Loop support: " << to_str(has_loop()) << std::endl;

  buf << "Map types" << std::endl
      << "  hash: " << to_str(has_map_hash())
      << "  percpu hash: " << to_str(has_map_percpu_hash())
      << "  array: " << to_str(has_map_array())
      << "  percpu array: " << to_str(has_map_percpu_array())
      << "  stack_trace: " << to_str(has_map_stack_trace())
      << "  perf_event_array: " << to_str(has_map_perf_event_array())
      << std::endl;

  buf << "Probe types" << std::endl
      << "  kprobe: " << to_str(has_prog_kprobe())
      << "  tracepoint: " << to_str(has_prog_tracepoint())
      << "  perf_event: " << to_str(has_prog_perf_event()) << std::endl;

  return buf.str();
}

} // namespace bpftrace
