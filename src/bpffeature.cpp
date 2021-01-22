#include <bcc/libbpf.h>
#ifdef HAVE_LIBBPF_MAP_BATCH
#include <bpf/bpf.h>
#endif
#include <bpffeature.h>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

#include "btf.h"
#include "probe_matcher.h"
#include "utils.h"

namespace bpftrace {

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static bool try_load(const char* name,
                     enum libbpf::bpf_prog_type prog_type,
                     struct bpf_insn* insns,
                     size_t insns_cnt,
                     int loglevel,
                     char* logbuf,
                     size_t logbuf_size)
{
  int ret = 0;
  StderrSilencer silencer;
  silencer.silence();
  for (int attempt = 0; attempt < 3; attempt++)
  {
    auto version = kernel_version(attempt);
    if (version == 0 && attempt > 0)
    {
      // Recent kernels don't check the version so we should try to call
      // bcc_prog_load during first iteration even if we failed to determine
      // the version. We should not do that in subsequent iterations to avoid
      // zeroing of log_buf on systems with older kernels.
      continue;
    }

#ifdef HAVE_BCC_PROG_LOAD
    ret = bcc_prog_load(
#else
    ret = bpf_prog_load(
#endif
        static_cast<enum ::bpf_prog_type>(prog_type),
        name,
        insns,
        insns_cnt * sizeof(struct bpf_insn),
        "GPL",
        version,
        loglevel,
        logbuf,
        logbuf_size);
    if (ret >= 0)
    {
      close(ret);
      return true;
    }
  }

  return false;
}

static bool try_load(enum libbpf::bpf_prog_type prog_type,
                     struct bpf_insn* insns,
                     size_t len,
                     const char* name = nullptr)
{
  constexpr int log_size = 4096;
  char logbuf[log_size] = {};

  // kfunc / kretfunc only for now. We can refactor if more attach types
  // get added to BPF_PROG_TYPE_TRACING
  if (prog_type == libbpf::BPF_PROG_TYPE_TRACING && !name)
  {
    // List of available functions must be readable
    std::ifstream traceable_funcs(kprobe_path);
    // bcc checks the name (first arg) for the magic strings. If the bcc we
    // build against doesn't support kfunc then we will fail here. That's fine
    // because it still means kfunc doesn't work, only from a library side, not
    // a kernel side.
    return traceable_funcs.good() &&
           try_load("kfunc__sched_fork",
                    prog_type,
                    insns,
                    len,
                    0,
                    logbuf,
                    log_size) &&
           try_load("kretfunc__sched_fork",
                    prog_type,
                    insns,
                    len,
                    0,
                    logbuf,
                    log_size);
  }

  return try_load(name, prog_type, insns, len, 0, logbuf, log_size);
}

bool BPFfeature::detect_helper(enum libbpf::bpf_func_id func_id,
                               enum libbpf::bpf_prog_type prog_type)
{
  // Stolen from libbpf's  bpf_probe_helper
  char logbuf[4096] = {};
  char* buf = logbuf;
  struct bpf_insn insns[] = {
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, func_id),
    BPF_EXIT_INSN(),
  };

  if (try_load(nullptr, prog_type, insns, ARRAY_SIZE(insns), 1, logbuf, 4096))
    return true;

  if (errno == EPERM)
    return false;

  // On older kernels the first byte can be zero, skip leading 0 bytes
  // $2 = "\000: (85) call 4\nR1 type=ctx expected=fp\n", '\000' <repeats 4056
  // times>
  //       ^^
  for (int i = 0; i < 8 && *buf == 0; i++, buf++)
    ;

  if (*buf == 0)
    return false;

  return (strstr(buf, "invalid func ") == nullptr) &&
         (strstr(buf, "unknown func ") == nullptr);
}

bool BPFfeature::detect_prog_type(enum libbpf::bpf_prog_type prog_type,
                                  const char* name)
{
  struct bpf_insn insns[] = { BPF_MOV64_IMM(BPF_REG_0, 0), BPF_EXIT_INSN() };
  return try_load(prog_type, insns, ARRAY_SIZE(insns), name);
}

bool BPFfeature::detect_map(enum libbpf::bpf_map_type map_type)
{
  int key_size = 4;
  int value_size = 4;
  int max_entries = 1;
  int flags = 0;
  int map_fd = 0;

  switch (map_type)
  {
    case libbpf::BPF_MAP_TYPE_STACK_TRACE:
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
      static_cast<enum ::bpf_map_type>(map_type),
      nullptr,
      key_size,
      value_size,
      max_entries,
      flags);

  if (map_fd >= 0)
    close(map_fd);

  return map_fd >= 0;
}

bool BPFfeature::has_loop(void)
{
  if (has_loop_.has_value())
    return *has_loop_;

  struct bpf_insn insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 1),
    BPF_JMP_IMM(BPF_JLT, BPF_REG_0, 4, -2),
    BPF_EXIT_INSN(),
  };

  has_loop_ = std::make_optional<bool>(
      try_load(libbpf::BPF_PROG_TYPE_TRACEPOINT, insns, ARRAY_SIZE(insns)));

  return has_loop();
}

bool BPFfeature::has_btf(void)
{
  BTF btf;
  return btf.has_data();
}

int BPFfeature::instruction_limit(void)
{
  if (insns_limit_.has_value())
    return *insns_limit_;

  struct bpf_insn insns[] = {
    BPF_LD_IMM64(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  constexpr int logsize = 4096;

  char logbuf[logsize] = {};
  bool res = try_load(nullptr,
                      libbpf::BPF_PROG_TYPE_KPROBE,
                      insns,
                      ARRAY_SIZE(insns),
                      1,
                      logbuf,
                      logsize);
  if (!res)
    insns_limit_ = std::make_optional<int>(-1);

  // Extract limit from the verifier log:
  // processed 2 insns (limit 131072), stack depth 0
  std::string log(logbuf, logsize);
  std::size_t line_start = log.find("processed 2 insns");
  if (line_start == std::string::npos)
  {
    insns_limit_ = std::make_optional<int>(-1);
    return *insns_limit_;
  }

  // Old kernels don't have the instruction limit in the verifier output
  auto begin = log.find("limit", line_start);
  if (begin == std::string::npos)
  {
    insns_limit_ = std::make_optional<int>(-1);
    return *insns_limit_;
  }

  begin += 6; /* "limit " = 6*/
  std::size_t end = log.find(")", begin);
  std::string cnt = log.substr(begin, end - begin);
  insns_limit_ = std::make_optional<int>(std::stoi(cnt));
  return *insns_limit_;
}

bool BPFfeature::has_map_batch()
{
#ifndef HAVE_LIBBPF_MAP_BATCH
  return false;

#else
  int key_size = 4;
  int value_size = 4;
  int max_entries = 10;
  int flags = 0;
  int map_fd = 0;
  int keys[10];
  int values[10];
  uint32_t count = 0;

  if (has_map_batch_.has_value())
    return *has_map_batch_;

#ifdef HAVE_BCC_CREATE_MAP
  map_fd = bcc_create_map(
#else
  map_fd = bpf_create_map(
#endif
      static_cast<enum ::bpf_map_type>(libbpf::BPF_MAP_TYPE_HASH),
      nullptr,
      key_size,
      value_size,
      max_entries,
      flags);

  if (map_fd < 0)
    return false;

  int err = bpf_map_lookup_batch(
      map_fd, nullptr, nullptr, keys, values, &count, nullptr);
  close(map_fd);

  has_map_batch_ = err >= 0;
  return *has_map_batch_;

#endif
}

bool BPFfeature::has_d_path(void)
{
  if (has_d_path_.has_value())
    return *has_d_path_;

  struct bpf_insn insns[] = {
    BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_1, 0),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
    BPF_MOV64_IMM(BPF_REG_6, 0),
    BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, 0),
    BPF_LD_IMM64(BPF_REG_3, 8),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, libbpf::BPF_FUNC_d_path),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  has_d_path_ = std::make_optional<bool>(try_load(libbpf::BPF_PROG_TYPE_TRACING,
                                                  insns,
                                                  ARRAY_SIZE(insns),
                                                  "kfunc__dentry_open"));

  return *has_d_path_;
}

bool BPFfeature::has_uprobe_refcnt()
{
  if (has_uprobe_refcnt_.has_value())
    return *has_uprobe_refcnt_;

#ifdef LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE
  struct stat sb;
  has_uprobe_refcnt_ =
      ::stat("/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset",
             &sb) == 0;
#else
  has_uprobe_refcnt_ = false;
#endif // LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE

  return *has_uprobe_refcnt_;
}

std::string BPFfeature::report(void)
{
  std::stringstream buf;
  auto to_str = [](bool f) -> auto
  {
    return f ? "yes\n" : "no\n";
  };

  buf << "Kernel helpers" << std::endl
      << "  probe_read: " << to_str(has_helper_probe_read())
      << "  probe_read_str: " << to_str(has_helper_probe_read_str())
      << "  probe_read_user: " << to_str(has_helper_probe_read_user())
      << "  probe_read_user_str: " << to_str(has_helper_probe_read_user_str())
      << "  probe_read_kernel: " << to_str(has_helper_probe_read_kernel())
      << "  probe_read_kernel_str: "
      << to_str(has_helper_probe_read_kernel_str())
      << "  get_current_cgroup_id: "
      << to_str(has_helper_get_current_cgroup_id())
      << "  send_signal: " << to_str(has_helper_send_signal())
      << "  override_return: " << to_str(has_helper_override_return())
      << "  get_boot_ns: " << to_str(has_helper_ktime_get_boot_ns())
      << "  dpath: " << to_str(has_d_path())
      << std::endl;

  buf << "Kernel features" << std::endl
      << "  Instruction limit: " << instruction_limit() << std::endl
      << "  Loop support: " << to_str(has_loop())
      << "  btf (depends on Build:libbpf): " << to_str(has_btf())
      << "  map batch (depends on Build:libbpf): " << to_str(has_map_batch())
      << "  uprobe refcount (depends on Build:bcc bpf_attach_uprobe refcount): "
      << to_str(has_uprobe_refcnt()) << std::endl;

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
      << "  perf_event: " << to_str(has_prog_perf_event())
      << "  kfunc: " << to_str(has_prog_kfunc())
      << "  iter:task: " << to_str(has_prog_iter_task())
      << "  iter:task_file: " << to_str(has_prog_iter_task_file()) << std::endl;

  return buf.str();
}

} // namespace bpftrace
