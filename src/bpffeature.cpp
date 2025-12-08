#include "bpffeature.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

#include "bpf_assembler.h"
#include "btf.h"
#include "dwarf_parser.h"
#include "symbols/kernel.h"
#include "tracefs/tracefs.h"
#include "util/strings.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

namespace bpftrace {

using symbols::KernelVersionMethod;

int BPFnofeature::parse(const char* str)
{
  for (auto feat : util::split_string(str, ',')) {
    // Remember to update bpftrace.adoc!
    if (feat == "kprobe_multi") {
      kprobe_multi_ = true;
    } else if (feat == "kprobe_session") {
      kprobe_session_ = true;
    } else if (feat == "uprobe_multi") {
      uprobe_multi_ = true;
    } else {
      return -1;
    }
  }
  return 0;
}

static bool try_load_(const char* name,
                      enum bpf_prog_type prog_type,
                      std::optional<bpf_attach_type> attach_type,
                      std::optional<unsigned int> attach_btf_id,
                      struct bpf_insn* insns,
                      size_t insns_cnt,
                      int loglevel,
                      char* logbuf,
                      size_t logbuf_size,
                      int* outfd = nullptr)
{
  const KernelVersionMethod methods[] = { KernelVersionMethod::vDSO,
                                          KernelVersionMethod::UTS,
                                          KernelVersionMethod::File };

  for (KernelVersionMethod method : methods) {
    auto version = kernel_version(method);

    if (method != KernelVersionMethod::vDSO && !version) {
      // Recent kernels don't check the version so we should try to call
      // bpf_prog_load during first iteration even if we failed to determine
      // the version. We should not do that in subsequent iterations to avoid
      // zeroing of log_buf on systems with older kernels.
      continue;
    }

    DECLARE_LIBBPF_OPTS(bpf_prog_load_opts, opts);
    opts.log_buf = logbuf;
    opts.log_size = logbuf_size;
    opts.log_level = loglevel;
    opts.kern_version = version;
    if (attach_type.has_value()) {
      opts.expected_attach_type = attach_type.value();
    }
    if (attach_btf_id.has_value())
      opts.attach_btf_id = attach_btf_id.value();

    int ret = bpf_prog_load(prog_type, name, "GPL", insns, insns_cnt, &opts);
    if (ret >= 0) {
      if (outfd)
        *outfd = ret;
      else
        close(ret);

      return true;
    }
  }

  return false;
}

bool BPFfeature::try_load(enum bpf_prog_type prog_type,
                          struct bpf_insn* insns,
                          size_t len,
                          const char* name,
                          std::optional<bpf_attach_type> attach_type,
                          int* outfd)
{
  constexpr int log_size = 4096;
  char logbuf[log_size] = {};

  std::optional<unsigned> btf_id;
  if (prog_type == BPF_PROG_TYPE_TRACING) {
    btf_id = btf_.get_btf_id(name, "vmlinux");
  }

  if (prog_type == BPF_PROG_TYPE_TRACING) {
    // List of available functions must be readable
    std::ifstream traceable_funcs(tracefs::available_filter_functions());
    if (!traceable_funcs.good())
      return false;
  }

  return try_load_(name,
                   prog_type,
                   attach_type,
                   btf_id,
                   insns,
                   len,
                   0,
                   logbuf,
                   log_size,
                   outfd);
}

bool BPFfeature::try_load_btf(const void* btf_data, size_t btf_size)
{
  constexpr int log_size = 4096;
  char log_buf[log_size] = {};
  DECLARE_LIBBPF_OPTS(bpf_btf_load_opts, btf_opts);
  btf_opts.log_buf = log_buf;
  btf_opts.log_level = 0;
  btf_opts.log_size = log_size;

  int fd = bpf_btf_load(btf_data, btf_size, &btf_opts);
  if (fd >= 0) {
    close(fd);
    return true;
  }
  return false;
}

bool BPFfeature::detect_helper(enum bpf_func_id func_id,
                               enum bpf_prog_type prog_type)
{
  // Stolen from libbpf's  bpf_probe_helper
  char logbuf[4096] = {};
  char* buf = logbuf;
  struct bpf_insn insns[] = {
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, func_id),
    BPF_EXIT_INSN(),
  };

  if (try_load_(nullptr,
                prog_type,
                std::nullopt,
                std::nullopt,
                insns,
                ARRAY_SIZE(insns),
                1,
                logbuf,
                4096))
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
         (strstr(buf, "unknown func ") == nullptr) &&
         (strstr(buf, "program of this type cannot use helper ") == nullptr);
}

// Used to test whether kfuncs are supported in a certain type of BPF program.
//
// The kernel function check_kfunc_call() will check metadata before the BPF
// Verifier. If the check fails, it will populate the log_buf with the
// corresponding error log. We can determine the support status of the kfunc
// in a BPF_PROG by matching specific logs.
bool BPFfeature::kfunc_allowed(const char* kfunc, enum bpf_prog_type prog_type)
{
  char logbuf[4096] = {};
  struct bpf_insn insn_buf[512];
  struct bpf_insn* insn = insn_buf;
  size_t insn_cnt = 0;
  int kfunc_btf_id = btf_.get_btf_id(kfunc, "vmlinux");
  if (kfunc_btf_id <= 0) {
    return false;
  }

  *insn++ = BPF_CALL_KFUNC(0, kfunc_btf_id);
  *insn++ = BPF_EXIT_INSN();

  *insn++ = BPF_CALL_KFUNC(0, kfunc_btf_id);
  *insn++ = BPF_EXIT_INSN();

  if (try_load_(nullptr,
                prog_type,
                std::nullopt,
                std::nullopt,
                insn_buf,
                insn_cnt,
                1,
                logbuf,
                4096)) {
    return true;
  } else {
    std::string errmsg = std::string("calling kernel function ") + kfunc +
                         " is not allowed";
    return strstr(logbuf, errmsg.c_str()) == nullptr;
  }
}

bool BPFfeature::has_kfunc(std::string kfunc)
{
  return btf_.get_btf_id(kfunc, "vmlinux");
}

bool BPFfeature::detect_prog_type(enum bpf_prog_type prog_type,
                                  const char* name,
                                  std::optional<bpf_attach_type> attach_type,
                                  int* outfd)
{
  struct bpf_insn insns[] = { BPF_MOV64_IMM(BPF_REG_0, 0), BPF_EXIT_INSN() };
  return try_load(
      prog_type, insns, ARRAY_SIZE(insns), name, attach_type, outfd);
}

bool BPFfeature::has_btf_func_global()
{
  if (has_btf_func_global_.has_value())
    return *has_btf_func_global_;

  /* static void x(int a) {} */
  __u32 types[] = {
    /* int */
    BTF_TYPE_INT_ENC(1, BTF_INT_SIGNED, 0, 32, 4), /* [1] */
    /* FUNC_PROTO */                               /* [2] */
    BTF_TYPE_ENC(0, BTF_INFO_ENC(BTF_KIND_FUNC_PROTO, 0, 1), 0),
    BTF_PARAM_ENC(7, 1),
    /* FUNC x BTF_FUNC_GLOBAL */ /* [3] */
    BTF_TYPE_ENC(5, BTF_INFO_ENC(BTF_KIND_FUNC, 0, BTF_FUNC_GLOBAL), 2),
  };

  has_btf_func_global_ = std::make_optional<bool>(
      try_load_btf(types, sizeof(types)));
  return *has_btf_func_global_;
}

int BPFfeature::instruction_limit()
{
  if (insns_limit_.has_value())
    return *insns_limit_;

  struct bpf_insn insns[] = {
    BPF_LD_IMM64(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  constexpr int logsize = 4096;

  char logbuf[logsize] = {};
  bool res = try_load_(nullptr,
                       BPF_PROG_TYPE_KPROBE,
                       std::nullopt,
                       std::nullopt,
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
  if (line_start == std::string::npos) {
    insns_limit_ = std::make_optional<int>(-1);
    return *insns_limit_;
  }

  // Old kernels don't have the instruction limit in the verifier output
  auto begin = log.find("limit", line_start);
  if (begin == std::string::npos) {
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

  DECLARE_LIBBPF_OPTS(bpf_map_create_opts, opts);
  opts.map_flags = flags;
  map_fd = bpf_map_create(
      BPF_MAP_TYPE_HASH, nullptr, key_size, value_size, max_entries, &opts);

  if (map_fd < 0)
    return false;

  int err = bpf_map_lookup_batch(
      map_fd, nullptr, nullptr, keys, values, &count, nullptr);
  close(map_fd);

  has_map_batch_ = err >= 0;
  return *has_map_batch_;
}

bool BPFfeature::has_d_path()
{
  if (has_d_path_.has_value())
    return *has_d_path_;

  struct bpf_insn insns[] = {
    BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
    BPF_MOV64_IMM(BPF_REG_6, 0),
    BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, 0),
    BPF_LD_IMM64(BPF_REG_3, 8),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_d_path),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  has_d_path_ = std::make_optional<bool>(try_load(BPF_PROG_TYPE_TRACING,
                                                  insns,
                                                  ARRAY_SIZE(insns),
                                                  "dentry_open",
                                                  BPF_TRACE_FENTRY));

  return *has_d_path_;
}

bool try_create_link(bpf_prog_type prog_type,
                     const std::string_view prog_name,
                     bpf_attach_type expected_attach_type,
                     const bpf_link_create_opts& link_opts,
                     std::optional<int> expected_err)
{
  bool result = false;

  DECLARE_LIBBPF_OPTS(bpf_prog_load_opts, load_opts);
  load_opts.expected_attach_type = expected_attach_type;

  struct bpf_insn insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  int progfd = bpf_prog_load(prog_type,
                             prog_name.data(),
                             "GPL",
                             reinterpret_cast<struct bpf_insn*>(insns),
                             ARRAY_SIZE(insns),
                             &load_opts);

  if (progfd < 0)
    return false;

  int linkfd = bpf_link_create(progfd, 0, expected_attach_type, &link_opts);

  result = expected_err.has_value() ? linkfd < 0 && -errno == *expected_err
                                    : linkfd >= 0;

  if (linkfd >= 0) {
    close(linkfd);
  }
  close(progfd);

  return result;
}

bool BPFfeature::has_kprobe_multi()
{
  if (has_kprobe_multi_.has_value())
    return *has_kprobe_multi_;

  if (no_feature_.kprobe_multi_) {
    has_kprobe_multi_ = false;
    return *has_kprobe_multi_;
  }

  const char* sym = "ksys_read";

  DECLARE_LIBBPF_OPTS(bpf_link_create_opts, link_opts);
  link_opts.kprobe_multi.syms = &sym;
  link_opts.kprobe_multi.cnt = 1;

  has_kprobe_multi_ = try_create_link(BPF_PROG_TYPE_KPROBE,
                                      sym,
                                      BPF_TRACE_KPROBE_MULTI,
                                      link_opts,
                                      std::nullopt);
  return *has_kprobe_multi_;
}

bool BPFfeature::has_kprobe_session()
{
  if (has_kprobe_session_.has_value())
    return *has_kprobe_session_;

  if (no_feature_.kprobe_session_) {
    has_kprobe_session_ = false;
    return *has_kprobe_session_;
  }

  const char* sym = "ksys_read";

  DECLARE_LIBBPF_OPTS(bpf_link_create_opts, link_opts);
  link_opts.kprobe_multi.syms = &sym;
  link_opts.kprobe_multi.cnt = 1;

  has_kprobe_session_ = try_create_link(BPF_PROG_TYPE_KPROBE,
                                        sym,
                                        BPF_TRACE_KPROBE_SESSION,
                                        link_opts,
                                        std::nullopt);
  return *has_kprobe_session_;
}

bool BPFfeature::has_uprobe_multi()
{
  if (has_uprobe_multi_.has_value())
    return *has_uprobe_multi_;

  if (no_feature_.uprobe_multi_) {
    has_uprobe_multi_ = false;
    return *has_uprobe_multi_;
  }

  DECLARE_LIBBPF_OPTS(bpf_link_create_opts, link_opts);
  const unsigned long offset = 0;
  link_opts.uprobe_multi.path = "/";
  link_opts.uprobe_multi.offsets = &offset;
  link_opts.uprobe_multi.cnt = 1;

  has_uprobe_multi_ = try_create_link(BPF_PROG_TYPE_KPROBE,
                                      "uprobe_multi",
                                      BPF_TRACE_UPROBE_MULTI,
                                      link_opts,
                                      -EBADF);
  return *has_uprobe_multi_;
}

static void tabulate(std::stringstream& buf,
                     std::vector<std::pair<std::string, std::string>>& data)
{
  size_t len = data.size();
  constexpr int width = 35;
  for (size_t i = 0; i < len; i += 2) {
    buf << std::setw(width) << std::left
        << "  " + data[i].first + ": " + data[i].second << std::setw(width);
    if (i + 1 < len) {
      buf << data[i + 1].first + ": " + data[i + 1].second << std::endl;
    } else {
      buf << std::endl;
    }
  }
}

std::string BPFfeature::report()
{
  std::stringstream buf;

  auto to_str = [](bool f) -> std::string { return f ? "yes" : "no"; };

  std::vector<std::pair<std::string, std::string>> helpers = {
    { "dpath", to_str(has_d_path()) },
    { "get_tai_ns", to_str(has_helper_ktime_get_tai_ns()) },
    { "get_func_ip", to_str(has_helper_get_func_ip()) },
    { "lookup_percpu_elem", to_str(has_helper_map_lookup_percpu_elem()) },
  };

  std::vector<std::pair<std::string, std::string>> features = {
    { "Instruction limit", std::to_string(instruction_limit()) },
    { "module btf", to_str(btf_.has_module_btf()) },
    { "map batch", to_str(has_map_batch()) },
  };

  std::vector<std::pair<std::string, std::string>> probe_types = {
    { "kprobe_multi", to_str(has_kprobe_multi()) },
    { "uprobe_multi", to_str(has_uprobe_multi()) },
    { "kprobe_session", to_str(has_kprobe_session()) },
    { "iter", to_str(has_iter("task")) }
  };

  buf << "Kernel helpers" << std::endl;
  tabulate(buf, helpers);
  buf << std::endl;

  buf << "Kernel features" << std::endl;
  tabulate(buf, features);
  buf << std::endl;

  buf << "Probe types" << std::endl;
  tabulate(buf, probe_types);
  buf << std::endl;

  return buf.str();
}

bool BPFfeature::has_prog_fentry()
{
  if (!has_prog_fentry_.has_value()) {
    int progfd;
    if (!detect_prog_type(
            BPF_PROG_TYPE_TRACING, "sched_fork", BPF_TRACE_FENTRY, &progfd))
      goto out_false;
    int tracing_fd = bpf_raw_tracepoint_open(nullptr, progfd);
    close(progfd);
    if (tracing_fd < 0)
      goto out_false;
    close(tracing_fd);
    has_prog_fentry_ = std::make_optional<bool>(true);
  }
  return *(has_prog_fentry_);
out_false:
  has_prog_fentry_ = std::make_optional<bool>(false);
  return *(has_prog_fentry_);
}

bool BPFfeature::has_iter(std::string name)
{
  auto tracing_name = "bpf_iter_" + name;
  return detect_prog_type(BPF_PROG_TYPE_TRACING,
                          tracing_name.c_str(),
                          BPF_TRACE_ITER);
}

} // namespace bpftrace
