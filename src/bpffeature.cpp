#include "bpffeature.h"

#include <bcc/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

#include "btf.h"
#include "debugfs.h"
#include "probe_matcher.h"
#include "tracefs.h"
#include "utils.h"

namespace bpftrace {

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

int BPFnofeature::parse(const char* str)
{
  for (auto feat : split_string(str, ',')) {
    if (feat == "kprobe_multi") {
      kprobe_multi_ = true;
    } else if (feat == "uprobe_multi") {
      uprobe_multi_ = true;
    } else {
      return -1;
    }
  }
  return 0;
}

static bool try_load_(const char* name,
                      enum libbpf::bpf_prog_type prog_type,
                      std::optional<libbpf::bpf_attach_type> attach_type,
                      std::optional<unsigned int> attach_btf_id,
                      struct bpf_insn* insns,
                      size_t insns_cnt,
                      int loglevel,
                      char* logbuf,
                      size_t logbuf_size,
                      int* outfd = nullptr)
{
  const KernelVersionMethod methods[] = { vDSO, UTS, File };

  for (KernelVersionMethod method : methods) {
    auto version = kernel_version(method);

    if (method != vDSO && !version) {
      // Recent kernels don't check the version so we should try to call
      // bpf_prog_load during first iteration even if we failed to determine
      // the version. We should not do that in subsequent iterations to avoid
      // zeroing of log_buf on systems with older kernels.
      continue;
    }

    BPFTRACE_LIBBPF_OPTS(bpf_prog_load_opts, opts);
    opts.log_buf = logbuf;
    opts.log_size = logbuf_size;
    opts.log_level = loglevel;
    opts.kern_version = version;
    if (attach_type.has_value()) {
      opts.expected_attach_type = static_cast<::bpf_attach_type>(
          attach_type.value());
    }
    if (attach_btf_id.has_value())
      opts.attach_btf_id = attach_btf_id.value();

    int ret = bpf_prog_load(static_cast<::bpf_prog_type>(prog_type),
                            name,
                            "GPL",
                            insns,
                            insns_cnt,
                            &opts);
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

bool BPFfeature::try_load(enum libbpf::bpf_prog_type prog_type,
                          struct bpf_insn* insns,
                          size_t len,
                          const char* name,
                          std::optional<libbpf::bpf_attach_type> attach_type,
                          int* outfd)
{
  constexpr int log_size = 4096;
  char logbuf[log_size] = {};

  std::optional<unsigned> btf_id;
  if (prog_type == libbpf::BPF_PROG_TYPE_TRACING && has_btf()) {
    btf_id = btf_.get_btf_id(name, "vmlinux");
  }

  if (prog_type == libbpf::BPF_PROG_TYPE_TRACING) {
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
  BPFTRACE_LIBBPF_OPTS(bpf_btf_load_opts,
                       btf_opts,
                       .log_buf = log_buf,
                       .log_level = 0,
                       .log_size = log_size, );

  int fd = bpf_btf_load(btf_data, btf_size, &btf_opts);
  if (fd >= 0) {
    close(fd);
    return true;
  }
  return false;
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

bool BPFfeature::detect_prog_type(
    enum libbpf::bpf_prog_type prog_type,
    const char* name,
    std::optional<libbpf::bpf_attach_type> attach_type,
    int* outfd)
{
  struct bpf_insn insns[] = { BPF_MOV64_IMM(BPF_REG_0, 0), BPF_EXIT_INSN() };
  return try_load(
      prog_type, insns, ARRAY_SIZE(insns), name, attach_type, outfd);
}

bool BPFfeature::detect_map(enum libbpf::bpf_map_type map_type)
{
  int key_size = 4;
  int value_size = 4;
  int max_entries = 1;
  int flags = 0;
  int map_fd = 0;

  switch (map_type) {
    case libbpf::BPF_MAP_TYPE_STACK_TRACE:
      value_size = 8;
      break;
    case libbpf::BPF_MAP_TYPE_RINGBUF:
      // values from libbpf/src/libbpf_probes.c
      // default pagesize 4KB
      // default perf_rb_pages 64
      key_size = 0;
      value_size = 0;
      max_entries = sysconf(_SC_PAGE_SIZE);
      break;
    default:
      break;
  }

  BPFTRACE_LIBBPF_OPTS(bpf_map_create_opts, opts);
  opts.map_flags = flags;
  map_fd = bpf_map_create(static_cast<enum ::bpf_map_type>(map_type),
                          nullptr,
                          key_size,
                          value_size,
                          max_entries,
                          &opts);

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
  return btf_.has_data();
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
  bool res = try_load_(nullptr,
                       libbpf::BPF_PROG_TYPE_KPROBE,
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

  BPFTRACE_LIBBPF_OPTS(bpf_map_create_opts, opts);
  opts.map_flags = flags;
  map_fd = bpf_map_create(static_cast<enum ::bpf_map_type>(
                              libbpf::BPF_MAP_TYPE_HASH),
                          nullptr,
                          key_size,
                          value_size,
                          max_entries,
                          &opts);

  if (map_fd < 0)
    return false;

  int err = bpf_map_lookup_batch(
      map_fd, nullptr, nullptr, keys, values, &count, nullptr);
  close(map_fd);

  has_map_batch_ = err >= 0;
  return *has_map_batch_;
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
                                                  "dentry_open",
                                                  libbpf::BPF_TRACE_FENTRY));

  return *has_d_path_;
}

bool BPFfeature::has_uprobe_refcnt()
{
  if (has_uprobe_refcnt_.has_value())
    return *has_uprobe_refcnt_;

  std::error_code ec;
  std_filesystem::path path{
    "/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset"
  };
  has_uprobe_refcnt_ = std_filesystem::exists(path, ec);

  return *has_uprobe_refcnt_;
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
  BPFTRACE_LIBBPF_OPTS(bpf_link_create_opts, link_opts);
  int progfd, linkfd = -1;

  struct bpf_insn insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  link_opts.kprobe_multi.syms = &sym;
  link_opts.kprobe_multi.cnt = 1;

  BPFTRACE_LIBBPF_OPTS(bpf_prog_load_opts, load_opts);
  load_opts.expected_attach_type = static_cast<enum ::bpf_attach_type>(
      libbpf::BPF_TRACE_KPROBE_MULTI);

  progfd = bpf_prog_load(static_cast<::bpf_prog_type>(
                             libbpf::BPF_PROG_TYPE_KPROBE),
                         sym,
                         "GPL",
                         reinterpret_cast<struct bpf_insn*>(insns),
                         ARRAY_SIZE(insns),
                         &load_opts);

  if (progfd >= 0) {
    linkfd = bpf_link_create(progfd,
                             0,
                             static_cast<enum ::bpf_attach_type>(
                                 libbpf::BPF_TRACE_KPROBE_MULTI),
                             &link_opts);
  }

  has_kprobe_multi_ = linkfd >= 0;

  if (linkfd >= 0) {
    close(linkfd);
  }
  if (progfd >= 0) {
    close(progfd);
  }
  return *has_kprobe_multi_;
}

bool BPFfeature::has_uprobe_multi()
{
  if (has_uprobe_multi_.has_value())
    return *has_uprobe_multi_;

#if defined(HAVE_LIBBPF_UPROBE_MULTI)
  if (no_feature_.uprobe_multi_) {
    has_uprobe_multi_ = false;
    return *has_uprobe_multi_;
  }

  BPFTRACE_LIBBPF_OPTS(
      bpf_prog_load_opts,
      load_opts,
      .expected_attach_type = static_cast<enum ::bpf_attach_type>(
          libbpf::BPF_TRACE_UPROBE_MULTI), );

  int err = 0, progfd, linkfd = -1;

  struct bpf_insn insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  progfd = bpf_prog_load(static_cast<::bpf_prog_type>(
                             libbpf::BPF_PROG_TYPE_KPROBE),
                         "uprobe_multi",
                         "GPL",
                         reinterpret_cast<struct bpf_insn*>(insns),
                         ARRAY_SIZE(insns),
                         &load_opts);

  if (progfd >= 0) {
    BPFTRACE_LIBBPF_OPTS(bpf_link_create_opts, link_opts);
    const unsigned long offset = 0;

    link_opts.uprobe_multi.path = "/";
    link_opts.uprobe_multi.offsets = &offset;
    link_opts.uprobe_multi.cnt = 1;

    linkfd = bpf_link_create(progfd,
                             0,
                             static_cast<enum ::bpf_attach_type>(
                                 libbpf::BPF_TRACE_UPROBE_MULTI),
                             &link_opts);
    err = -errno;
  }

  has_uprobe_multi_ = linkfd < 0 && err == -EBADF;

  if (linkfd >= 0) {
    close(linkfd);
  }
  if (progfd >= 0) {
    close(progfd);
  }
#else
  has_uprobe_multi_ = false;
#endif // HAVE_LIBBPF_UPROBE_MULTI
  return *has_uprobe_multi_;
}

bool BPFfeature::has_skb_output(void)
{
  if (!has_kfunc())
    return false;

  if (has_skb_output_.has_value())
    return *has_skb_output_;

  int map_fd = 0;

  BPFTRACE_LIBBPF_OPTS(bpf_map_create_opts, opts);
  opts.map_flags = 0;
  map_fd = bpf_map_create(static_cast<enum ::bpf_map_type>(
                              libbpf::BPF_MAP_TYPE_PERF_EVENT_ARRAY),
                          "rb",
                          sizeof(int),
                          sizeof(int),
                          1,
                          &opts);

  if (map_fd < 0)
    return false;

  struct bpf_insn insns[] = {
    BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_1, 0),
    BPF_LD_MAP_FD(BPF_REG_2, map_fd),
    BPF_MOV64_IMM(BPF_REG_3, 0),
    BPF_MOV64_REG(BPF_REG_4, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, -8),
    BPF_MOV64_IMM(BPF_REG_6, 0),
    BPF_STX_MEM(BPF_DW, BPF_REG_4, BPF_REG_6, 0),
    BPF_LD_IMM64(BPF_REG_5, 8),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, libbpf::BPF_FUNC_skb_output),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  has_skb_output_ = std::make_optional<bool>(
      try_load(libbpf::BPF_PROG_TYPE_TRACING,
               insns,
               ARRAY_SIZE(insns),
               "__kfree_skb",
               libbpf::BPF_TRACE_FENTRY));

  close(map_fd);
  return *has_skb_output_;
}

bool BPFfeature::has_raw_tp_special()
{
  if (has_raw_tp_special_.has_value())
    return *has_raw_tp_special_;

  struct bpf_insn insns[] = { BPF_MOV64_IMM(BPF_REG_0, 0), BPF_EXIT_INSN() };
  int fd;

  // Check that we can both load BPF_PROG_TYPE_RAW_TRACEPOINT and that
  // BPF_PROG_RUN is supported by the kernel
  if (try_load(libbpf::BPF_PROG_TYPE_RAW_TRACEPOINT,
               insns,
               ARRAY_SIZE(insns),
               nullptr,
               std::nullopt,
               &fd)) {
    struct bpf_test_run_opts opts = {};
    opts.sz = sizeof(opts);
    has_raw_tp_special_ = !::bpf_prog_test_run_opts(fd, &opts);
    close(fd);
  } else
    has_raw_tp_special_ = false;

  return *has_raw_tp_special_;
}

std::string BPFfeature::report(void)
{
  std::stringstream buf;
  auto to_str = [](bool f) -> auto { return f ? "yes\n" : "no\n"; };

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
      << "  skboutput: " << to_str(has_skb_output())
      << "  get_tai_ns: " << to_str(has_helper_ktime_get_tai_ns())
      << "  get_func_ip: " << to_str(has_helper_get_func_ip())
      << "  jiffies64: " << to_str(has_helper_jiffies64())
      << "  for_each_map_elem: " << to_str(has_helper_for_each_map_elem())

      << std::endl;

  buf << "Kernel features" << std::endl
      << "  Instruction limit: " << instruction_limit() << std::endl
      << "  Loop support: " << to_str(has_loop())
      << "  btf: " << to_str(has_btf())
      << "  module btf: " << to_str(has_module_btf())
      << "  map batch: " << to_str(has_map_batch())
      << "  uprobe refcount (depends on Build:bcc bpf_attach_uprobe refcount): "
      << to_str(has_uprobe_refcnt()) << std::endl;

  buf << "Map types" << std::endl
      << "  hash: " << to_str(has_map_hash())
      << "  percpu hash: " << to_str(has_map_percpu_hash())
      << "  array: " << to_str(has_map_array())
      << "  percpu array: " << to_str(has_map_percpu_array())
      << "  stack_trace: " << to_str(has_map_stack_trace())
      << "  perf_event_array: " << to_str(has_map_perf_event_array())
      << "  ringbuf: " << to_str(has_map_ringbuf()) << std::endl;

  buf << "Probe types" << std::endl
      << "  kprobe: " << to_str(has_prog_kprobe())
      << "  tracepoint: " << to_str(has_prog_tracepoint())
      << "  perf_event: " << to_str(has_prog_perf_event())
      << "  kfunc: " << to_str(has_kfunc())
      << "  kprobe_multi: " << to_str(has_kprobe_multi())
      << "  uprobe_multi: " << to_str(has_uprobe_multi())
      << "  raw_tp_special: " << to_str(has_raw_tp_special())
      << "  iter: " << to_str(has_iter("task")) << std::endl;

  return buf.str();
}

bool BPFfeature::has_prog_kfunc()
{
  if (!has_prog_kfunc_.has_value()) {
    int progfd;
    if (!detect_prog_type(libbpf::BPF_PROG_TYPE_TRACING,
                          "sched_fork",
                          libbpf::BPF_TRACE_FENTRY,
                          &progfd))
      goto out_false;
    int tracing_fd = bpf_raw_tracepoint_open(nullptr, progfd);
    close(progfd);
    if (tracing_fd < 0)
      goto out_false;
    close(tracing_fd);
    has_prog_kfunc_ = std::make_optional<bool>(true);
  }
  return *(has_prog_kfunc_);
out_false:
  has_prog_kfunc_ = std::make_optional<bool>(false);
  return *(has_prog_kfunc_);
}

bool BPFfeature::has_kfunc()
{
  return has_prog_kfunc() && btf_.has_data();
}

bool BPFfeature::has_module_btf()
{
  if (has_module_btf_.has_value())
    return *has_module_btf_;

  char name[64];
  struct bpf_btf_info info = {};
  info.name = (__u64)name;
  info.name_len = sizeof(name);
  __u32 id = 0, info_len = sizeof(info);
  int err = 0, fd = -1;

  err = bpf_btf_get_next_id(id, &id);
  if (err)
    goto not_support;

  fd = bpf_btf_get_fd_by_id(id);
  if (fd < 0)
    goto not_support;

  err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
  close(fd);
  if (err)
    goto not_support;

  has_module_btf_ = true;
  return *has_module_btf_;

not_support:
  has_module_btf_ = false;
  return *has_module_btf_;
}

bool BPFfeature::has_iter(std::string name)
{
  auto tracing_name = "bpf_iter_" + name;
  return detect_prog_type(libbpf::BPF_PROG_TYPE_TRACING,
                          tracing_name.c_str(),
                          libbpf::BPF_TRACE_ITER);
}

} // namespace bpftrace
