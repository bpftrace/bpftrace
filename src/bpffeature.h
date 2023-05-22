#pragma once

#include "btf.h"
#include <memory>
#include <optional>
#include <string>

#include <linux/bpf.h>

namespace libbpf {
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace {

#define DEFINE_MAP_TEST(var, maptype)                                          \
protected:                                                                     \
  std::optional<bool> map_##var##_;                                            \
                                                                               \
public:                                                                        \
  bool has_map_##var(void)                                                     \
  {                                                                            \
    if (!map_##var##_.has_value())                                             \
      map_##var##_ = std::make_optional<bool>(detect_map((maptype)));          \
    return *(map_##var##_);                                                    \
  }

#define DEFINE_HELPER_TEST(name, progtype)                                     \
protected:                                                                     \
  std::optional<bool> has_##name##_;                                           \
                                                                               \
public:                                                                        \
  bool has_helper_##name(void)                                                 \
  {                                                                            \
    if (!has_##name##_.has_value())                                            \
      has_##name##_ = std::make_optional<bool>(                                \
          detect_helper(libbpf::BPF_FUNC_##name, (progtype)));                 \
    return *(has_##name##_);                                                   \
  }

#define __DEFINE_PROG_TEST(var, progtype, name, attach_type)                   \
protected:                                                                     \
  std::optional<bool> prog_##var##_;                                           \
                                                                               \
public:                                                                        \
  bool has_prog_##var(void)                                                    \
  {                                                                            \
    if (!prog_##var##_.has_value())                                            \
      prog_##var##_ = std::make_optional<bool>(                                \
          detect_prog_type((progtype), (name), (attach_type)));                \
    return *(prog_##var##_);                                                   \
  }

#define DEFINE_PROG_TEST(var, progtype)                                        \
  __DEFINE_PROG_TEST(var, progtype, NULL, std::nullopt)

#define DEFINE_PROG_TEST_FUNC(var, progtype, name, attach_type)                \
  __DEFINE_PROG_TEST(var, progtype, name, attach_type)

class BPFfeature
{
public:
  BPFfeature() = default;
  virtual ~BPFfeature() = default;

  // Due to the unique_ptr usage the generated copy constructor & assignment
  // don't work. Move works but doesn't make sense as the `has_*` functions
  // will just reassign the unique_ptr.
  // A single bpffeature should be constructed in main() and passed around,
  // marking these as deleted to avoid accidentally copying/moving it.
  BPFfeature(const BPFfeature&) = delete;
  BPFfeature& operator=(const BPFfeature&) = delete;
  BPFfeature(BPFfeature&&) = delete;
  BPFfeature& operator=(BPFfeature&&) = delete;

  int instruction_limit();
  bool has_loop();
  bool has_btf();
  bool has_map_batch();
  bool has_d_path();
  bool has_uprobe_refcnt();
  bool has_kprobe_multi();
  bool has_kfunc();
  bool has_skb_output();
  bool has_raw_tp_special();
  bool has_prog_kfunc();
  bool has_module_btf();

  std::string report(void);

  DEFINE_MAP_TEST(array, libbpf::BPF_MAP_TYPE_ARRAY);
  DEFINE_MAP_TEST(hash, libbpf::BPF_MAP_TYPE_HASH);
  DEFINE_MAP_TEST(percpu_array, libbpf::BPF_MAP_TYPE_PERCPU_ARRAY);
  DEFINE_MAP_TEST(percpu_hash, libbpf::BPF_MAP_TYPE_ARRAY);
  DEFINE_MAP_TEST(stack_trace, libbpf::BPF_MAP_TYPE_STACK_TRACE);
  DEFINE_MAP_TEST(perf_event_array, libbpf::BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  DEFINE_MAP_TEST(ringbuf, libbpf::BPF_MAP_TYPE_RINGBUF);
  DEFINE_HELPER_TEST(send_signal, libbpf::BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(override_return, libbpf::BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(get_current_cgroup_id, libbpf::BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read, libbpf::BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_str, libbpf::BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_user, libbpf::BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_kernel, libbpf::BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_user_str, libbpf::BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_kernel_str, libbpf::BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(ktime_get_boot_ns, libbpf::BPF_PROG_TYPE_KPROBE);
  DEFINE_PROG_TEST(kprobe, libbpf::BPF_PROG_TYPE_KPROBE);
  DEFINE_PROG_TEST(tracepoint, libbpf::BPF_PROG_TYPE_TRACEPOINT);
  DEFINE_PROG_TEST(perf_event, libbpf::BPF_PROG_TYPE_PERF_EVENT);
  DEFINE_PROG_TEST_FUNC(iter_task,
                        libbpf::BPF_PROG_TYPE_TRACING,
                        "bpf_iter_task",
                        libbpf::BPF_TRACE_ITER);
  DEFINE_PROG_TEST_FUNC(iter_task_file,
                        libbpf::BPF_PROG_TYPE_TRACING,
                        "bpf_iter_task_file",
                        libbpf::BPF_TRACE_ITER);
  DEFINE_PROG_TEST_FUNC(iter_task_vma,
                        libbpf::BPF_PROG_TYPE_TRACING,
                        "bpf_iter_task_vma",
                        libbpf::BPF_TRACE_ITER);

protected:
  std::optional<bool> has_loop_;
  std::optional<bool> has_d_path_;
  std::optional<int> insns_limit_;
  std::optional<bool> has_map_batch_;
  std::optional<bool> has_uprobe_refcnt_;
  std::optional<bool> has_kprobe_multi_;
  std::optional<bool> has_skb_output_;
  std::optional<bool> has_raw_tp_special_;
  std::optional<bool> has_prog_kfunc_;
  std::optional<bool> has_module_btf_;

private:
  bool detect_map(libbpf::bpf_map_type map_type);
  bool detect_helper(libbpf::bpf_func_id func_id,
                     libbpf::bpf_prog_type prog_type);
  bool detect_prog_type(libbpf::bpf_prog_type prog_type,
                        const char* name,
                        std::optional<libbpf::bpf_attach_type> attach_type,
                        int* outfd = nullptr);

  bool try_load(
      libbpf::bpf_prog_type prog_type,
      struct bpf_insn* insns,
      size_t len,
      const char* name = nullptr,
      std::optional<libbpf::bpf_attach_type> attach_type = std::nullopt,
      int* outfd = nullptr);

  BTF btf_ = BTF({ "vmlinux" });
};

#undef DEFINE_PROG_TEST
#undef DEFINE_MAP_TEST
#undef DEFINE_HELPER_TEST
} // namespace bpftrace
