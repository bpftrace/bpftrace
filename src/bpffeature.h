#pragma once

#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <optional>
#include <string>

#include "btf.h"
#include "kfuncs.h"

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
          detect_helper(BPF_FUNC_##name, (progtype)));                         \
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

class BPFfeature;

class BPFnofeature {
public:
  BPFnofeature() = default;
  int parse(const char* str);

protected:
  bool kprobe_multi_{ false };
  bool kprobe_session_{ false };
  bool uprobe_multi_{ false };
  friend class BPFfeature;
};

class BPFfeature {
public:
  BPFfeature(BPFnofeature& no_feature, BTF& btf)
      : no_feature_(no_feature), btf_(btf)
  {
  }
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
  bool has_btf();
  bool has_btf_func_global();
  bool has_map_batch();
  bool has_d_path();
  bool has_kprobe_multi();
  bool has_kprobe_session();
  bool has_uprobe_multi();
  bool has_skb_output();
  bool has_prog_fentry();
  // These are virtual so they can be overridden in tests by the mock
  virtual bool has_fentry();
  virtual bool has_kernel_func(Kfunc kfunc);
  virtual bool has_iter(std::string name);

  std::string report();

  DEFINE_MAP_TEST(array, BPF_MAP_TYPE_ARRAY);
  DEFINE_MAP_TEST(hash, BPF_MAP_TYPE_HASH);
  DEFINE_MAP_TEST(percpu_array, BPF_MAP_TYPE_PERCPU_ARRAY);
  DEFINE_MAP_TEST(stack_trace, BPF_MAP_TYPE_STACK_TRACE);
  DEFINE_MAP_TEST(ringbuf, BPF_MAP_TYPE_RINGBUF);
  DEFINE_HELPER_TEST(send_signal, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(override_return, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(get_current_cgroup_id, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_str, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_user, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_kernel, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_user_str, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_kernel_str, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(ktime_get_boot_ns, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(ktime_get_tai_ns, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(get_func_ip, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(jiffies64, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(for_each_map_elem, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(get_ns_current_pid_tgid, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(map_lookup_percpu_elem, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(loop, BPF_PROG_TYPE_KPROBE); // Added in 5.13.
  DEFINE_PROG_TEST(kprobe, BPF_PROG_TYPE_KPROBE);
  DEFINE_PROG_TEST(tracepoint, BPF_PROG_TYPE_TRACEPOINT);
  DEFINE_PROG_TEST(perf_event, BPF_PROG_TYPE_PERF_EVENT);

protected:
  std::optional<bool> has_d_path_;
  std::optional<int> insns_limit_;
  std::optional<bool> has_map_batch_;
  std::optional<bool> has_kprobe_multi_;
  std::optional<bool> has_kprobe_session_;
  std::optional<bool> has_uprobe_multi_;
  std::optional<bool> has_skb_output_;
  std::optional<bool> has_prog_fentry_;
  std::optional<bool> has_btf_func_global_;
  std::optional<bool> has_kernel_dwarf_;

  std::unordered_map<Kfunc, bool> available_kernel_funcs_;

private:
  bool detect_map(bpf_map_type map_type);
  bool detect_helper(bpf_func_id func_id, bpf_prog_type prog_type);
  bool detect_prog_type(bpf_prog_type prog_type,
                        const char* name,
                        std::optional<bpf_attach_type> attach_type,
                        int* outfd = nullptr);

  bool try_load(bpf_prog_type prog_type,
                struct bpf_insn* insns,
                size_t len,
                const char* name = nullptr,
                std::optional<bpf_attach_type> attach_type = std::nullopt,
                int* outfd = nullptr);
  bool try_load_btf(const void* btf_data, size_t btf_size);

  BPFnofeature no_feature_;
  BTF& btf_;
};

#undef DEFINE_PROG_TEST
#undef DEFINE_MAP_TEST
#undef DEFINE_HELPER_TEST
} // namespace bpftrace
