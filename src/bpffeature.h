#pragma once

#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <optional>
#include <string>

#include "btf.h"

namespace bpftrace {

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
  bool has_btf_func_global();
  bool has_map_batch();
  bool has_d_path();
  bool has_kprobe_multi();
  bool has_kprobe_session();
  bool has_uprobe_multi();
  bool has_prog_fentry();
  virtual bool has_iter(std::string name);

  std::string report();

  DEFINE_HELPER_TEST(ktime_get_tai_ns, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(map_lookup_percpu_elem, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(loop, BPF_PROG_TYPE_KPROBE); // Added in 5.17.

  bool has_kfunc(std::string kfunc);
  bool kfunc_allowed(const char* kfunc, enum bpf_prog_type prog_type);

protected:
  std::optional<bool> has_d_path_;
  std::optional<int> insns_limit_;
  std::optional<bool> has_map_batch_;
  std::optional<bool> has_kprobe_multi_;
  std::optional<bool> has_kprobe_session_;
  std::optional<bool> has_uprobe_multi_;
  std::optional<bool> has_prog_fentry_;
  std::optional<bool> has_btf_func_global_;
  std::optional<bool> has_kernel_dwarf_;

private:
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

#undef DEFINE_HELPER_TEST
} // namespace bpftrace
