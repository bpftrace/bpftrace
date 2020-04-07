#pragma once

#include <bcc/libbpf.h>
#include <memory>
#include <string>

namespace libbpf {
#undef __BPF_FUNC_MAPPER
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace {

#define DEFINE_MAP_TEST(var, maptype)                                          \
protected:                                                                     \
  std::unique_ptr<bool> map_##var##_;                                          \
                                                                               \
public:                                                                        \
  bool has_map_##var(void)                                                     \
  {                                                                            \
    if (!map_##var##_)                                                         \
      map_##var##_ = std::make_unique<bool>(detect_map((maptype)));            \
    return *(map_##var##_).get();                                              \
  }

#define DEFINE_HELPER_TEST(name, progtype)                                     \
protected:                                                                     \
  std::unique_ptr<bool> has_##name##_;                                         \
                                                                               \
public:                                                                        \
  bool has_helper_##name(void)                                                 \
  {                                                                            \
    if (!has_##name##_)                                                        \
      has_##name##_ = std::make_unique<bool>(                                  \
          detect_helper(libbpf::BPF_FUNC_##name, (progtype)));                 \
    return *(has_##name##_).get();                                             \
  }

#define DEFINE_PROG_TEST(var, progtype)                                        \
protected:                                                                     \
  std::unique_ptr<bool> prog_##var##_;                                         \
                                                                               \
public:                                                                        \
  bool has_prog_##var(void)                                                    \
  {                                                                            \
    if (!prog_##var##_)                                                        \
      prog_##var##_ = std::make_unique<bool>(detect_prog_type((progtype)));    \
    return *(prog_##var##_).get();                                             \
  }

class BPFfeature
{
public:
  BPFfeature() = default;
  virtual ~BPFfeature() = default;

  // Due to the unique_ptr usage the generated copy constructor & assignment
  // don't work. Move works but doesn't make sense as the `has_*` functions
  // will just reassign the unique_ptr.
  // A single bpffeature should be constructed in main() and passed around,
  // making these as deleted to avoid accidentally copying/moving it.
  BPFfeature(const BPFfeature&) = delete;
  BPFfeature& operator=(const BPFfeature&) = delete;
  BPFfeature(BPFfeature&&) = delete;
  BPFfeature& operator=(BPFfeature&&) = delete;

  int instruction_limit();
  bool has_loop();

  std::string report(void);

  DEFINE_MAP_TEST(array, BPF_MAP_TYPE_ARRAY);
  DEFINE_MAP_TEST(hash, BPF_MAP_TYPE_HASH);
  DEFINE_MAP_TEST(percpu_array, BPF_MAP_TYPE_PERCPU_ARRAY);
  DEFINE_MAP_TEST(percpu_hash, BPF_MAP_TYPE_ARRAY);
  DEFINE_MAP_TEST(stack_trace, BPF_MAP_TYPE_STACK_TRACE);
  DEFINE_MAP_TEST(perf_event_array, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  DEFINE_HELPER_TEST(send_signal, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(override_return, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(get_current_cgroup_id, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_str, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_user, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_kernel, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_user_str, BPF_PROG_TYPE_KPROBE);
  DEFINE_HELPER_TEST(probe_read_kernel_str, BPF_PROG_TYPE_KPROBE);
  DEFINE_PROG_TEST(kprobe, BPF_PROG_TYPE_KPROBE);
  DEFINE_PROG_TEST(tracepoint, BPF_PROG_TYPE_TRACEPOINT);
  DEFINE_PROG_TEST(perf_event, BPF_PROG_TYPE_PERF_EVENT);

protected:
  std::unique_ptr<bool> has_loop_;
  std::unique_ptr<int> insns_limit_;

private:
  bool detect_map(enum bpf_map_type map_type);
  bool detect_helper(enum libbpf::bpf_func_id func_id,
                     enum bpf_prog_type prog_type);
  bool detect_prog_type(enum bpf_prog_type prog_type);
};

#undef DEFINE_PROG_TEST
#undef DEFINE_MAP_TEST
#undef DEFINE_HELPER_TEST
} // namespace bpftrace
