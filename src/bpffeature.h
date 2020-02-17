#pragma once

#include <memory>
#include <string>

namespace bpftrace {

class BPFfeature
{
public:
  BPFfeature(){};

  int instruction_limit();
  bool has_loop();

  bool has_helper_override_return();
  bool has_helper_get_current_cgroup_id();
  bool has_helper_send_signal();

  bool has_map_array();
  bool has_map_hash();
  bool has_map_percpu_array();
  bool has_map_percpu_hash();
  bool has_map_stack_trace();
  bool has_map_perf_event_array();

  bool has_prog_kprobe();
  bool has_prog_tracepoint();
  bool has_prog_perf_event();

  std::string report(void);

protected:
  std::unique_ptr<bool> has_loop_;
  std::unique_ptr<int> insns_limit_;

  /* Map types */
  std::unique_ptr<bool> map_hash_;
  std::unique_ptr<bool> map_percpu_hash_;
  std::unique_ptr<bool> map_array_;
  std::unique_ptr<bool> map_percpu_array_;
  std::unique_ptr<bool> map_stack_trace_;
  std::unique_ptr<bool> map_perf_event_array_;

  /* Prog type */
  std::unique_ptr<bool> prog_kprobe_;
  std::unique_ptr<bool> prog_tracepoint_;
  std::unique_ptr<bool> prog_perf_event_;

  /* Helpers */
  std::unique_ptr<bool> has_send_signal_;
  std::unique_ptr<bool> has_get_current_cgroup_id_;
  std::unique_ptr<bool> has_override_return_;
};

} // namespace bpftrace
