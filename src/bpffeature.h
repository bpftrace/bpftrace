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

  std::string report(void);

protected:
  std::unique_ptr<bool> has_loop_;
  std::unique_ptr<int> insns_limit_;

  /* Helpers */
  std::unique_ptr<bool> has_send_signal_;
  std::unique_ptr<bool> has_get_current_cgroup_id_;
  std::unique_ptr<bool> has_override_return_;
};

} // namespace bpftrace
