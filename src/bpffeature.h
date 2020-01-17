#pragma once

#include <string>

namespace bpftrace {

class BPFfeature
{
public:
  BPFfeature();
  bool has_loop(void)
  {
    return has_loop_;
  };
  bool has_helper_send_signal(void)
  {
    return has_signal_;
  };
  bool has_helper_get_current_cgroup_id(void)
  {
    return has_get_current_cgroup_id_;
  };
  std::string report(void);

protected:
  bool has_loop_;

  /* Helpers */
  bool has_signal_;
  bool has_get_current_cgroup_id_;
};

} // namespace bpftrace
