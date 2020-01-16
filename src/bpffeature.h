#pragma once

#include <string>

namespace bpftrace {

class BPFfeature
{
public:
  BPFfeature();
  bool has_loop(void);
  bool has_helper_send_signal(void);
  bool has_helper_get_current_cgroup_id(void);

private:
  bool has_loop_;
};

} // namespace bpftrace
