#pragma once

#include <vector>
#include <sys/capability.h>

class Capabilities {
public:
  Capabilities(void);
  /**
     Drop down to the specified capability set
  */
  void drop_to(std::vector<cap_value_t> caps);
  /**
     Drop a single capability
  */
  void drop(cap_value_t cap);

  /**
     Do we currently have this capability?
  */
  bool has_cap(cap_value_t cap);

  /**
     Check whether the system supports this capability
  */
  bool system_has_cap(cap_value_t cap);

  std::string to_string(cap_t cap);
  std::string to_string(void) { return to_string(current_); };
  std::string to_string(cap_value_t cap);

private:
  cap_t current_;

  // Highest cap the system supports
  ssize_t max_cap_;
};
