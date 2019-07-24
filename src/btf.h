#pragma once

#include <linux/types.h>
#include <unistd.h>
#include <unordered_set>

struct btf;

namespace bpftrace {

class BTF
{
  enum state {
    NODATA,
    OK,
  };

public:
  BTF();
  ~BTF();

  bool has_data(void);
  std::string c_def(std::unordered_set<std::string>& set);

private:
  struct btf *btf;
  enum state state = NODATA;
};

inline bool BTF::has_data(void)
{
  return state == OK;
}

} // namespace bpftrace
