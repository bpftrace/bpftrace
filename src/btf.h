#pragma once

#include <linux/types.h>
#include <unistd.h>

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

private:
  struct btf *btf;
  enum state state = NODATA;
};

inline bool BTF::has_data(void)
{
  return state == OK;
}

} // namespace bpftrace
