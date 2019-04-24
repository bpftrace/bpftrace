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
  BTF(unsigned char *data, unsigned int size);
  ~BTF();

  bool has_data(void);

private:
  void init(unsigned char *data, unsigned int size);

  struct btf *btf;
  enum state state;
};

inline bool BTF::has_data(void)
{
  return state == OK;
}

} // namespace bpftrace
