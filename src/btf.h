#pragma once

#include <linux/types.h>
#include <unistd.h>
#include <map>
#include "struct.h"

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
  void resolve_struct(std::string name, std::map<std::string, Struct> &structs);

private:
  void init(unsigned char *data, unsigned int size);
  int resolve_field(__u32 type_id, Field& field, std::map<std::string, Struct> &structs);
  void resolve_struct_id(__u32 type_id, std::string name, std::map<std::string, Struct> &structs, bool new_struct = true);

  struct btf *btf;
  enum state state;
};

inline bool BTF::has_data(void)
{
  return state == OK;
}

} // namespace bpftrace
