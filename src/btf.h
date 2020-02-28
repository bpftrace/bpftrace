#pragma once

#include "types.h"
#include <linux/types.h>
#include <map>
#include <string>
#include <unistd.h>
#include <unordered_set>

struct btf;
struct btf_type;

namespace bpftrace {

class BTF
{
  enum state
  {
    NODATA,
    OK,
  };

public:
  BTF();
  ~BTF();

  bool has_data(void);
  std::string c_def(std::unordered_set<std::string>& set);
  std::string type_of(const std::string& name, const std::string& field);
  std::string type_of(const btf_type* type, const std::string& field);

  int resolve_args(const std::string &func,
                   std::map<std::string, SizedType>& args,
                   bool ret);

private:
  SizedType get_stype(__u32 id);
  const struct btf_type* btf_type_skip_modifiers(const struct btf_type* t);

  struct btf* btf;
  enum state state = NODATA;
};

inline bool BTF::has_data(void)
{
  return state == OK;
}

} // namespace bpftrace
