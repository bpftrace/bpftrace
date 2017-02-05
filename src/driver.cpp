#include <iostream>

#include "driver.h"

namespace ebpf {
namespace bpftrace {

int Driver::parse()
{
  return parser_.parse();
}

int Driver::parse(const std::string &f)
{
  if (!(yyin = fopen(f.c_str(), "r"))) {
    std::cerr << "Could not open file" << std::endl;
    return -1;
  }
  return parser_.parse();
}

} // namespace bpftrace
} // namespace ebpf
