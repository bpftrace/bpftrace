#include <iostream>
#include "driver.h"

int main(int argc, char *argv[])
{
  int result;
  ebpf::bpftrace::Driver driver;
  if (argc == 1) {
    result = driver.parse();
  }
  else {
    result = driver.parse(argv[1]);
  }

  if (!result) {
    driver.dump_ast(std::cout);
    driver.compile();
  }

  return result;
}
