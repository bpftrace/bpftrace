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

  if (result) {
    return result;
  }

  driver.dump_ast(std::cout);

  result = driver.analyse();
  if (result) {
    return result;
  }

  driver.compile();

  return 0;
}
