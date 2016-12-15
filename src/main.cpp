#include "driver.h"
#include "ast.h"

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

  driver.root_->print_ast(std::cout);
  return result;
}
