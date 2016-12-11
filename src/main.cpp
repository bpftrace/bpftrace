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

  for (auto &preproc : *(driver.root_->preprocs)) {
    std::cout << preproc->line << std::endl;
  }
  return result;
}
