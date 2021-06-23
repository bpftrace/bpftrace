#include "aot.h"

#include "log.h"

namespace bpftrace {
namespace aot {

int generate(const RequiredResources &resources,
             const BpfBytecode &bytecode,
             const std::string &out)
{
  (void)resources;
  (void)bytecode;
  (void)out;

  return 0;
}

} // namespace aot
} // namespace bpftrace
