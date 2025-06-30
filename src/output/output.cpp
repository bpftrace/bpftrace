#include <map>
#include <sstream>

#include "output/output.h"
#include "output/text.h"
#include "util/strings.h"

namespace bpftrace::output {

std::ostream &operator<<(std::ostream &out, const Primitive &p)
{
  TextOutput output(out);
  output.primitive(p);
  return out;
}

} // namespace bpftrace::output
