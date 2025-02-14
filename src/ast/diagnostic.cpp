#include "diagnostic.h"

#include "log.h"

namespace bpftrace::ast {

void Diagnostics::emit(std::ostream& out)
{
  // Emit all errors first, following by all warnings. Hints follow the
  // structured log message in the same location.
  foreach(Severity::Error, [&out](const Diagnostic& d) {
    LOG(ERROR, d.loc(), out) << d.msg();
    if (auto s = d.hint(); s.size() > 0) {
      LOG(HINT, out) << s;
    }
  });
  foreach(Severity::Warning, [&out](const Diagnostic& d) {
    LOG(WARNING, d.loc(), out) << d.msg();
    if (auto s = d.hint(); s.size() > 0) {
      LOG(HINT, out) << s;
    }
  });
}

} // namespace bpftrace::ast
