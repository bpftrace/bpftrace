#include "diagnostic.h"

#include "log.h"

namespace bpftrace::ast {

void Diagnostics::emit(std::ostream& out) const
{
  // Emit all errors first, following by all warnings.
  emit(out, Severity::Error);
  emit(out, Severity::Warning);
}

void Diagnostics::emit(std::ostream& out, Severity s) const
{
  foreach(s, [this, s, &out](const Diagnostic& d) { emit(out, s, d); });
}

void Diagnostics::emit(std::ostream& out, Severity s, const Diagnostic& d) const
{
  const auto& loc = d.loc();
  switch (s) {
    case Severity::Warning:
      LOG(WARNING, loc.source_location(), loc.source_context(), out) << d.msg();
      if (auto msg = d.hint(); !msg.empty()) {
        LOG(HINT, out) << msg;
      }
      break;
    case Severity::Error:
      LOG(ERROR, loc.source_location(), loc.source_context(), out) << d.msg();
      if (auto msg = d.hint(); !msg.empty()) {
        LOG(HINT, out) << msg;
      }
      break;
  }
}

} // namespace bpftrace::ast
