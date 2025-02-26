#include "diagnostic.h"

#include "ast/context.h"
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
  switch (s) {
    case Severity::Warning:
      LOG(WARNING, src_.filename, src_.contents, d.loc(), out) << d.msg();
      if (auto s = d.hint(); s.size() > 0) {
        LOG(HINT, out) << s;
      }
      break;
    case Severity::Error:
      LOG(ERROR, src_.filename, src_.contents, d.loc(), out) << d.msg();
      if (auto s = d.hint(); s.size() > 0) {
        LOG(HINT, out) << s;
      }
      break;
  }
}

} // namespace bpftrace::ast
