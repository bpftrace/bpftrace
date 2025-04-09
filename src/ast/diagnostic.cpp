#include <algorithm>
#include <ranges>

#include "diagnostic.h"
#include "log.h"

namespace bpftrace::ast {

std::stringstream& Diagnostic::addContext(Location loc)
{
  // This must not modify the existing location, instead we add
  // a new link to the location chain. We don't inject the full
  // chain if one has been provided, but take only that node.
  auto nloc = std::make_shared<LocationChain>(loc->current);
  auto& nlink = nloc->parent.emplace(LocationChain::Parent(std::move(loc_)));
  loc_ = std::move(nloc);
  return nlink.msg;
}

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
  // Build our set of messages.
  std::vector<std::pair<std::string, SourceLocation>> msgs;
  auto loc = d.loc();
  while (loc) {
    auto& parent = loc->parent;
    if (parent) {
      msgs.emplace_back(parent->msg.str(), loc->current);
      loc = parent->loc;
    } else {
      msgs.emplace_back(d.msg(), loc->current);
      break;
    }
  }
  std::ranges::reverse(msgs);

  switch (s) {
    case Severity::Warning:
      if (msgs.empty()) {
        LOG(WARNING, out) << d.msg();
      }
      for (const auto& [msg, loc] : msgs) {
        LOG(WARNING, loc.source_location(), loc.source_context(), out) << msg;
      }
      if (auto msg = d.hint(); !msg.empty()) {
        LOG(HINT, out) << msg;
      }
      break;
    case Severity::Error:
      if (msgs.empty()) {
        LOG(ERROR, out) << d.msg();
      }
      for (const auto& [msg, loc] : msgs) {
        LOG(ERROR, loc.source_location(), loc.source_context(), out) << msg;
      }
      if (auto msg = d.hint(); !msg.empty()) {
        LOG(HINT, out) << msg;
      }
      break;
  }
}

} // namespace bpftrace::ast
