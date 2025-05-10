#include <algorithm>
#include <ranges>

#include "diagnostic.h"
#include "log.h"

namespace bpftrace::ast {

std::stringstream& Diagnostic::addContext(Location loc)
{
  loc_->contexts.emplace_back(std::make_shared<LocationChain>(loc->current));
  return loc_->contexts.back().msg;
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
  // Build our sets of messages.
  std::vector<std::pair<std::string, SourceLocation>> msgs;
  std::vector<std::pair<std::string, SourceLocation>> parent_msgs;
  auto loc = d.loc();

  if (loc) {
    msgs.emplace_back(d.msg(), loc->current);

    for (const auto& context : loc->contexts) {
      msgs.emplace_back(context.msg.str(), context.loc->current);
    }

    while (loc) {
      auto& parent = loc->parent;
      if (parent) {
        parent_msgs.emplace_back(parent->msg.str(), parent->loc->current);
        loc = parent->loc;
      } else {
        break;
      }
    }
  }

  // reverse to print the initial parent first
  std::ranges::reverse(parent_msgs);

  switch (s) {
    case Severity::Warning:
      if (msgs.empty()) {
        LOG(WARNING, out) << d.msg();
      }
      for (const auto& [msg, loc] : msgs) {
        LOG(WARNING, loc.source_location(), loc.source_context(), out) << msg;
      }
      for (const auto& msg : d.hints()) {
        LOG(HINT, out) << msg;
      }
      for (const auto& [msg, loc] : parent_msgs) {
        LOG(WARNING, loc.source_location(), loc.source_context(), out) << msg;
      }
      break;
    case Severity::Error:
      if (msgs.empty()) {
        LOG(ERROR, out) << d.msg();
      }
      for (const auto& [msg, loc] : msgs) {
        LOG(ERROR, loc.source_location(), loc.source_context(), out) << msg;
      }
      for (const auto& msg : d.hints()) {
        LOG(HINT, out) << msg;
      }
      for (const auto& [msg, loc] : parent_msgs) {
        LOG(ERROR, loc.source_location(), loc.source_context(), out) << msg;
      }
      break;
  }
}

} // namespace bpftrace::ast
