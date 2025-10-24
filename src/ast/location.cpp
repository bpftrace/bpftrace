#include <sstream>

#include "ast/context.h"
#include "ast/location.h"

namespace bpftrace::ast {

std::string SourceLocation::filename() const
{
  if (source_) {
    return source_->filename;
  }
  return "";
}

std::string SourceLocation::source_location() const
{
  std::stringstream ss;
  if (source_) {
    ss << source_->filename << ":";
  }
  if (begin.line != end.line) {
    ss << begin.line << "-" << end.line;
    return ss.str();
  }
  ss << begin.line << ":";
  ss << begin.column << "-" << end.column;
  return ss.str();
}

std::ostream &operator<<(std::ostream &out, const SourceLocation &loc)
{
  out << loc.source_location();
  return out;
}

SourceLocation operator+(const SourceLocation &orig, const SourceLocation &loc)
{
  // The parser constructs source locations that don't have any source. These
  // are quickly joined into locations that do have source, so we allow for this
  // and quickly converge to what is expected.
  auto source = orig.source_;
  if (source == nullptr && loc.source_ != nullptr) {
    source = loc.source_;
  } else if (loc.source_ != nullptr) {
    assert(source == loc.source_);
  }
  auto result = SourceLocation(source);
  result.begin.line = std::min(orig.begin.line, loc.begin.line);
  result.end.line = std::max(orig.end.line, loc.end.line);

  if (orig.begin.line < loc.begin.line) {
    result.begin.column = orig.begin.column;
  } else if (orig.begin.line == loc.begin.line) {
    result.begin.column = std::min(orig.begin.column, loc.begin.column);
  } else {
    result.begin.column = loc.begin.column;
  }

  if (orig.end.line < loc.end.line) {
    result.end.column = loc.end.column;
  } else if (orig.end.line == loc.end.line) {
    result.end.column = std::max(orig.end.column, loc.end.column);
  } else {
    result.end.column = orig.end.column;
  }

  // Anything that spans inherits the *first* location's comments.
  result.comments_ = orig.comments_;
  result.vspace_ = orig.vspace_;

  return result;
}

std::vector<std::string> SourceLocation::source_context() const
{
  std::vector<std::string> result;

  // Is there source available?
  if (!source_ || begin.line == 0) {
    return result;
  }

  // Multi-lines just include all context.
  if (begin.line != end.line) {
    assert(begin.line < end.line);
    for (int i = begin.line; i <= end.line; i++) {
      assert(i <= static_cast<int>(source_->lines_.size()));
      result.push_back(source_->lines_[i - 1]);
    }
    return result;
  }

  // Single line includes just the relevant context.
  if (begin.line > static_cast<int>(source_->lines_.size())) {
    return result; // Nothing available.
  }
  auto &srcline = source_->lines_[begin.line - 1];
  std::stringstream orig;
  for (auto c : srcline) {
    if (c == '\t')
      orig << "    ";
    else
      orig << c;
  }
  result.emplace_back(orig.str());

  std::stringstream select;
  for (int x = 0; x < static_cast<int>(srcline.size()) && x < end.column - 1;
       x++) {
    char marker = x < begin.column - 1 ? ' ' : '~';
    if (srcline[x] == '\t') {
      select << std::string(4, marker);
    } else {
      select << marker;
    }
  }
  result.emplace_back(select.str());

  return result;
}

Location operator+(const Location &orig, const Location &expansion)
{
  if (expansion == nullptr) {
    return orig;
  }
  if (orig == nullptr) {
    return expansion;
  }
  auto nlink = std::make_shared<LocationChain>(expansion->current);
  nlink->parent.emplace(LocationChain::Context(Location(orig)));
  nlink->parent->msg << "expanded from";
  return nlink;
}

} // namespace bpftrace::ast
