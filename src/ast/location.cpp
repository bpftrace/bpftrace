#include "location.h"

#include <sstream>

#include "ast/context.h"

namespace bpftrace::ast {

SourceLocation::SourceLocation(location loc, std::shared_ptr<ASTSource> source)
    : line_range_(loc.begin.line, loc.end.line),
      column_range_(loc.begin.column, loc.end.column),
      source_(std::move(source))
{
}

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
  if (line_range_.first != line_range_.second) {
    ss << line_range_.first << "-" << line_range_.second;
    return ss.str();
  }
  ss << line_range_.first << ":";
  ss << column_range_.first << "-" << column_range_.second;
  return ss.str();
}

std::vector<std::string> SourceLocation::source_context() const
{
  std::vector<std::string> result;

  // Is there source available?
  if (!source_ || line_range_.first == 0) {
    return result;
  }

  // Multi-lines just include all context.
  if (line_range_.first != line_range_.second) {
    assert(line_range_.first < line_range_.second);
    for (unsigned int i = line_range_.first; i <= line_range_.second; i++) {
      assert(i <= source_->lines_.size());
      result.push_back(source_->lines_[i - 1]);
    }
    return result;
  }

  // Single line includes just the relevant context.
  if (line_range_.first > source_->lines_.size()) {
    return result; // Nothing available.
  }
  auto &srcline = source_->lines_[line_range_.first - 1];
  std::stringstream orig;
  for (auto c : srcline) {
    if (c == '\t')
      orig << "    ";
    else
      orig << c;
  }
  result.emplace_back(orig.str());

  std::stringstream select;
  for (unsigned int x = 0; x < srcline.size() && x < column_range_.second - 1;
       x++) {
    char marker = x < column_range_.first - 1 ? ' ' : '~';
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
  auto nlink = std::make_shared<LocationChain>(expansion->current);
  nlink->parent.emplace(LocationChain::Parent(Location(orig)));
  nlink->parent->msg << "expanded from";
  return nlink;
}

} // namespace bpftrace::ast
