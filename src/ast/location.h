#pragma once

#include <cassert>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "location.hh"

namespace bpftrace::ast {

class ASTSource;

// Location is a source location. This effectively wraps an `ASTSource` and
// allows for a full source context to be produced.
class Location {
public:
  Location() = default;
  Location(const Location &) = default;
  Location &operator=(const Location &) = default;
  Location(location loc, std::shared_ptr<ASTSource> source = {});

  // Canonical filename.
  std::string filename() const;

  // Produce a canonical string showing the filename, line range and/or column
  // range. This is of the form `<file>:<line>:<x-y>` but may also take the
  // form `<file>:<x-y>`.
  std::string source_location() const;

  // Produce a sequence of lines that highlights the specific source context.
  // Note that these should be emitted such that the columns for each line line
  // up when they are displayed.
  std::vector<std::string> source_context() const;

  // Canonical line number, will be start of range.
  unsigned int line() const
  {
    return line_range_.first;
  };

  // Canonical column number, will be start of range.
  unsigned int column() const
  {
    return column_range_.first;
  };

  // Joining Locations; both *must* be from the same source context. This
  // essentially selects the full superset of both locations. If we want to
  // represent the idea of multiple related locations, they should be
  // represented separately as multiple `Location` objects.
  Location operator+(const Location &other) const
  {
    assert(source_.get() == other.source_.get());
    range_t lines = line_range_;
    range_t columns = column_range_;
    if (other.line_range_.first < lines.first) {
      lines.first = other.line_range_.first;
      columns.first = other.column_range_.first;
    } else if (other.line_range_.first == lines.first) {
      columns.first = std::min(columns.first, other.column_range_.first);
    }
    if (other.line_range_.second > lines.second) {
      lines.second = other.line_range_.second;
      columns.second = other.column_range_.second;
    } else if (other.line_range_.second == lines.second) {
      columns.second = std::max(columns.second, other.column_range_.second);
    }
    return { std::move(lines), std::move(columns), source_ };
  }

private:
  using range_t = std::pair<unsigned int, unsigned int>;
  Location(range_t &&lines,
           range_t &&columns,
           std::shared_ptr<ASTSource> source)
      : line_range_(std::move(lines)),
        column_range_(std::move(columns)),
        source_(std::move(source)) {};

  range_t line_range_;
  range_t column_range_;
  std::shared_ptr<ASTSource> source_;
};

} // namespace bpftrace::ast
