#pragma once

#include <cassert>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "location.hh"

namespace bpftrace::ast {

class ASTSource;

// SourceLocation refers to a single location in a source file.
//
// It does not contain any additional context.
class SourceLocation {
public:
  SourceLocation() = default;
  SourceLocation(const SourceLocation &) = default;
  SourceLocation &operator=(const SourceLocation &) = default;
  SourceLocation(location loc, std::shared_ptr<ASTSource> source = {});

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

private:
  using range_t = std::pair<unsigned int, unsigned int>;
  SourceLocation(range_t &&lines,
                 range_t &&columns,
                 std::shared_ptr<ASTSource> source)
      : line_range_(std::move(lines)),
        column_range_(std::move(columns)),
        source_(std::move(source)) {};

  range_t line_range_;
  range_t column_range_;
  std::shared_ptr<ASTSource> source_;
};

class LocationChain;
using Location = std::shared_ptr<LocationChain>;

// LocationChain is what is used to represent a canonical location in the AST.
// It is a effectively a linked list of source locations, where each link is
// annotated by some additional amount of context.
//
// Note that each LocationChain should be wrapped as a `shared_ptr`, and the
// `Location` alias should be the way that it is referred to broadly.
class LocationChain {
public:
  // See the `parent` field below.
  struct Parent {
    Parent(Location &&loc) : loc(std::move(loc)) {};
    std::stringstream msg;
    const Location loc;
  };

  LocationChain(const SourceLocation &loc) : current(loc) {};

  // See above.
  std::string filename() const
  {
    return current.filename();
  }
  std::string source_location() const
  {
    return current.source_location();
  }
  std::vector<std::string> source_context() const
  {
    return current.source_context();
  }
  unsigned int line() const
  {
    return current.line();
  }
  unsigned int column() const
  {
    return current.column();
  }

  // This may be modified for a node, typically when copying. For example, when
  // copying a node you may automatically modify the location in order to
  // inject a parent that has "expanded from <...>". When these are displayed as
  // diagnostics, they are unpacked in reverse.
  std::optional<Parent> parent;
  const SourceLocation current;
};

Location operator+(const Location &orig, const Location &expansion);

} // namespace bpftrace::ast
