#pragma once

#include <cassert>
#include <compare>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace bpftrace::ast {

class ASTSource;
class ASTContext;

// SourceLocation refers to a single location in a source file.
//
// It does not contain any additional context. It may be manipulated directly
// by the lexer, and copied.
class SourceLocation {
public:
  struct Position {
    int line = 1;
    int column = 1;
  };

  SourceLocation() = default; // Allowed, but see operator+.
  SourceLocation(const SourceLocation &) = default;
  SourceLocation &operator=(const SourceLocation &other) = default;
  SourceLocation(SourceLocation &&) = default;
  SourceLocation &operator=(SourceLocation &&other) = default;
  SourceLocation(std::shared_ptr<ASTSource> source)
      : source_(std::move(source)) {};

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
    return begin.line;
  };

  // Canonical column number, will be start of range.
  unsigned int column() const
  {
    return begin.column;
  };

  // Moves the cursor forward `lines` lines.
  void advance_lines(int lines = 1)
  {
    begin.column = 1;
    end.column = 1;
    begin.line += lines;
    end.line = begin.line;
  }

  // Moves the cursor forward `count` columns.
  void advance_columns(int count)
  {
    begin.column = end.column;
    end.column += count;
  }

  // Move the cursor backwards.
  void rewind_columns()
  {
    end.column -= 1;
    begin.column -= 1;
  }

  // Trims the last character from this location.
  void trim()
  {
    end.column -= 1;
  }

  // Resets the column.
  void reset_column()
  {
    begin.column = 1;
    end.column = 1;
  }

  Position begin;
  Position end;

private:
  std::shared_ptr<ASTSource> source_;

  friend class ASTContext;
  friend SourceLocation operator+(const SourceLocation &orig,
                                  const SourceLocation &other);
};

SourceLocation operator+(const SourceLocation &orig,
                         const SourceLocation &other);

std::ostream &operator<<(std::ostream &out, const SourceLocation &loc);

std::strong_ordering operator<=>(const SourceLocation::Position &lhs,
                                 const SourceLocation::Position &rhs);
std::strong_ordering operator<=>(const SourceLocation &lhs,
                                 const SourceLocation &rhs);
bool operator==(const SourceLocation::Position &lhs,
                const SourceLocation::Position &rhs);
bool operator==(const SourceLocation &lhs, const SourceLocation &rhs);

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
  struct Context {
    Context(Location &&loc) : loc(std::move(loc)) {};
    std::stringstream msg;
    const Location loc;
  };

  LocationChain(SourceLocation loc) : current(std::move(loc)) {};

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
  std::optional<Context> parent;
  const SourceLocation current;
  std::vector<Context> contexts;
};

Location operator+(const Location &orig, const Location &expansion);

} // namespace bpftrace::ast
