#pragma once

#include <cassert>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "ast/location.h"

namespace bpftrace::ast {

class ASTSource;

// Diagnostic reflects a single error at a single source location. This is a
// simple wrapper around a string for that message, and the location class.
class Diagnostic {
public:
  enum class Severity {
    Warning,
    Error,
  };
  Diagnostic(const Location loc) : loc_(loc) {};
  std::string msg() const
  {
    return msg_.str();
  }
  std::vector<std::string> hints() const
  {
    std::vector<std::string> msgs;
    for (const auto& hint : hints_) {
      msgs.emplace_back(hint.str());
    }
    return msgs;
  }
  const Location& loc() const
  {
    return loc_;
  }

  // Each diagnostic can potentially have hints attached, which is how to
  // effectively resolve this issue.
  std::stringstream& addHint()
  {
    return hints_.emplace_back();
  }

  // Add additional context for the error.
  std::stringstream& addContext(Location loc);

  template <typename T>
  Diagnostic& operator<<(const T& t)
  {
    msg_ << t;
    return *this;
  }

private:
  std::stringstream msg_;
  std::vector<std::stringstream> hints_;
  Location loc_;
};

class Diagnostics {
public:
  using Severity = Diagnostic::Severity;

  // Note that the state of the diagnostics is really only a vector, which
  // provides well-defined `move` semantics. After the move, the vector is
  // guaranteed to be empty, which matches the state required for an empty
  // Diagnostics object.
  Diagnostics() = default;
  Diagnostics(Diagnostics&& other) = default;
  Diagnostics(const Diagnostics& other) = delete;
  Diagnostics& operator=(const Diagnostics& other) = delete;
  Diagnostics& operator=(Diagnostics&& other) = delete;

  template <typename... Args>
  Diagnostic& add(Severity severity, Args... args)
  {
    auto index = static_cast<long unsigned int>(severity);
    if (diagnostics_.size() <= index) {
      diagnostics_.resize(index + 1);
    }
    auto& diags = diagnostics_[index];
    auto& p = diags.emplace_back(std::make_unique<Diagnostic>(args...));
    return *p.get();
  }

  template <typename... Args>
  Diagnostic& addError(Args... args)
  {
    return add(Severity::Error, args...);
  }
  template <typename... Args>
  Diagnostic& addWarning(Args... args)
  {
    return add(Severity::Warning, args...);
  }
  bool has(Severity severity) const
  {
    auto index = static_cast<long unsigned int>(severity);
    return diagnostics_.size() > index && !diagnostics_[index].empty();
  }
  void clear()
  {
    for (auto& diag : diagnostics_) {
      diag.clear();
    }
  }

  // ok is the recommended short-hand for `has(Severity::Error)`.
  bool ok() const
  {
    return !has(Severity::Error);
  }

  // emit implements a default formatter of all diagnostics to a given stream.
  // The use of `emit` should be generally discouraged, especially by tests,
  // who should use more structured checks and avoid matching against the
  // specific format here.
  void emit(std::ostream& out) const;
  void emit(std::ostream& out, Severity s) const;
  void emit(std::ostream& out, Severity s, const Diagnostic& d) const;

  // adds all diagnostics from some other set.
  void add(Diagnostics&& other);

private:
  void foreach(Severity severity,
               std::function<void(const Diagnostic&)> fn) const
  {
    auto index = static_cast<long unsigned int>(severity);
    if (diagnostics_.size() <= index) {
      return;
    }
    for (const auto& diag : diagnostics_[index]) {
      fn(*diag);
    }
  }

  // Two-dimensional vector with all diagnostics. The first level is indexed by
  // severity, and the second level is the set of diagnostics for that level.
  //
  // N.B. we store diagnostics as a pointer because the lifetime is returned
  // early above, so they must not be moving at any point.
  std::vector<std::vector<std::unique_ptr<Diagnostic>>> diagnostics_;

  friend class Node;
};

} // namespace bpftrace::ast
