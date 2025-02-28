#pragma once

#include <cassert>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include "location.hh"

namespace bpftrace {
namespace ast {

// Diagnostic reflects a single error at a single source location. This is a
// simple wrapper around a string for that message, and the location class.
class Diagnostic {
public:
  enum class Severity {
    Warning,
    Error,
  };
  Diagnostic(location loc) : loc_(loc) {};
  const std::string msg() const
  {
    return msg_.str();
  }
  const std::string hint() const
  {
    return hint_.str();
  }
  const location& loc() const
  {
    return loc_;
  }

  // Each diagnostic can potentially have a hint attached, which is how to
  // effectively resolve this issue.
  std::stringstream& addHint()
  {
    return hint_;
  }

  template <typename T>
  Diagnostic& operator<<(const T& t)
  {
    msg_ << t;
    return *this;
  }

private:
  std::stringstream msg_;
  std::stringstream hint_;
  location loc_;
};

class Diagnostics {
public:
  using Severity = Diagnostic::Severity;

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
    return diagnostics_.size() > index && diagnostics_[index].size() > 0;
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
  void emit(std::ostream& out);

private:
  void foreach(Severity severity,
               std::function<void(const Diagnostic&)> fn) const
  {
    auto index = static_cast<long unsigned int>(severity);
    if (diagnostics_.size() <= index) {
      return;
    }
    for (const auto& diag : diagnostics_[index]) {
      fn(*diag.get());
    }
  }

  // Two-dimensional vector with all diagnostics. The first level is indexed by
  // severity, and the second level is the set of diagnostics for that level.
  //
  // N.B. we store diagnostics as a pointer because the lifetime is returned
  // early above, so they must not be moving at any point.
  std::vector<std::vector<std::unique_ptr<Diagnostic>>> diagnostics_;
};

} // namespace ast
} // namespace bpftrace
