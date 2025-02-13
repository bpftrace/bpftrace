#pragma once

#include <functional>

// Need two levels of indirection here for __LINE__ to correctly expand
#define _CONCAT2(a, b) a##b
#define _CONCAT(a, b) _CONCAT2(a, b)
#define _ANON_VAR(str) _CONCAT(str, __LINE__)

namespace bpftrace {

enum class ScopeGuardExit {};

class ScopeGuard {
public:
  explicit ScopeGuard(std::function<void()> fn)
  {
    fn_ = fn;
  }

  ~ScopeGuard()
  {
    if (fn_) {
      fn_();
    }
  }

private:
  std::function<void()> fn_;
};

inline ScopeGuard operator+(ScopeGuardExit, std::function<void()> fn)
{
  return ScopeGuard(fn);
}

} // namespace bpftrace

#define SCOPE_EXIT auto _ANON_VAR(SCOPE_EXIT_STATE) = ScopeGuardExit() + [&]()
