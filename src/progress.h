#pragma once

#include <iostream>
#include <memory>

namespace bpftrace {

// BoundedProgress is used to indicate that progress is being made in some
// dimension for which we now the final amount. Note that this can be modified
// over time (e.g. like a set of downloads for which you discover the sizes
// of files as you work your way through the list).
class BoundedProgress {
public:
  virtual ~BoundedProgress() = default;
  virtual void add_goal(size_t sz) = 0;
  virtual void add_progress(size_t sz) = 0;
};

// UnboundedProgress is used to indicate progress is being made when the bound
// is not known in advance. This might be processing a stream of events when we
// don't know when they will end.
class UnboundedProgress {
public:
  virtual ~UnboundedProgress() = default;
  virtual void tick() = 0;
};

// Progress is an abstract class that allows implementations to define the two
// different classes of progress hooks above.
class Progress {
public:
  virtual ~Progress() = default;
  virtual std::unique_ptr<BoundedProgress> bounded(const std::string &name) = 0;
  virtual std::unique_ptr<UnboundedProgress> unbounded(
      const std::string &name) = 0;
};

// Simple CRTP base class.
//
// Implementations simply define a class with two subclasses, `Bounded` and
// `Unbounded` that have constructs that take a pointer to the current class
// and the name.
template <typename T>
class ProgressImpl : public Progress {
public:
  ~ProgressImpl() = default;
  std::unique_ptr<BoundedProgress> bounded(const std::string &name)
  {
    return std::make_unique<typename T::Bounded>(static_cast<T *>(this), name);
  }
  std::unique_ptr<UnboundedProgress> unbounded(const std::string &name)
  {
    return std::make_unique<typename T::Unbounded>(static_cast<T *>(this),
                                                   name);
  }
};

// CreateSilentProgress returns a no-op implementation of the above.
std::unique_ptr<Progress> CreateSilentProgress();

// CreateConsoleProgress is currently the only implementation; it emits output
// to the console, optionally using pretty colors.
std::unique_ptr<Progress> CreateConsoleProgress(std::ostream &out, bool color);

} // namespace bpftrace
