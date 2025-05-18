#pragma once

#include <stdexcept>
#include <string>

namespace bpftrace::util {

class MountNSException : public std::exception {
public:
  MountNSException(std::string msg);
  const char *what() const noexcept override;

private:
  std::string msg_;
};

class EnospcException : public std::runtime_error {
public:
  // C++11 feature: bring base class constructor into scope to automatically
  // forward constructor calls to base class
  using std::runtime_error::runtime_error;
};

// Use this to end bpftrace execution due to a user error.
// These should be caught at a high level only e.g. main.cpp or bpftrace.cpp
class FatalUserException : public std::runtime_error {
public:
  // C++11 feature: bring base class constructor into scope to automatically
  // forward constructor calls to base class
  using std::runtime_error::runtime_error;
};

class BpfMapElemException : public std::runtime_error {
public:
  // C++11 feature: bring base class constructor into scope to automatically
  // forward constructor calls to base class
  using std::runtime_error::runtime_error;
};

} // namespace bpftrace::util
