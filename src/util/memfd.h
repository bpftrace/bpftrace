#pragma once

#include <span>
#include <string>

#include "util/result.h"
#include "llvm/Support/raw_ostream.h"

namespace bpftrace::util {

class MemFd {
public:
  static Result<MemFd> create(const std::string &name);
  MemFd(MemFd &&other) : fd_(other.fd_), path_(other.path_)
  {
    other.fd_ = -1;
  }
  MemFd(const MemFd &other) = delete;
  ~MemFd();

  const std::string &path()
  {
    return path_;
  }

  Result<std::string> read_all();
  Result<> write_all(const std::span<const char> &data);

private:
  MemFd(int fd) : fd_(fd), path_("/dev/fd/" + std::to_string(fd)) {};

  int fd_ = -1;
  std::string path_;
};

} // namespace bpftrace::util
