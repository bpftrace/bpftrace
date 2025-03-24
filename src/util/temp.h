#pragma once

#include <filesystem>
#include <span>
#include <string>

#include "util/result.h"

namespace bpftrace::util {

class TempFileError : public ErrorInfo<TempFileError> {
public:
  TempFileError(std::string origin, int err)
      : origin_(std::move(origin)), err_(err) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string origin_;
  int err_;
};

// TempFile provide a convenient RAII wrapper for temporary files. The use of
// temporary files should be generally discouraged, unless they are necessary
// to interacting with other libraries or tools.
class TempFile {
public:
  static Result<TempFile> create(std::string pattern = "");
  ~TempFile();

  TempFile(const TempFile &other) = delete;
  TempFile &operator=(const TempFile &other) = delete;

  TempFile(TempFile &&other)
  {
    path_ = std::move(other.path_);
    fd_ = other.fd_;
    other.fd_ = -1;
  }
  TempFile &operator=(TempFile &&other)
  {
    path_ = std::move(other.path_);
    fd_ = other.fd_;
    other.fd_ = -1;
    return *this;
  }

  const std::filesystem::path &path()
  {
    return path_;
  }

  Result<OK> write_all(std::span<char> bytes);

private:
  TempFile(std::filesystem::path &&path, int fd)
      : path_(std::move(path)), fd_(fd) {};

  std::filesystem::path path_;
  int fd_;
};

} // namespace bpftrace::util
