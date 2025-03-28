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
  int err() const
  {
    return err_;
  }

private:
  std::string origin_;
  int err_;
};

// TempFile provide a convenient RAII wrapper for temporary files. The use of
// temporary files should be generally discouraged, unless they are necessary
// to interacting with other libraries or tools.
class TempFile {
public:
  static Result<TempFile> create(std::string name = "", bool pattern = true);
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

  Result<OK> write_all(std::span<const char> bytes);

private:
  TempFile(std::filesystem::path &&path, int fd)
      : path_(std::move(path)), fd_(fd) {};

  std::filesystem::path path_;
  int fd_;
};

// TempDir provides a wrapper for temporary directories.
//
// There is no way to create directories with a fixed name.
class TempDir {
public:
  static Result<TempDir> create(std::string pattern = "");
  ~TempDir();

  TempDir(const TempDir &other) = delete;
  TempDir &operator=(const TempDir &other) = delete;

  TempDir(TempDir &&other)
  {
    path_ = std::move(other.path_);
  }
  TempDir &operator=(TempDir &&other)
  {
    path_ = std::move(other.path_);
    return *this;
  }

  const std::filesystem::path &path()
  {
    return path_;
  }

  // Creates a temporary file in this directory. Note that `name` need not
  // contain any `X` characters if `pattern` is true, as these will be appended
  // as a suffix. The `name` provided may hae path components, but this
  // function will do not anything with respect to creating intermediate
  // directories.
  Result<TempFile> create_file(std::string name = "", bool pattern = true);

private:
  TempDir(std::filesystem::path &&path) : path_(std::move(path)) {};

  std::filesystem::path path_;
};

} // namespace bpftrace::util
