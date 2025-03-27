#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include "log.h"
#include "util/result.h"
#include "util/temp.h"

namespace bpftrace::util {

char TempFileError::ID;
void TempFileError::log(llvm::raw_ostream &OS) const
{
  OS << "temporary file " << origin_ << ": " << strerror(err_);
}

// Generic helper for providing a default pattern and ensuring that it is
// mutable, in order to call the standard `mktemp` et al. Note that the
// function `fn` must return `-errno` in the case of failure.
static Result<std::pair<std::string, int>> mktemp(std::string pattern,
                                                  std::function<int(char *)> fn)
{
  if (pattern.empty()) {
    // Attempt to extract the best temporary directory. If the environment
    // variable is not available, then we fall back to /tmp. This is mandated
    // to exist by POSIX, but `TMPDIR` is the canonical way to override.
    const char *tmp = getenv("TMPDIR");
    if (tmp == nullptr) {
      tmp = "/tmp";
    }
    // Requires sufficient XXXXXX as suffix for mkostemp.
    pattern = std::string(tmp) + "/" + "bpftrace.XXXXXX";
  }
  // The call to `mkostemp` will mutate the resulting string. This is not
  // permitted through `std::string::c_str`, therefore we construct a vector to
  // hold this result. This is used below as the actual filename.
  std::vector<char> mutable_pattern(pattern.size() + 1);
  ::strncpy(mutable_pattern.data(), pattern.c_str(), mutable_pattern.size());
  int fd = fn(mutable_pattern.data());
  if (fd < 0) {
    int err = -fd; // See doc above.
    return make_error<TempFileError>(pattern, err);
  }
  return std::pair<std::string, int>(std::string(mutable_pattern.data()), fd);
}

Result<TempFile> TempFile::create(std::string name, bool pattern)
{
  if (!pattern) {
    int fd = ::open(name.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
      return make_error<TempFileError>(name, errno);
    }
    return TempFile(std::move(name), fd);
  }
  auto res = mktemp(name, [](char *s) -> int {
    int fd = ::mkostemp(s, O_CLOEXEC);
    if (fd < 0) {
      return -errno;
    }
    return fd;
  });
  if (!res) {
    return res.takeError();
  }
  return TempFile(std::move(res->first), res->second);
}

TempFile::~TempFile()
{
  if (fd_ != -1) {
    unlink(path_.c_str());
    close(fd_);
  }
}

Result<OK> TempFile::write_all(std::span<const char> bytes)
{
  const auto b = std::as_bytes(bytes);
  int done = 0;
  int left = bytes.size();
  while (left > 0) {
    int rc = ::write(fd_, &b[done], left);
    if (rc < 0 && (errno == EAGAIN || errno == EINTR)) {
      continue;
    }
    if (rc < 0) {
      int err = errno;
      return make_error<TempFileError>(path_.string(), err);
    }
    done += rc;
    left -= rc;
  }
  return OK();
}

Result<TempDir> TempDir::create(std::string pattern)
{
  auto res = mktemp(pattern, [](char *s) -> int {
    char *res = ::mkdtemp(s);
    return res == nullptr ? -errno : 0;
  });
  if (!res) {
    return res.takeError();
  }
  assert(res->second == 0);
  return TempDir(std::move(res->first));
}

Result<TempFile> TempDir::create_file(std::string name, bool pattern)
{
  if (pattern) {
    // Using a pattern.
    if (name.empty()) {
      return TempFile::create(path_ / "XXXXXX");
    }
    return TempFile::create(path_ / (name + ".XXXXXX"));
  }

  // Using a fixed name.
  if (name.empty()) {
    return make_error<TempFileError>(name, EINVAL);
  }
  return TempFile::create(path_ / name, false);
}

TempDir::~TempDir()
{
  std::error_code ec;
  std::filesystem::remove_all(path_, ec);
  if (ec) {
    LOG(WARNING) << "unable to remove directory: " << path_;
  }
}

} // namespace bpftrace::util
