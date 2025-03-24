#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include "util/result.h"
#include "util/temp.h"

namespace bpftrace::util {

char TempFileError::ID;
void TempFileError::log(llvm::raw_ostream &OS) const
{
  OS << "temporary file " << origin_ << ": " << strerror(err_);
}

Result<TempFile> TempFile::create(std::string pattern)
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
  int fd = ::mkostemp(mutable_pattern.data(), O_CLOEXEC);
  if (fd < 0) {
    int err = errno;
    return make_error<TempFileError>(pattern, err);
  }
  std::filesystem::path final_path(mutable_pattern.data());
  return TempFile(std::move(final_path), fd);
}

TempFile::~TempFile()
{
  if (fd_ != -1) {
    unlink(path_.c_str());
    close(fd_);
  }
}

Result<OK> TempFile::write_all(std::span<char> bytes)
{
  auto b = std::as_bytes(bytes);
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
  }
  return OK();
}

} // namespace bpftrace::util
