#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util/memfd.h"

namespace bpftrace::util {

Result<MemFd> MemFd::create(const std::string &name)
{
  int fd = memfd_create(name.c_str(), MFD_CLOEXEC);
  if (fd < 0) {
    return make_error<SystemError>("failed to create memfd");
  }
  return MemFd(fd);
}

MemFd::~MemFd()
{
  if (fd_ >= 0) {
    close(fd_);
    fd_ = -1;
  }
}

Result<std::string> MemFd::read_all()
{
  // Seek to the beginning of the file, and read the entire contents
  // into a single string that can be returned. We stat the file up
  // front in order to avoid excessive chunking.
  if (lseek(fd_, 0, SEEK_SET) < 0) {
    return make_error<SystemError>("failed to seek memfd");
  }

  struct stat st;
  if (fstat(fd_, &st) < 0) {
    return make_error<SystemError>("failed to stat memfd");
  }

  std::string result;
  result.resize(st.st_size);
  if (st.st_size > 0) {
    ssize_t bytes_read = read(fd_, result.data(), st.st_size);
    if (bytes_read < 0) {
      return make_error<SystemError>("error during read");
    }
    result.resize(bytes_read);
  }
  return result;
}

Result<> MemFd::write_all(const std::span<const char> data)
{
  ssize_t written = write(fd_, data.data(), data.size());
  if (written < 0) {
    return make_error<SystemError>("failed to write to memfd");
  }
  if (static_cast<size_t>(written) != data.size()) {
    return make_error<SystemError>("incomplete write to memfd");
  }
  return OK();
}

} // namespace bpftrace::util
