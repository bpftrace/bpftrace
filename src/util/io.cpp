#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <unistd.h>

#include "log.h"
#include "util/exceptions.h"
#include "util/io.h"

namespace bpftrace::util {

void StdioSilencer::silence()
{
  auto syserr = [](std::string msg) {
    return std::system_error(errno, std::generic_category(), msg);
  };

  try {
    int fd = fileno(ofile);
    if (fd < 0)
      throw syserr("fileno()");

    fflush(ofile);

    if ((old_stdio_ = dup(fd)) < 0)
      throw syserr("dup(fd)");

    int new_stdio = -1;
    if ((new_stdio = open("/dev/null", O_WRONLY)) < 0)
      throw syserr("open(\"/dev/null\")");

    if (dup2(new_stdio, fd) < 0)
      throw syserr("dup2(new_stdio_, fd)");

    close(new_stdio);
  } catch (const std::system_error &e) {
    if (errno == EMFILE)
      throw FatalUserException(std::string(e.what()) + ": please raise NOFILE");
    else
      LOG(BUG) << e.what();
  }
}

StdioSilencer::~StdioSilencer()
{
  if (old_stdio_ == -1)
    return;

  auto syserr = [](std::string msg) {
    return std::system_error(errno, std::generic_category(), msg);
  };

  try {
    int fd = fileno(ofile);
    if (fd < 0)
      throw syserr("fileno()");

    fflush(ofile);
    if (dup2(old_stdio_, fd) < 0)
      throw syserr("dup2(old_stdio_)");
    close(old_stdio_);
    old_stdio_ = -1;
  } catch (const std::system_error &e) {
    LOG(BUG) << e.what();
  }
}

void cat_file(const char *filename, size_t max_bytes, std::ostream &out)
{
  std::ifstream file(filename);
  const size_t BUFSIZE = 4096;

  if (file.fail()) {
    LOG(ERROR) << "failed to open file '" << filename
               << "': " << strerror(errno);
    return;
  }

  char buf[BUFSIZE];
  size_t bytes_read = 0;
  // Read the file batches to avoid allocating a potentially
  // massive buffer.
  while (bytes_read < max_bytes) {
    size_t size = std::min(BUFSIZE, max_bytes - bytes_read);
    file.read(buf, size);
    out.write(buf, file.gcount());
    if (file.eof()) {
      return;
    }
    if (file.fail()) {
      LOG(ERROR) << "failed to open file '" << filename
                 << "': " << strerror(errno);
      return;
    }
    bytes_read += file.gcount();
  }
}

} // namespace bpftrace::util
