#pragma once

#include <cstdint>
#include <cstdio>
#include <streambuf>

namespace bpftrace::util {

class StdioSilencer {
public:
  StdioSilencer() = default;
  ~StdioSilencer();
  void silence();

protected:
  FILE *ofile;

private:
  int old_stdio_ = -1;
};

class StderrSilencer : public StdioSilencer {
public:
  StderrSilencer()
  {
    ofile = stderr;
  }
};

class StdoutSilencer : public StdioSilencer {
public:
  StdoutSilencer()
  {
    ofile = stdout;
  }
};

// Helper class to convert a pointer to an `std::istream`
class Membuf : public std::streambuf {
public:
  Membuf(uint8_t *begin, uint8_t *end)
  {
    auto *b = reinterpret_cast<char *>(begin);
    auto *e = reinterpret_cast<char *>(end);
    this->setg(b, b, e);
  }
};

void cat_file(const char *filename, size_t, std::ostream &);

} // namespace bpftrace::util
