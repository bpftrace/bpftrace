#include "printf.h"
#include "printf_format_types.h"
#include "struct.h"

namespace bpftrace {

int PrintableString::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(buf, size, fmt, value_.c_str());
}

int PrintableBuffer::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(
      buf,
      size,
      fmt,
      hex_format_buffer(value_.data(), value_.size(), keep_ascii_).c_str());
}

void PrintableBuffer::keep_ascii(bool value)
{
  keep_ascii_ = value;
}

int PrintableCString::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(buf, size, fmt, value_);
}

int PrintableInt::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(buf, size, fmt, value_);
}

int PrintableSInt::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(buf, size, fmt, value_);
}
} // namespace bpftrace
