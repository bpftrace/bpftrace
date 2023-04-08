#include "printf.h"
#include "printf_format_types.h"
#include "struct.h"

namespace bpftrace {

PrintableString::PrintableString(std::string value,
                                 std::optional<size_t> buffer_size,
                                 const char *trunc_trailer)
    : value_(std::move(value))
{
  // Add a trailer if string is truncated
  //
  // The heuristic we use is to check if the string exactly fits inside
  // the buffer (NUL included). If it does, we assume it was truncated.
  // This is obviously not a perfect heuristic, but it solves the majority
  // case well enough and is simple to implement.
  if (buffer_size && (value_.size() + 1 == *buffer_size))
    value_ += trunc_trailer;
}

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
      hex_format_buffer(value_.data(), value_.size(), keep_ascii_, escape_hex_)
          .c_str());
}

void PrintableBuffer::keep_ascii(bool value)
{
  keep_ascii_ = value;
}

void PrintableBuffer::escape_hex(bool value)
{
  escape_hex_ = value;
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
