#include "printf.h"
#include "printf_format_types.h"
#include "struct.h"

#include <cstdint>

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

int PrintableString::print(char *buf,
                           size_t size,
                           const char *fmt,
                           ArgumentType)
{
  return snprintf(buf, size, fmt, value_.c_str());
}

int PrintableBuffer::print(char *buf,
                           size_t size,
                           const char *fmt,
                           ArgumentType)
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

int PrintableCString::print(char *buf,
                            size_t size,
                            const char *fmt,
                            ArgumentType)
{
  return snprintf(buf, size, fmt, value_);
}

int PrintableInt::print(char *buf,
                        size_t size,
                        const char *fmt,
                        ArgumentType expected_type)
{
  // Since the value is internally always stored as a 64-bit integer, a cast is
  // needed to ensure that the type of the argument passed to snprintf matches
  // the format specifier.
  // For example, an int64_t argument may be pushed onto the stack while an int
  // is stored in a register, in which case "%d" would print the wrong value if
  // we used value_ without an explicit cast.
  switch (expected_type) {
    case ArgumentType::CHAR:
      return snprintf(buf, size, fmt, static_cast<unsigned char>(value_));
    case ArgumentType::SHORT:
      return snprintf(buf, size, fmt, static_cast<unsigned short>(value_));
    case ArgumentType::INT:
      return snprintf(buf, size, fmt, static_cast<unsigned int>(value_));
    case ArgumentType::LONG:
      return snprintf(buf, size, fmt, static_cast<unsigned long>(value_));
    case ArgumentType::LONG_LONG:
      return snprintf(buf, size, fmt, static_cast<unsigned long long>(value_));
    case ArgumentType::INTMAX_T:
      return snprintf(buf, size, fmt, static_cast<uintmax_t>(value_));
    case ArgumentType::SIZE_T:
      return snprintf(buf, size, fmt, static_cast<size_t>(value_));
    case ArgumentType::PTRDIFF_T:
      return snprintf(buf, size, fmt, static_cast<ptrdiff_t>(value_));
    case ArgumentType::POINTER:
      return snprintf(buf, size, fmt, reinterpret_cast<void *>(value_));
    case ArgumentType::UNKNOWN:
      return snprintf(buf, size, fmt, value_);
  }

  __builtin_unreachable();
}

int PrintableSInt::print(char *buf,
                         size_t size,
                         const char *fmt,
                         ArgumentType expected_type)
{
  switch (expected_type) {
    case ArgumentType::CHAR:
      return snprintf(buf, size, fmt, static_cast<char>(value_));
    case ArgumentType::SHORT:
      return snprintf(buf, size, fmt, static_cast<short>(value_));
    case ArgumentType::INT:
      return snprintf(buf, size, fmt, static_cast<int>(value_));
    case ArgumentType::LONG:
      return snprintf(buf, size, fmt, static_cast<long>(value_));
    case ArgumentType::LONG_LONG:
      return snprintf(buf, size, fmt, static_cast<long long>(value_));
    case ArgumentType::INTMAX_T:
      return snprintf(buf, size, fmt, static_cast<intmax_t>(value_));
    case ArgumentType::SIZE_T:
      return snprintf(buf, size, fmt, static_cast<ssize_t>(value_));
    case ArgumentType::PTRDIFF_T:
      return snprintf(buf, size, fmt, static_cast<ptrdiff_t>(value_));
    case ArgumentType::POINTER:
      return snprintf(buf, size, fmt, reinterpret_cast<void *>(value_));
    case ArgumentType::UNKNOWN:
      return snprintf(buf, size, fmt, value_);
  }

  __builtin_unreachable();
}
} // namespace bpftrace
