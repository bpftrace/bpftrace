#include "util/exceptions.h"

#include <utility>

namespace bpftrace::util {

MountNSException::MountNSException(std::string msg) : msg_(std::move(msg))
{
}

const char *MountNSException::what() const noexcept
{
  return msg_.c_str();
}

} // namespace bpftrace::util
