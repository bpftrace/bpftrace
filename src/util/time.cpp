#include "util/time.h"

namespace bpftrace::util {

using namespace std::chrono_literals;

std::pair<DisplayUnit, uint64_t> duration_str(
    const std::chrono::duration<uint64_t, std::nano> &ns)
{
  uint64_t count = ns.count();
  uint64_t scale = 1;
  auto unit = DisplayUnit::ns;
  if (count >= std::chrono::duration<uint64_t, std::nano>(1s).count()) {
    unit = DisplayUnit::s;
    scale = std::chrono::duration<uint64_t, std::nano>(1s).count();
  } else if (count >= std::chrono::duration<uint64_t, std::nano>(1ms).count()) {
    unit = DisplayUnit::ms;
    scale = std::chrono::duration<uint64_t, std::nano>(1ms).count();
  } else if (count >= std::chrono::duration<uint64_t, std::nano>(1us).count()) {
    unit = DisplayUnit::us;
    scale = std::chrono::duration<uint64_t, std::nano>(1us).count();
  }
  return { unit, scale };
}

std::ostream &operator<<(std::ostream &out, const DisplayUnit &unit)
{
  switch (unit) {
    case DisplayUnit::ns:
      out << "ns";
      break;
    case DisplayUnit::ms:
      out << "ms";
      break;
    case DisplayUnit::us:
      out << "μs";
      break;
    case DisplayUnit::s:
      out << "s";
      break;
  }
  return out;
}

} // namespace bpftrace::util
