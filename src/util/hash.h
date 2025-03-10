#include <functional>

namespace bpftrace::util {

// Combination of 2 hashes
// The algorithm is taken from boost::hash_combine
template <class T>
inline void hash_combine(std::size_t &seed, const T &value)
{
  std::hash<T> hasher;
  seed ^= hasher(value) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

} // namespace bpftrace::util
