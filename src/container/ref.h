#pragma once

#include <functional>

namespace bpftrace {

/**
 * A non-nullable reference type which can be updated and stored in containers.
 *
 * ref is based on std::reference_wrapper but has a shorter name and
 * getter operator to make it easier to use.
 */
template <typename T>
class ref : public std::reference_wrapper<T> {
public:
  ref(T &t) : std::reference_wrapper<T>{ t }
  {
  }

  constexpr T &operator()() const
  {
    return this->get();
  }

  constexpr T &operator()()
  {
    return this->get();
  }

  constexpr T *ptr() const
  {
    return &this->get();
  }

  constexpr T *ptr()
  {
    return &this->get();
  }

  friend constexpr bool operator==(ref<T> lhs, ref<T> rhs)
  {
    return lhs.ptr() == rhs.ptr();
  }
};

} // namespace bpftrace
