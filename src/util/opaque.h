#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>

namespace bpftrace::util {

// OpaqueValue corresponds to a blob of type-erased memory. It owns its own
// underlying memory, taking a copy if necessary. This allows it to be used
// to read maps, rings, and other locations which may not be permanent.
//
// This class does not really provide safety beyond first-order memory safety.
class OpaqueValue {
private:
  struct OwnedBuffer {
    OwnedBuffer(char *data) : data(data) {};
    OwnedBuffer(const OwnedBuffer &other) = delete;
    OwnedBuffer(OwnedBuffer &&other) = delete;
    OwnedBuffer &operator=(const OwnedBuffer &other) = delete;
    OwnedBuffer &operator=(OwnedBuffer &&other) = delete;
    ~OwnedBuffer()
    {
      free(data);
    }
    char *data;
  };
  using SharedMemory = std::shared_ptr<OwnedBuffer>;
  using Storage = std::variant<uintptr_t, SharedMemory>;

public:
  // Allows for the creation of an OpaqueValue.
  static OpaqueValue alloc(size_t length, std::function<void(char *)> init)
  {
    return { length, init };
  }

  // Create a zerod OpaqueValue.
  static OpaqueValue alloc(size_t length)
  {
    return { length, [&](char *data) { memset(data, 0, length); } };
  }

  // Create a copy of a string.
  static OpaqueValue string(const std::string &s, size_t sz)
  {
    return { sz, [&](char *data) {
              size_t s_sz = std::min(s.size() + 1, sz);
              memcpy(data, s.data(), s_sz);
              memset(data + s_sz, 0, sz - s_sz);
            } };
  }

  // Merge two OpaqueValues together.
  OpaqueValue operator+(const OpaqueValue &other) const
  {
    return { size() + other.size(), [&](char *new_data) {
              memcpy(new_data, data(), size());
              memcpy(new_data + size(), other.data(), other.size());
            } };
  }

  // Creates a copy of any type that has an iterator.
  //
  // This requires that the underlying type has a simple `from`, so we can't do
  // complex types like strings in this way. This is intended for use in tests
  // only and is therefore not optimized for performance in any way.
  template <std::ranges::range T>
  static OpaqueValue from(const T &other)
  {
    OpaqueValue res;
    for (const auto &v : other) {
      res = res + from(v);
    }
    if constexpr (std::is_same_v<T, std::string>) {
      res = res + OpaqueValue::from<char>(0);
    }
    return res;
  }

  // Creates an OpaqueValue from an existing region.
  template <typename T>
  static OpaqueValue from(const T *orig_data, size_t length)
  {
    return { sizeof(T) * length, [&](char *data) {
              memcpy(data,
                     reinterpret_cast<const char *>(orig_data),
                     sizeof(T) * length);
            } };
  }

  // Creates a new OpaqueValue from any trivial type.
  template <typename T>
    requires(std::is_trivially_copyable_v<T>)
  static OpaqueValue from(const T &other)
  {
    return { sizeof(other),
             [&](char *data) { memcpy(data, &other, sizeof(other)); } };
  }

  // Returns bytes available.
  size_t size() const
  {
    return length_ - offset_;
  }

  // Return the number of values that may fit.
  template <typename T>
  size_t count() const
  {
    return size() / sizeof(T);
  }

  // Creates a slice from an existing OpaqueValue.
  //
  // This does not copy any memory, and relies on the original ownership
  // semantics for the current OpaqueValue.
  OpaqueValue slice(size_t offset,
                    std::optional<size_t> length = std::nullopt) const
  {
    size_t l = length ? *length : size() - offset;
    check(offset, l);
    return { mem_, offset_ + offset, offset_ + offset + l };
  }

  // Returns a pointer to the underlying memory for this object.
  //
  // This does not permit any mutation. The only way to mutate an OpaqueValue
  // is with `alloc` that allows for construction-time mutation.
  const char *data() const
  {
    if (std::holds_alternative<uintptr_t>(mem_)) {
      const auto *ptr = std::get_if<uintptr_t>(&mem_);
      return reinterpret_cast<const char *>(ptr) + offset_;
    } else {
      const auto &obj = std::get<SharedMemory>(mem_);
      return obj->data + offset_;
    }
  }

  template <typename T>
    requires(std::is_trivially_copyable_v<T>)
  T bitcast(size_t index = 0) const
  {
    check(sizeof(T) * index, sizeof(T));
    const T *src = reinterpret_cast<const T *>(data()) + index;
    // Some existing types are packed structures that don't have default
    // constructors (although they are trivially copyable). Therefore, if we
    // don't have any alignment constraints, avoid the constructor and do the
    // direct copy out. If we do have alignment constraints, allow the memcpy
    // to do all the heavy lifting.
    if constexpr (std::alignment_of_v<T> <= 1) {
      return *src;
    } else {
      T result;
      std::memcpy(&result, src, sizeof(result));
      return result;
    }
  }

  bool operator==(const OpaqueValue &other) const;
  bool operator!=(const OpaqueValue &other) const;
  bool operator<(const OpaqueValue &other) const;
  size_t hash() const;

private:
  // Creates an OpaqueValue of size zero.
  OpaqueValue() : mem_(static_cast<uintptr_t>(0)) {};

  // Creates a new OpaqueValue.
  OpaqueValue(size_t length, std::function<void(char *)> init) : length_(length)
  {
    if (length > sizeof(uintptr_t)) {
      auto *new_data = static_cast<char *>(malloc(length));
      if (new_data == nullptr) {
        throw std::bad_alloc();
      }
      mem_ = std::make_shared<OwnedBuffer>(new_data);
    }
    init(const_cast<char *>(data()));
  }

  // Low-level constructor.
  OpaqueValue(Storage mem, size_t offset, size_t length)
      : mem_(std::move(mem)), offset_(offset), length_(length) {};

  void check(size_t offset, size_t length) const
  {
    // Check for overflow and underflow.
    if (offset_ + offset < offset_ ||
        offset_ + offset + length < offset_ + offset ||
        offset_ + offset + length > length_) {
      throw std::bad_alloc();
    }
  }

  Storage mem_;
  size_t offset_ = 0;
  size_t length_ = 0;
};

std::ostream &operator<<(std::ostream &out, const OpaqueValue &value);

} // namespace bpftrace::util

namespace std {
template <>
struct hash<bpftrace::util::OpaqueValue> {
  size_t operator()(const bpftrace::util::OpaqueValue &value) const
  {
    return value.hash();
  }
};
} // namespace std
