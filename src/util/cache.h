#pragma once

#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "util/result.h"

namespace bpftrace::util {

class CacheObject {
public:
  // This object supports owned and non-owned references.
  CacheObject(std::string contents)
      : value_(std::move(contents)), hash_(compute()) {};
  CacheObject(std::string_view contents)
      : value_(contents), hash_(compute()) {};
  template <size_t N>
  CacheObject(const char (&contents)[N])
      : value_(std::string_view(contents, N - 1)), hash_(compute()){};

  // This reads from the given path. The data must generally be loaded in
  // order to be used and hashed, so we just enforce this up front.
  static Result<CacheObject> from(const std::filesystem::path &path);

  // Serialize this object to the given path.
  Result<> save(std::filesystem::path &path) const;

  // The string data, as a view.
  std::string_view data() const
  {
    return std::visit([](const auto &v) -> std::string_view { return v; },
                      value_);
  }

  // The hash value for the object.
  const std::string &hash() const
  {
    return hash_;
  }

private:
  std::string compute(); // Computes the hash of `value_`.
  std::variant<std::string, std::string_view> value_;
  std::string hash_;
};

// Simple class that wraps the cache directory;
class CacheManager {
public:
  // If `cache_dir` is empty, the cache is disabled. If it is the empty
  // string, then the default cache directory will be used.
  CacheManager(std::optional<std::filesystem::path> cache_dir = "");

  // On a cache hit, or a successful cache miss, it will return a
  // CacheObject containing the artifact from the cache.
  //
  // Note that the LLVM version and host kernel version are both
  // implicitly included as part of the cache key; this does not
  // need to be done separately by the caller.
  Result<std::map<std::string, CacheObject>> lookup(
      const std::vector<std::string> &keys,
      const std::vector<std::reference_wrapper<const CacheObject>> &inputs,
      const std::vector<std::string> &extensions,
      std::function<Result<std::map<std::string, CacheObject>>()> generator);

  // Convenience overload for accepting a list.
  Result<std::map<std::string, CacheObject>> lookup(
      const std::vector<std::string> &keys,
      const std::vector<CacheObject> &args,
      const std::vector<std::string> &extensions,
      std::function<Result<std::map<std::string, CacheObject>>()> generator)
  {
    std::vector<std::reference_wrapper<const CacheObject>> inputs;
    inputs.reserve(args.size());
    for (const auto &arg : args) {
      inputs.push_back(std::cref(arg));
    }
    return lookup(keys, inputs, extensions, generator);
  }

  // Convenience overload for accepting a single extension.
  Result<CacheObject> lookup(const std::vector<std::string> &keys,
                             const std::vector<CacheObject> &args,
                             const std::string &extension,
                             std::function<Result<CacheObject>()> generator)
  {
    auto result = lookup(keys,
                         args,
                         { extension },
                         [&]() -> Result<std::map<std::string, CacheObject>> {
                           auto result = generator();
                           if (!result) {
                             return result.takeError();
                           }
                           auto m = std::map<std::string, CacheObject>();
                           m.emplace(extension, std::move(*result));
                           return m;
                         });
    if (!result) {
      return result.takeError();
    }
    return result->at(extension);
  }

private:
  // If empty, the cache is disabled.
  std::optional<std::filesystem::path> cache_dir_;
};

} // namespace bpftrace::util
