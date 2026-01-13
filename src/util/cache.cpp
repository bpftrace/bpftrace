#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <llvm/Config/llvm-config.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/VersionTuple.h>
#include <map>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>

#include "log.h"
#include "util/cache.h"

namespace bpftrace::util {

// Returns the path to the cache directory, creating it if it doesn't
// exist. Returns an error if no path can be found successfully.
static Result<std::filesystem::path> get_cache_dir()
{
  const char *xdg_cache_home = getenv("XDG_CACHE_HOME");
  std::filesystem::path cache_path;

  if (xdg_cache_home) {
    cache_path = xdg_cache_home;
  } else {
    const char *home = std::getenv("HOME");
    if (!home) {
      return make_error<SystemError>(
          "no $XDG_CACHE_HOME or $HOME environment variables set", ENOENT);
    }
    cache_path = home;
    cache_path /= ".cache";
  }

  cache_path /= "bpftrace";

  return cache_path;
}

CacheManager::CacheManager(std::optional<std::filesystem::path> cache_dir)
{
  if (!cache_dir) {
    return; // Intentionally disabled.
  }

  if (!cache_dir->empty()) {
    cache_dir_ = std::move(*cache_dir);
  } else {
    auto auto_dir = get_cache_dir();
    if (auto_dir) {
      // Automatically guessed.
      cache_dir_ = std::move(*auto_dir);
    } else {
      // Not intentionally disabled, but disabled nonetheless.
      LOG(WARNING) << "Cache is disabled: " << auto_dir.takeError();
    }
  }
}

static std::string hash_string(const std::string_view view)
{
  llvm::SHA256 hasher;
  hasher.update(view);
  auto result = hasher.final();
  std::stringstream ss;
  for (auto byte : result) {
    ss << std::hex << (byte >> 4) << (byte & 0x0F);
  }
  return ss.str();
}

std::string CacheObject::compute()
{
  return hash_string(data());
}

Result<CacheObject> CacheObject::from(const std::filesystem::path &path)
{
  // Load the file and read it.
  std::ifstream file(path, std::ios::in | std::ios::binary);
  if (!file) {
    return make_error<SystemError>("failed to open file: " + path.string());
  }
  std::string contents((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
  return CacheObject(std::move(contents));
}

Result<> CacheObject::save(std::filesystem::path &path) const
{
  // Write the string to the file.
  std::ofstream file(path, std::ios::out | std::ios::binary);
  if (!file) {
    return make_error<SystemError>("failed to open file for writing: " +
                                   path.string());
  }
  file << data();
  if (!file) {
    return make_error<SystemError>("failed to write to file: " + path.string());
  }
  return OK();
}

Result<std::map<std::string, CacheObject>> CacheManager::lookup(
    const std::vector<std::string> &keys,
    const std::vector<std::reference_wrapper<const CacheObject>> &inputs,
    const std::vector<std::string> &extensions,
    std::function<Result<std::map<std::string, CacheObject>>()> generator)
{
  // Is the cache disabled?
  if (!cache_dir_) {
    return generator();
  }

  // Create the directory if needed.
  std::error_code ec;
  std::filesystem::create_directories(*cache_dir_, ec);
  if (ec) {
    // If this fails, just run directly.
    LOG(WARNING) << "Unable to create cache directory (" << *cache_dir_
                 << "), skipping cache.";
    cache_dir_.reset();
    return generator();
  }

  // Join the hashes together into a single string, along with the key,
  // and rehash to get the final key.
  std::stringstream ss;
  for (const auto &key : keys) {
    ss << key << ";";
  }
  // Include the host kernel version, and the LLVM version.
  struct utsname uts = {};
  if (uname(&uts) == 0) {
    ss << uts.release << ";";
  } else {
    ss << "unknown_kernel;";
  }
  ss << LLVM_VERSION_STRING;
  // Include all other hashes.
  ss << "#";
  for (const auto &input : inputs) {
    ss << input.get().hash() << ";";
  }
  auto final_key = hash_string(ss.str());

  // Does this already exist? We need to check for any files that
  // are matching, and index them into the map by extension.
  std::map<std::string, std::filesystem::path> existing_files;
  for (const auto &ext : extensions) {
    auto cache_file = *cache_dir_ / (final_key + "." + ext);
    if (std::filesystem::exists(cache_file)) {
      existing_files[ext] = cache_file;
    } else {
      existing_files.clear(); // All or nothing.
      break;
    }
  }
  // Can we satisfy this request?
  if (existing_files.size() == extensions.size()) {
    std::map<std::string, CacheObject> result;
    for (const auto &[ext, path] : existing_files) {
      auto obj = CacheObject::from(path);
      if (!obj) {
        LOG(WARNING) << "Failed to load cache file: " << path << ".";
        break;
      }
      result.emplace(ext, std::move(*obj));
    }
    // Check that we loaded everything.
    if (result.size() == extensions.size()) {
      return result;
    }
  }

  // Attempt to generate the file.
  auto result = generator();
  if (!result) {
    return result.takeError();
  }

  // If this was successful, then save it to the cache.
  for (const auto &ext : extensions) {
    auto cache_file = *cache_dir_ / (final_key + "." + ext);
    if (result->contains(ext)) {
      if (!result->at(ext).save(cache_file)) {
        LOG(WARNING) << "Failed to save cache to " << cache_file << ".";
      }
    } else {
      // This is an error; the generator has not produced the set
      // of files that it promised to.
      LOG(WARNING) << "Generator did not produce cache file: " << ext << ".";
    }
  }

  return std::move(*result);
}

} // namespace bpftrace::util
