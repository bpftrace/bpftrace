#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_NAME_TO_HANDLE_AT
#include <sys/stat.h>
#include <sys/types.h>
#else
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <map>
#include <ranges>
#include <regex>
#include <sys/stat.h>

#include "util/cgroup.h"
#include "util/wildcard.h"

namespace bpftrace::util {

std::string get_cgroup_path_in_hierarchy(uint64_t cgroupid,
                                         std::string base_path)
{
  static std::map<std::pair<uint64_t, std::string>, std::string> path_cache;
  struct stat path_st;

  auto cached_path = path_cache.find({ cgroupid, base_path });
  if (cached_path != path_cache.end() &&
      stat(cached_path->second.c_str(), &path_st) >= 0 &&
      path_st.st_ino == cgroupid)
    return cached_path->second;

  // Check for root cgroup path separately, since recursive_directory_iterator
  // does not iterate over base directory
  if (stat(base_path.c_str(), &path_st) >= 0 && path_st.st_ino == cgroupid) {
    path_cache[{ cgroupid, base_path }] = "/";
    return "/";
  }

  for (const auto &path_iter :
       std::filesystem::recursive_directory_iterator(base_path)) {
    if (stat(path_iter.path().c_str(), &path_st) < 0)
      return "";
    if (path_st.st_ino == cgroupid) {
      // Base directory is not a part of cgroup path
      path_cache[{ cgroupid, base_path }] = path_iter.path().string().substr(
          base_path.length());
      return path_cache[{ cgroupid, base_path }];
    }
  }

  return "";
}

std::array<std::vector<std::string>, 2> get_cgroup_hierarchy_roots()
{
  // Get all cgroup mounts and their type (cgroup/cgroup2) from /proc/mounts
  std::ifstream mounts_file("/proc/mounts");
  std::array<std::vector<std::string>, 2> result;

  const std::regex cgroup_mount_regex("(cgroup[2]?) (\\S*)[ ]?.*");
  for (std::string line; std::getline(mounts_file, line);) {
    std::smatch match;
    if (std::regex_match(line, match, cgroup_mount_regex)) {
      if (std::filesystem::is_directory(match[2].str())) {
        if (match[1].str() == "cgroup") {
          result[0].push_back(match[2].str());
        } else if (match[1].str() == "cgroup2") {
          result[1].push_back(match[2].str());
        }
      }
    }
  }

  mounts_file.close();
  return result;
}

std::vector<std::pair<std::string, std::string>> get_cgroup_paths(
    uint64_t cgroupid,
    std::string filter)
{
  auto roots = get_cgroup_hierarchy_roots();

  // Replace cgroup version with cgroup mount point directory name for cgroupv1
  // roots and "unified" for cgroupv2 roots
  auto types_v1 = roots[0] |
                  std::views::transform(
                      [&](auto &root) -> std::pair<std::string, std::string> {
                        return {
                          std::filesystem::path(root).filename().string(), root
                        };
                      });
  auto types_v2 = roots[1] |
                  std::views::transform(
                      [&](auto &root) -> std::pair<std::string, std::string> {
                        return { "unified", root };
                      });

  // Filter roots
  bool start_wildcard, end_wildcard;
  auto tokens = get_wildcard_tokens(filter, start_wildcard, end_wildcard);
  auto filter_func = std::views::filter([&](auto pair) -> bool {
    return wildcard_match(pair.first, tokens, start_wildcard, end_wildcard);
  });
  auto filtered_v1 = types_v1 | filter_func;
  auto filtered_v2 = types_v2 | filter_func;

  // Get cgroup path for each root
  auto get_path_func = std::views::transform(
      [&](auto pair) -> std::pair<std::string, std::string> {
        return { pair.first,
                 get_cgroup_path_in_hierarchy(cgroupid, pair.second) };
      });
  auto paths_v1 = filtered_v1 | get_path_func;
  auto paths_v2 = filtered_v2 | get_path_func;

  // Return paths with v2 first, then v1 sorted lexically by name.
  std::vector<std::pair<std::string, std::string>> sorted(paths_v2.begin(),
                                                          paths_v2.end());
  std::vector<std::pair<std::string, std::string>> sorted_v1(paths_v1.begin(),
                                                             paths_v1.end());
  std::ranges::sort(sorted_v1);
  sorted.insert(sorted.end(), sorted_v1.begin(), sorted_v1.end());
  return sorted;
}

namespace {

// Annoying C type helpers.
//
// C headers sometimes contain struct ending with a flexible array
// member, which is not supported in C++. An example of such a type is
// file_handle from fcntl.h (man name_to_handle_at)
//
// Here are some helper macros helping to ensure if the C++
// counterpart has members of the same type and offset.

template <typename T, typename M>
M get_member_type(M T::*);

} // namespace

#define ACTH_SAME_SIZE(cxxtype, ctype, extra_type)                             \
  (sizeof(cxxtype) == sizeof(ctype) + sizeof(extra_type))
#define ACTH_GET_TYPE_OF(mem) decltype(get_member_type(&mem))
#define ACTH_SAME_OFFSET(cxxtype, cxxmem, ctype, cmem)                         \
  (std::is_standard_layout_v<cxxtype> && std::is_standard_layout_v<ctype> &&   \
   (offsetof(cxxtype, cxxmem) == offsetof(ctype, cmem)))
#define ACTH_SAME_TYPE(cxxtype, cxxmem, ctype, cmem)                           \
  std::is_same_v<ACTH_GET_TYPE_OF(cxxtype ::cxxmem),                           \
                 ACTH_GET_TYPE_OF(ctype ::cmem)>

#define ACTH_ASSERT_SAME_SIZE(cxxtype, ctype, extra_type)                      \
  static_assert(ACTH_SAME_SIZE(cxxtype, ctype, extra_type),                    \
                "assumption that is broken: " #cxxtype " == " #ctype           \
                " + " #extra_type)
#define ACTH_ASSERT_SAME_OFFSET(cxxtype, cxxmem, ctype, cmem)                  \
  static_assert(ACTH_SAME_OFFSET(cxxtype, cxxmem, ctype, cmem),                \
                "assumption that is broken: " #cxxtype "::" #cxxmem            \
                " is at the same offset as " #ctype "::" #cmem)
#define ACTH_ASSERT_SAME_TYPE(cxxtype, cxxmem, ctype, cmem)                    \
  static_assert(ACTH_SAME_TYPE(cxxtype, cxxmem, ctype, cmem),                  \
                "assumption that is broken: " #cxxtype "::" #cxxmem            \
                " has the same type as " #ctype "::" #cmem)
#define ACTH_ASSERT_SAME_MEMBER(cxxtype, cxxmem, ctype, cmem)                  \
  ACTH_ASSERT_SAME_TYPE(cxxtype, cxxmem, ctype, cmem);                         \
  ACTH_ASSERT_SAME_OFFSET(cxxtype, cxxmem, ctype, cmem)

#ifndef HAVE_NAME_TO_HANDLE_AT

struct file_handle {
  unsigned int handle_bytes;
  int handle_type;
  char f_handle[0];
};

int name_to_handle_at(int dirfd,
                      const char *pathname,
                      struct file_handle *handle,
                      int *mount_id,
                      int flags)
{
  return static_cast<int>(
      syscall(SYS_name_to_handle_at, dirfd, pathname, handle, mount_id, flags));
}

#endif

// Not embedding file_handle directly in cgid_file_handle, because C++
// has problems with zero-sized array as struct members and
// file_handle's f_handle is a zero-sized array.
//
// Also, not embedding file_handle through the public inheritance,
// since checking for member offsets with offsetof within a
// non-standard-layout type is conditionally-supported (so compilers
// are not required to support it). And we want to do it to make sure
// we got the wrapper right.
//
// Hence open coding the file_handle members directly in
// cgid_file_handle and the static asserts following it.
struct cgid_file_handle {
  file_handle *as_file_handle_ptr()
  {
    return reinterpret_cast<file_handle *>(this);
  }

  unsigned int handle_bytes = sizeof(std::uint64_t);
  int handle_type;
  std::uint64_t cgid;
};

ACTH_ASSERT_SAME_SIZE(cgid_file_handle, file_handle, std::uint64_t);
ACTH_ASSERT_SAME_MEMBER(cgid_file_handle,
                        handle_bytes,
                        file_handle,
                        handle_bytes);
ACTH_ASSERT_SAME_MEMBER(cgid_file_handle,
                        handle_type,
                        file_handle,
                        handle_type);
ACTH_ASSERT_SAME_OFFSET(cgid_file_handle, cgid, file_handle, f_handle);

Result<uint64_t> resolve_cgroupid(const std::string &path)
{
  cgid_file_handle cfh;
  int mount_id;
  int err = name_to_handle_at(
      AT_FDCWD, path.c_str(), cfh.as_file_handle_ptr(), &mount_id, 0);
  if (err < 0) {
    return make_error<SystemError>("Failed to get cgroupid for '" + path + "'",
                                   err);
  }

  return cfh.cgid;
}

} // namespace bpftrace::util
