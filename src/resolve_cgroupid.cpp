#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifdef HAVE_NAME_TO_HANDLE_AT

# include <sys/types.h>
# include <sys/stat.h>

#else

# include <unistd.h>
# include <sys/syscall.h>

#endif

#include <fcntl.h>

#include <stdexcept>

#include "act_helpers.h"
#include "resolve_cgroupid.h"

namespace
{

#ifndef HAVE_NAME_TO_HANDLE_AT

struct file_handle
{
  unsigned int handle_bytes;
  int handle_type;
  char f_handle[0];
};

int name_to_handle_at(int dirfd, const char *pathname,
                      struct file_handle *handle,
                      int *mount_id, int flags)
{
  return (int)syscall(SYS_name_to_handle_at, dirfd, pathname, handle, mount_id, flags);
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
struct cgid_file_handle
{
  file_handle *as_file_handle_ptr()
  {
    return reinterpret_cast<file_handle*>(this);
  }

  unsigned int handle_bytes = sizeof(std::uint64_t);
  int handle_type;
  std::uint64_t cgid;
};

ACTH_ASSERT_SAME_SIZE(cgid_file_handle, file_handle, std::uint64_t);
ACTH_ASSERT_SAME_MEMBER(cgid_file_handle, handle_bytes, file_handle, handle_bytes);
ACTH_ASSERT_SAME_MEMBER(cgid_file_handle, handle_type, file_handle, handle_type);
ACTH_ASSERT_SAME_OFFSET(cgid_file_handle, cgid, file_handle, f_handle);

}

namespace bpftrace_linux
{

std::uint64_t resolve_cgroupid(const std::string &path)
{
  cgid_file_handle cfh;
  int mount_id;
  auto err = name_to_handle_at(AT_FDCWD, path.c_str(), cfh.as_file_handle_ptr(), &mount_id, 0);
  if (err < 0) {
    throw std::runtime_error("cgroup '" + path + "' not found");
  }

  return cfh.cgid;
}

}
