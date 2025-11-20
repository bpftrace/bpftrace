#define __KERNEL__
#include <asm/errno.h>
#include <asm/posix_types.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>
#include "errors.h"
#include "strings.h"
#include "syscall.h"

extern int bpf_strnlen(const char *s__ign, size_t count) __ksym __weak;

long __bpf_strnlen(const char *ptr, size_t max_size)
{
  if (bpf_strnlen) {
    return bpf_strnlen(ptr, max_size);
  }
  long sz = 0;
  for (size_t i = 0; i < max_size; ++i) {
    if (ptr[i] == 0) {
      break;
    }
    ++sz;
  }
  return sz;
}

extern int bpf_strnstr(const char *s1__ign,
                       const char *s2__ign,
                       size_t len) __ksym __weak;

int __bpf_strnstr(const char *haystack,
                   const char *needle,
                   size_t haystack_size,
                   size_t needle_size)
{
  if (bpf_strnstr) {
    return bpf_strnstr(haystack, needle, haystack_size);
  }
  if (needle_size > haystack_size) {
    return -1;
  }
  for (size_t i = 0; i < haystack_size; i++) {
    size_t j;
    if (haystack[i] == 0) {
      break;
    }
    for (j = 0; j < needle_size; j++) {
      if (needle[j] == 0) {
        return (int)i;
      }
      size_t k = i + j;
      if (k > haystack_size) {
        break;
      }
      if (haystack[k] != needle[j]) {
        break;
      }
    }

    if (j == needle_size) {
      return (int)i;
    }
  }
  return -1;
}

m_str* __strerror(int errno, m_arg *out) {
  if (errno < 0) {
    errno = -errno;
  }
  if (errno >= 0 && errno <= EHWPOISON) {
    __builtin_memcpy(&out->data, &errors[errno], sizeof(*out));
  } else {
    __builtin_memcpy(&out->data, &unknown_error, sizeof(*out));
  }
  return &out->data;
}

m_str* __syscall_name(int n, m_arg *out) {
  if (n >= 0 && n < NR_SYSCALL_ALIGN_BITS) {
    // To resolve the verifier's complaint that the off range is too large,
    // resulting in "possible" access beyond the range of syscall_names[],
    // we use a constant value to constrain n to help the verifier.
    n &= NR_SYSCALL_ALIGN_BITS;

    // System call numbers are not sequential, so when syscall_names is empty,
    // we return "unknown system call".
    if (syscall_names[n][0] == '\0') {
      __builtin_memcpy(&out->data, &unknown_syscall, sizeof(*out));
    } else {
      __builtin_memcpy(&out->data, &syscall_names[n], sizeof(*out));
    }
  } else {
    __builtin_memcpy(&out->data, &unknown_syscall, sizeof(*out));
  }

  return &out->data;
}
