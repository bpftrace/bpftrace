#define __KERNEL__
#include <asm/errno.h>
#include <asm/posix_types.h>
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

extern int bpf_strnlen(const char *s__ign, size_t count) __ksym __weak;

long __bpf_strnlen(const char *ptr, size_t max_size)
{
  if (bpf_strnlen) {
    return bpf_strnlen(ptr, max_size);
  }
  return -ENOSYS; // Not available, must fall back.
}

extern int bpf_strnstr(const char *s1__ign,
                       const char *s2__ign,
                       size_t len) __ksym __weak;

long __bpf_strnstr(const char *haystack,
                   const char *needle,
                   size_t max_size,
                   long *out)
{
  if (bpf_strnstr) {
    *out = bpf_strnstr(haystack, needle, max_size);
    return 0; // Successfully searched.
  }
  return -ENOSYS;
}
