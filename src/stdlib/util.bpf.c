#define __KERNEL__
#include <asm/errno.h>
#include <asm/posix_types.h>
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

// Unlike standard memcmp, we return 1 for true and 0 for false.
// This is so we can easily cast it to a boolean
int __memcmp(const char * mem_left, const char * mem_right, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    if (mem_left[i] != mem_right[i]){
      return 0;
    }
  }

  return 1;
}
