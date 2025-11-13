#define __KERNEL__
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

extern _Bool bpf_session_is_return(void) __ksym __weak;

_Bool __session_is_return() {
    if (bpf_session_is_return) {
        return bpf_session_is_return();
    }
    return 0;
}

int __memcmp(const char * mem_left, const char * mem_right, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    if (mem_left[i] != mem_right[i]) {
      return (int)mem_left[i] - (int)mem_right[i];
    }
  }

  return 0;
}
