#define __KERNEL__
#include <asm/errno.h>
#include <asm/posix_types.h>
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

long __get_numa_node_id() {
    return bpf_get_numa_node_id();
}

void __override(void * ctx, __u64 rc) {
    bpf_override_return(ctx, rc);
}

int __memcmp(const char * mem_left, const char * mem_right, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    if (mem_left[i] != mem_right[i]) {
      return (int)mem_left[i] - (int)mem_right[i];
    }
  }

  return 0;
}
