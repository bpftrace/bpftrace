#define __KERNEL__
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

// Kernel v7.0+ signature with ctx parameter.
// The ___with_ctx suffix is stripped by libbpf, mapping to kernel symbol "bpf_session_is_return"
extern _Bool bpf_session_is_return___with_ctx(void *ctx) __ksym __weak;

// Kernel < v7.0 signature without ctx parameter.
// The ___no_ctx suffix is stripped by libbpf, mapping to kernel symbol "bpf_session_is_return"
extern _Bool bpf_session_is_return___no_ctx(void) __ksym __weak;

// Try to limit the functions that get added in this file
// as these will always be imported/compiled by every script

// Always called with ctx. If the kernel exposes the newer ctx aware kfunc,
// use it. otherwise fall back to the no arg variant.
_Bool __session_is_return(void *ctx) {
    if (bpf_session_is_return___with_ctx)
        return bpf_session_is_return___with_ctx(ctx);
    if (bpf_session_is_return___no_ctx)
        return bpf_session_is_return___no_ctx();
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
