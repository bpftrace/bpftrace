#define __KERNEL__
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

long __bpf_get_func_ip(void *ctx) {
  return (long)bpf_get_func_ip(ctx);
}
