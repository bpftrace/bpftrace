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

long __probe_write_user(void *dst, const void *src, __u32 len) {
    return bpf_probe_write_user(dst, src, len);
}

unsigned long long __get_jiffies() {
    return bpf_jiffies64();
}

unsigned long long __get_rand() {
    return bpf_get_prandom_u32();
}
