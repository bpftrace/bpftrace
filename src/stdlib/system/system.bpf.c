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
