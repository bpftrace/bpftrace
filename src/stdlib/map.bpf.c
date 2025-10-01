#define __KERNEL__
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

struct bpf_map;
extern __s64 bpf_map_sum_elem_count(const struct bpf_map *map) __ksym __weak;

_Bool __has_key(void * map, void * key) {
    if (bpf_map_lookup_elem(map, key) == NULL) {
        return 0;
    }
    return 1;
}

static long __empty_map_elem_cb(void *map, const void *key, void *value, void *ctx)
{
    return 0;
}

long __elem_count(void * map) {
    // This was added in kernel version 6.6
    // https://docs.ebpf.io/linux/kfuncs/bpf_map_sum_elem_count/
    if (bpf_map_sum_elem_count) {
        return bpf_map_sum_elem_count(map);
    }
    return bpf_for_each_map_elem(map, &__empty_map_elem_cb, NULL, 0);
}
