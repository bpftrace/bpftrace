#define __VMLINUX_H__
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

extern __s64 bpf_map_sum_elem_count(const struct bpf_map *map) __ksym __weak;

int __has_key(void * map, void * key) {
    if (bpf_map_lookup_elem(map, key) == NULL) {
        return 1;
    }
    return 0;
}

static long __empty_map_elem_cb(void *map, const void *key, void *value, void *ctx)
{
    return 0;
}

long __len(void * map) {
    if (bpf_map_sum_elem_count) {
        return bpf_map_sum_elem_count(map);
    }
    return bpf_for_each_map_elem(map, &__empty_map_elem_cb, NULL, 0);
}
