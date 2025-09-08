#define __KERNEL__
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

int __has_key(void * map, void * key) {
    if (bpf_map_lookup_elem(map, key) == NULL) {
        return 1;
    }
    return 0;
}
