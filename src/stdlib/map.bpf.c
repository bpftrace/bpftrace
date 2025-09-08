#define __KERNEL__
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

_Bool __has_key(void * map, void * key) {
    if (bpf_map_lookup_elem(map, key) == NULL) {
        return 0;
    }
    return 1;
}
