#define __VMLINUX_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

void * __has_key(void * map, void * key) {
    return bpf_map_lookup_elem(map, key);
}
