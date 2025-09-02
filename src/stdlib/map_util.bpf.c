#define __VMLINUX_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

int __has_key(void * map, void * key) {
    void * val;
    val = bpf_map_lookup_elem(map, key);
    if (!val) {
        return 1;
    }
    return 0;
}
