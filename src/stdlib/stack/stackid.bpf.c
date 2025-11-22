#define __KERNEL__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

static __u64 next_stack_id = 1;

// This algo is optimized for the case where most keys already exist
// so it starts off slow but then should speed up as more repeated
// stacks are added to the map
__u64 __get_stack_id(void *map, void *key) {
    __u64 *existing_id = bpf_map_lookup_elem(map, key);
    if (existing_id != NULL) {
        return *existing_id;
    }

    // We need to avoid direct usage of XADD return value due to BPF verifier constraints
    __sync_fetch_and_add(&next_stack_id, 1);
    __u64 new_id = next_stack_id;

    int ret = bpf_map_update_elem(map, key, &new_id, BPF_NOEXIST);
    if (ret == 0) {
        return new_id;
    }

    // Race condition: another thread inserted between our lookup and insert
    existing_id = bpf_map_lookup_elem(map, key);
    if (existing_id != NULL) {
        return *existing_id;
    }

    return 0;
}
