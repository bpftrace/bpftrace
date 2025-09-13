#define __KERNEL__
#include <asm/posix_types.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} recursion_map SEC(".maps");

int __try_set_recursion()
{
  __u32 key = 0;
  __u32 *value;

  value = (__u32 *)bpf_map_lookup_elem(&recursion_map, &key);
  if (!value)
    return 0;

  int prev = __sync_fetch_and_or(value, 1);
  if (prev)
    return 0;
  return 1;
}

int __unset_recursion()
{
  __u32 key = 0;
  __u32 *value;

  value = (__u32 *)bpf_map_lookup_elem(&recursion_map, &key);
  if (value)
    *value = 0;

  return 0;
}
