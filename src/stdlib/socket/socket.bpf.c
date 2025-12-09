#define __KERNEL__
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

struct sock;

__u64 __bpf_socket_cookie(struct sock *sk)
{
  return bpf_get_socket_cookie(sk);
}
