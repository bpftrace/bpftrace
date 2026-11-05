#define __KERNEL__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

unsigned long long __get_socket_cookie(struct sock *sk) {
  return bpf_get_socket_cookie(sk);
}
