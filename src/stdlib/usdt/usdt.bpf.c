#define __VMLINUX_H__
#include <vmlinux.h>
#include <bpf/usdt.bpf.h>

// N.B. ctx is type erased because struct pt_regs is in a different location
// depending on kernel version and it's just easier this way
long __usdt_arg(void * ctx, long arg_num)
{
  long _x;
  bpf_usdt_arg(ctx, arg_num, &_x);
  return _x;
}
