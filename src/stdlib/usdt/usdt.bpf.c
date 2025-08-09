#define __VMLINUX_H__
#include <vmlinux.h>
#include <bpf/usdt.bpf.h>

long __usdt_arg(struct pt_regs * ctx, long arg_num)
{
  long _x;
  bpf_usdt_arg(ctx, arg_num, &_x);
  return _x;
}
