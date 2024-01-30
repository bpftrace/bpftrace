#include "arch.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <unordered_map>

#include <sys/utsname.h>

namespace bpftrace {
namespace arch {

namespace {

// clang-format off
std::array<std::string, 17> registers_aarch32 = {
  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "fp",
  "ip",
  "sp",
  "lr",
  "pc",
  "cpsr",
};

std::array<std::string, 34> registers_aarch64 = {
  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
  "r16",
  "r17",
  "r18",
  "r19",
  "r20",
  "r21",
  "r22",
  "r23",
  "r24",
  "r25",
  "r26",
  "r27",
  "r28",
  "r29",
  "r30",
  "sp",
  "pc",
  "pstate",
};

// Alternative register names that match struct pt_regs
std::array<std::string, 34> ptrace_registers = {
  "regs[0]",
  "regs[1]",
  "regs[2]",
  "regs[3]",
  "regs[4]",
  "regs[5]",
  "regs[6]",
  "regs[7]",
  "regs[8]",
  "regs[9]",
  "regs[10]",
  "regs[11]",
  "regs[12]",
  "regs[13]",
  "regs[14]",
  "regs[15]",
  "regs[16]",
  "regs[17]",
  "regs[18]",
  "regs[19]",
  "regs[20]",
  "regs[21]",
  "regs[22]",
  "regs[23]",
  "regs[24]",
  "regs[25]",
  "regs[26]",
  "regs[27]",
  "regs[28]",
  "regs[29]",
  "regs[30]",
  "sp",
  "pc",
  "pstate",
};

std::unordered_map<std::string, int> compat_offsets = {
  {"compat_fp", 11},
  {"compat_sp", 13},
  {"compat_lr", 14},
};

// clang-format on

bool is_arm64()
{
  static int ptr_width = get_kernel_ptr_width();

  return ptr_width == 64;
}

int offset_aarch32(const std::string& reg_name)
{
  auto it = find(registers_aarch32.begin(), registers_aarch32.end(), reg_name);
  if (it == registers_aarch32.end())
    return -1;
  return distance(registers_aarch32.begin(), it);
}

int offset_aarch64(const std::string& reg_name)
{
  auto it = find(registers_aarch64.begin(), registers_aarch64.end(), reg_name);
  if (it != registers_aarch64.end())
    return distance(registers_aarch64.begin(), it);

  // Support compat aliases for userspace code executing in the AArch32 state
  auto it_compat = compat_offsets.find(reg_name);
  if (it_compat != compat_offsets.end())
    return it_compat->second;

  // Also allow register names that match the fields in struct pt_regs.
  // These appear in USDT probe arguments.
  it = find(ptrace_registers.begin(), ptrace_registers.end(), reg_name);
  if (it != ptrace_registers.end())
    return distance(ptrace_registers.begin(), it);

  return -1;
}

} // anonymous namespace

int offset(std::string reg_name)
{
  // TODO: consider making this based on the execution state bit in pstate
  return is_arm64() ? offset_aarch64(reg_name) : offset_aarch32(reg_name);
}

int max_arg()
{
  return (is_arm64() ? 8 : 4) - 1; // r0 to r7 on arm64
}

int arg_offset(int arg_num)
{
  // Nth argument is stored at offset N in struct pt_regs
  return arg_num;
}

int ret_offset()
{
  return offset("r0");
}

int pc_offset()
{
  return offset("pc");
}

int sp_offset()
{
  // TODO: this needs to be compat_sp on arm64 if accessing the stack of a
  // 32-bit process (AArch32), but we don't currently have a way to detect that.
  return offset("sp");
}

int arg_stack_offset()
{
  // SP points to the first argument that is passed on the stack
  return 0;
}

std::string name()
{
  return std::string(is_arm64() ? "arm64" : "arm");
}

std::vector<std::string> invalid_watchpoint_modes()
{
  // See arch/arm/kernel/hw_breakpoint.c:arch_build_bp_info in kernel source
  return std::vector<std::string>{
    "rx",
    "wx",
    "rwx",
  };
}

int get_kernel_ptr_width()
{
  // We can't assume that sizeof(void*) in bpftrace is the same as the kernel
  // pointer size (bpftrace can be compiled as a 32-bit binary and run on a
  // 64-bit kernel), so we guess based on the machine field of struct utsname.
  // Note that the uname() syscall can return different values for compat mode
  // processes (e.g. "armv8l" instead of "aarch64"; see COMPAT_UTS_MACHINE), so
  // make sure this is taken into account.
  struct utsname utsname;
  if (uname(&utsname) >= 0) {
    if (!strncmp(utsname.machine, "armv", 4) && utsname.machine[4] < '8')
      return 32;
  }
  return 64;
}

} // namespace arch
} // namespace bpftrace
