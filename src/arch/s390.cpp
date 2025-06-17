#include <unordered_map>

#include "arch.h"

namespace bpftrace::arch {

template <>
size_t Arch<Machine::S390X>::kernel_ptr_width()
{
  return 64;
}

template <>
const std::vector<std::string>& Arch<Machine::S390X>::c_defs()
{
  static std::vector<std::string> defs = {
    "__TARGET_ARCH_s390",
  };
  return defs;
}

template <>
std::optional<std::string> Arch<Machine::S390X>::register_to_pt_regs_expr(
    const std::string& name)
{
  static const std::unordered_map<std::string, std::string> register_exprs = {
    { "arg", "args[0]" },  { "pswmask", "psw.mask" }, { "pswaddr", "psw.addr" },
    { "r0", "gprs[0]" },   { "r1", "gprs[1]" },       { "r2", "gprs[2]" },
    { "r3", "gprs[3]" },   { "r4", "gprs[4]" },       { "r5", "gprs[5]" },
    { "r6", "gprs[6]" },   { "r7", "gprs[7]" },       { "r8", "gprs[8]" },
    { "r9", "gprs[9]" },   { "r10", "gprs[10]" },     { "r11", "gprs[11]" },
    { "r12", "gprs[12]" }, { "r13", "gprs[13]" },     { "r14", "gprs[14]" },
    { "r15", "gprs[15]" },
  };
  auto it = register_exprs.find(name);
  if (it != register_exprs.end()) {
    return it->second;
  }
  return std::nullopt;
}

template <>
std::optional<size_t> Arch<Machine::S390X>::register_to_pt_regs_offset(
    const std::string& name)
{
  static const std::unordered_map<std::string, size_t> register_offsets = {
    { "arg", 0 },   { "pswmask", 8 }, { "pswaddr", 16 }, { "r0", 24 },
    { "r1", 32 },   { "r2", 40 },     { "r3", 48 },      { "r4", 56 },
    { "r5", 64 },   { "r6", 72 },     { "r7", 80 },      { "r8", 88 },
    { "r9", 96 },   { "r10", 104 },   { "r11", 112 },    { "r12", 120 },
    { "r13", 128 }, { "r14", 136 },   { "r15", 144 },
  };
  auto it = register_offsets.find(name);
  if (it != register_offsets.end()) {
    return it->second;
  }
  return std::nullopt;
}

template <>
const std::vector<std::string>& Arch<Machine::S390X>::arguments()
{
  static std::vector<std::string> args = {
    "r2", "r3", "r4", "r5", "r6",
  };
  return args;
}

template <>
size_t Arch<Machine::S390X>::argument_stack_offset()
{
  // For s390x, r2-r6 registers are used as function arguments, then the extra
  // arguments can be found starting at sp+160.
  return 160;
}

template <>
std::string Arch<Machine::S390X>::return_value()
{
  return "r2";
}

template <>
std::string Arch<Machine::S390X>::pc_value()
{
  return "pswaddr";
}

template <>
std::string Arch<Machine::S390X>::sp_value()
{
  return "r15";
}

template <>
const std::unordered_set<std::string>& Arch<Machine::S390X>::watchpoint_modes()
{
  static std::unordered_set<std::string> valid_modes = {};
  return valid_modes;
}

} // namespace bpftrace::arch
