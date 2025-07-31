#include <climits>
#include <elf.h>
#include <iostream>
#include <limits>
#include <memory>

#include "async/relocations.h"

namespace bpftrace::async {

using namespace bpftrace::arch;

char RelocationError::ID;

void RelocationError::log(llvm::raw_ostream& OS) const
{
  OS << "Failed to relocate type " << relocation_type_ << ":" << msg_;
}

template <typename T>
bool fits_in_range(uint64_t value)
{
  if constexpr (std::is_signed_v<T>) {
    return static_cast<int64_t>(value) >= std::numeric_limits<T>::min() &&
           static_cast<int64_t>(value) <= std::numeric_limits<T>::max();
  } else {
    return value <= std::numeric_limits<T>::max();
  }
}

#ifndef R_X86_64_GOTPCRELX
#define R_X86_64_GOTPCRELX 41
#endif

template <>
Result<> RelocationHandler<Machine::X86_64>::apply(uint32_t type,
                                                   uint8_t* patch_location,
                                                   uint64_t symbol_addr,
                                                   int64_t addend,
                                                   uint64_t pc)
{
  switch (type) {
    case R_X86_64_NONE:
      // No operation.
      return OK();

    case R_X86_64_64: {
      // Direct 64-bit relocation.
      uint64_t value = symbol_addr + addend;
      *reinterpret_cast<uint64_t*>(patch_location) = value;
      return OK();
    }

    case R_X86_64_PC32: {
      // PC-relative 32-bit relocation.
      uint64_t actual_pc = pc ? pc : reinterpret_cast<uint64_t>(patch_location);
      int64_t value = symbol_addr + addend - actual_pc;
      if (!fits_in_range<int32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "PC32 relocation out of range");
      }
      *reinterpret_cast<int32_t*>(patch_location) = static_cast<int32_t>(value);
      return OK();
    }

    case R_X86_64_32: {
      // Direct 32-bit zero-extended relocation.
      uint64_t value = symbol_addr + addend;
      if (!fits_in_range<uint32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "32-bit relocation out of range");
      }
      *reinterpret_cast<uint32_t*>(patch_location) = static_cast<uint32_t>(
          value);
      return OK();
    }

    case R_X86_64_32S: {
      // Direct 32-bit sign-extended relocation.
      uint64_t value = symbol_addr + addend;
      if (!fits_in_range<int32_t>(value)) {
        return make_error<RelocationError>(type, "32S relocation out of range");
      }
      *reinterpret_cast<int32_t*>(patch_location) = static_cast<int32_t>(value);
      return OK();
    }

    case R_X86_64_PLT32: {
      // PLT-relative 32-bit relocation (treat as PC32 for now).
      uint64_t actual_pc = pc ? pc : reinterpret_cast<uint64_t>(patch_location);
      int64_t value = symbol_addr + addend - actual_pc;
      if (!fits_in_range<int32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "PLT32 relocation out of range");
      }
      *reinterpret_cast<int32_t*>(patch_location) = static_cast<int32_t>(value);
      return OK();
    }

    case R_X86_64_GOTPCREL: {
      // GOT PC-relative 32-bit relocation.
      uint64_t actual_pc = pc ? (pc + 4)
                              : (reinterpret_cast<uint64_t>(patch_location) +
                                 4);
      int64_t value = symbol_addr - actual_pc;
      if (!fits_in_range<int32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "GOTPCREL relocation out of range");
      }
      *reinterpret_cast<int32_t*>(patch_location) = static_cast<int32_t>(value);
      return OK();
    }

    case R_X86_64_GOTPCRELX: {
      // GOT PC-relative 32-bit relocation with relaxation.
      uint64_t actual_pc = pc ? (pc + 4)
                              : (reinterpret_cast<uint64_t>(patch_location) +
                                 4);
      int64_t value = symbol_addr - actual_pc;
      if (!fits_in_range<int32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "GOTPCRELX relocation out of range");
      }
      *reinterpret_cast<int32_t*>(patch_location) = static_cast<int32_t>(value);
      return OK();
    }

    default:
      return make_error<RelocationError>(type, "Unsupported relocation type");
  }
}

template <>
Result<> RelocationHandler<Machine::X86_64>::trampoline(
    uint8_t* trampoline_addr,
    uint64_t target_addr)
{
  // Generate x86_64 trampoline: movabs rax, target; jmp rax
  // movabs rax, imm64 (10 bytes): 48 B8 [8-byte immediate]
  trampoline_addr[0] = 0x48; // REX.W
  trampoline_addr[1] = 0xB8; // MOV RAX, imm64
  *reinterpret_cast<uint64_t*>(&trampoline_addr[2]) = target_addr;

  // jmp rax (2 bytes): FF E0
  trampoline_addr[10] = 0xFF; // JMP
  trampoline_addr[11] = 0xE0; // r/m64 = rax

  return OK();
}

template <>
size_t RelocationHandler<Machine::X86_64>::trampoline_size()
{
  return 16; // Padded to 16 bytes for alignment.
}

template <>
bool RelocationHandler<Machine::X86_64>::needs_trampoline(uint32_t type,
                                                          int64_t distance)
{
  switch (type) {
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
    case R_X86_64_GOTPCREL:
    case R_X86_64_GOTPCRELX:
      // 32-bit PC-relative relocations need trampolines if distance > ±2GB.
      return distance < INT32_MIN || distance > INT32_MAX;
    default:
      return false; // Other relocation types don't need trampolines.
  }
}

template <>
Result<> RelocationHandler<Machine::ARM64>::apply(uint32_t type,
                                                  uint8_t* patch_location,
                                                  uint64_t symbol_addr,
                                                  int64_t addend,
                                                  uint64_t pc)
{
  switch (type) {
    case R_AARCH64_NONE:
      // No operation
      return OK();

    case R_AARCH64_ABS64: {
      // Direct 64-bit relocation.
      uint64_t value = symbol_addr + addend;
      *reinterpret_cast<uint64_t*>(patch_location) = value;
      return OK();
    }

    case R_AARCH64_ABS32: {
      // Direct 32-bit relocation.
      uint64_t value = symbol_addr + addend;
      if (!fits_in_range<uint32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "ABS32 relocation out of range");
      }
      *reinterpret_cast<uint32_t*>(patch_location) = static_cast<uint32_t>(
          value);
      return OK();
    }

    case R_AARCH64_CALL26:
    case R_AARCH64_JUMP26: {
      // 26-bit PC-relative branch.
      uint64_t actual_pc = pc ? pc : reinterpret_cast<uint64_t>(patch_location);
      int64_t offset = symbol_addr + addend - actual_pc;

      // Check 26-bit range (±128MB).
      if (offset < -0x8000000 || offset > 0x7FFFFFF || (offset & 3) != 0) {
        return make_error<RelocationError>(
            type, "CALL26/JUMP26 relocation out of range or misaligned");
      }

      uint32_t insn = *reinterpret_cast<uint32_t*>(patch_location);
      insn = (insn & 0xFC000000) | ((offset >> 2) & 0x03FFFFFF);
      *reinterpret_cast<uint32_t*>(patch_location) = insn;
      return OK();
    }

    case R_AARCH64_PREL32: {
      // PC-relative 32-bit.
      uint64_t actual_pc = pc ? pc : reinterpret_cast<uint64_t>(patch_location);
      int64_t value = symbol_addr + addend - actual_pc;
      if (!fits_in_range<int32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "PREL32 relocation out of range");
      }
      *reinterpret_cast<int32_t*>(patch_location) = static_cast<int32_t>(value);
      return OK();
    }

    default:
      return make_error<RelocationError>(type, "Unsupported relocation type");
  }

  return OK();
}

template <>
Result<> RelocationHandler<Machine::ARM64>::trampoline(uint8_t* trampoline_addr,
                                                       uint64_t target_addr)
{
  // Generate ARM64 trampoline using LDR + BR
  // ldr x16, #8    (4 bytes): 0x58000050
  // br x16         (4 bytes): 0xD61F0200
  // target_addr    (8 bytes): 64-bit address
  uint32_t* insn = reinterpret_cast<uint32_t*>(trampoline_addr);
  insn[0] = 0x58000050; // LDR X16, #8 (load from PC+8)
  insn[1] = 0xD61F0200; // BR X16 (branch to X16)
  *reinterpret_cast<uint64_t*>(&trampoline_addr[8]) = target_addr;

  return OK();
}

template <>
size_t RelocationHandler<Machine::ARM64>::trampoline_size()
{
  return 16; // 16 bytes total.
}

template <>
bool RelocationHandler<Machine::ARM64>::needs_trampoline(uint32_t type,
                                                         int64_t distance)
{
  switch (type) {
    case R_AARCH64_CALL26:
    case R_AARCH64_JUMP26:
      // 26-bit branch instructions need trampolines if distance > ±128MB.
      return distance < -0x8000000 || distance > 0x7FFFFFF;
    case R_AARCH64_PREL32:
      // 32-bit PC-relative relocations need trampolines if distance > ±2GB.
      return distance < INT32_MIN || distance > INT32_MAX;
    default:
      return false;
  }
}

template <>
Result<> RelocationHandler<Machine::ARM>::apply(uint32_t type,
                                                uint8_t* patch_location,
                                                uint64_t symbol_addr,
                                                int64_t addend,
                                                uint64_t pc)
{
  switch (type) {
    case R_ARM_NONE:
      // No operation.
      return OK();

    case R_ARM_ABS32: {
      // Direct 32-bit relocation.
      uint64_t value = symbol_addr + addend;
      if (!fits_in_range<uint32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "ABS32 relocation out of range");
      }
      *reinterpret_cast<uint32_t*>(patch_location) = static_cast<uint32_t>(
          value);
      return OK();
    }

    case R_ARM_REL32: {
      // PC-relative 32-bit.
      uint64_t actual_pc = pc ? pc : reinterpret_cast<uint64_t>(patch_location);
      int64_t value = symbol_addr + addend - actual_pc;
      if (!fits_in_range<int32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "REL32 relocation out of range");
      }
      *reinterpret_cast<int32_t*>(patch_location) = static_cast<int32_t>(value);
      return OK();
    }

    case R_ARM_CALL:
    case R_ARM_JUMP24: {
      // 24-bit PC-relative branch.
      uint64_t actual_pc = pc ? pc : reinterpret_cast<uint64_t>(patch_location);
      int64_t offset = symbol_addr + addend - actual_pc - 8; // ARM PC is +8

      // Check 24-bit range (±32MB)
      if (offset < -0x2000000 || offset > 0x1FFFFFF || (offset & 3) != 0) {
        return make_error<RelocationError>(
            type, "CALL/JUMP24 relocation out of range or misaligned");
      }

      uint32_t insn = *reinterpret_cast<uint32_t*>(patch_location);
      insn = (insn & 0xFF000000) | ((offset >> 2) & 0x00FFFFFF);
      *reinterpret_cast<uint32_t*>(patch_location) = insn;
      return OK();
    }

    default:
      return make_error<RelocationError>(type, "Unsupported relocation type");
  }

  return OK();
}

template <>
Result<> RelocationHandler<Machine::ARM>::trampoline(uint8_t* trampoline_addr,
                                                     uint64_t target_addr)
{
  // Generate ARM trampoline using LDR PC
  // ldr pc, [pc, #-4]  (4 bytes): 0xE51FF004
  // target_addr        (4 bytes): 32-bit address (ARM is 32-bit)
  uint32_t* insn = reinterpret_cast<uint32_t*>(trampoline_addr);
  insn[0] = 0xE51FF004;                         // LDR PC, [PC, #-4]
  insn[1] = static_cast<uint32_t>(target_addr); // Target address (truncated to
                                                // 32-bit)

  return OK();
}

template <>
size_t RelocationHandler<Machine::ARM>::trampoline_size()
{
  return 8; // 8 bytes total.
}

template <>
bool RelocationHandler<Machine::ARM>::needs_trampoline(uint32_t type,
                                                       int64_t distance)
{
  switch (type) {
    case R_ARM_CALL:
    case R_ARM_JUMP24:
      // 24-bit branch instructions need trampolines if distance > ±32MB.
      return distance < -0x2000000 || distance > 0x1FFFFFF;
    case R_ARM_REL32:
      // 32-bit PC-relative relocations need trampolines if distance > ±2GB.
      return distance < INT32_MIN || distance > INT32_MAX;
    default:
      return false;
  }
}

template <>
Result<> RelocationHandler<Machine::RISCV64>::apply(uint32_t type,
                                                    uint8_t* patch_location,
                                                    uint64_t symbol_addr,
                                                    int64_t addend,
                                                    uint64_t pc)
{
  switch (type) {
    case R_RISCV_NONE:
      // No operation.
      return OK();

    case R_RISCV_64: {
      // Direct 64-bit relocation.
      uint64_t value = symbol_addr + addend;
      *reinterpret_cast<uint64_t*>(patch_location) = value;
      return OK();
    }

    case R_RISCV_32: {
      // Direct 32-bit relocation.
      uint64_t value = symbol_addr + addend;
      if (!fits_in_range<uint32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "32-bit relocation out of range");
      }
      *reinterpret_cast<uint32_t*>(patch_location) = static_cast<uint32_t>(
          value);
      return OK();
    }

    case R_RISCV_32_PCREL: {
      // PC-relative 32-bit.
      uint64_t actual_pc = pc ? pc : reinterpret_cast<uint64_t>(patch_location);
      int64_t value = symbol_addr + addend - actual_pc;
      if (!fits_in_range<int32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "32_PCREL relocation out of range");
      }
      *reinterpret_cast<int32_t*>(patch_location) = static_cast<int32_t>(value);
      return OK();
    }

    default:
      return make_error<RelocationError>(type, "Unsupported relocation type");
  }

  return OK();
}

template <>
Result<> RelocationHandler<Machine::RISCV64>::trampoline(
    uint8_t* trampoline_addr,
    uint64_t target_addr)
{
  // Generate RISC-V trampoline using AUIPC + JALR
  uint32_t* insn = reinterpret_cast<uint32_t*>(trampoline_addr);
  insn[0] = 0x00000297; // AUIPC T0, 0
  insn[1] = 0x0082B283; // LD T0, 8(T0)
  insn[2] = 0x00028067; // JALR X0, T0, 0
  insn[3] = 0x00000000; // Padding
  *reinterpret_cast<uint64_t*>(&trampoline_addr[16]) = target_addr;

  return OK();
}

template <>
size_t RelocationHandler<Machine::RISCV64>::trampoline_size()
{
  return 24;
}

template <>
bool RelocationHandler<Machine::RISCV64>::needs_trampoline(uint32_t type,
                                                           int64_t distance)
{
  switch (type) {
    case R_RISCV_32_PCREL:
      return distance < INT32_MIN || distance > INT32_MAX;
    default:
      return false;
  }
}

template <>
Result<> RelocationHandler<Machine::S390X>::apply(uint32_t type,
                                                  uint8_t* patch_location,
                                                  uint64_t symbol_addr,
                                                  int64_t addend,
                                                  uint64_t pc)
{
  switch (type) {
    case R_390_NONE:
      // No operation.
      return OK();

    case R_390_64: {
      // Direct 64-bit relocation.
      uint64_t value = symbol_addr + addend;
      *reinterpret_cast<uint64_t*>(patch_location) = value;
      return OK();
    }

    case R_390_32: {
      // Direct 32-bit relocation.
      uint64_t value = symbol_addr + addend;
      if (!fits_in_range<uint32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "32-bit relocation out of range");
      }
      *reinterpret_cast<uint32_t*>(patch_location) = static_cast<uint32_t>(
          value);
      return OK();
    }

    case R_390_PC32: {
      // PC-relative 32-bit.
      uint64_t actual_pc = pc ? pc : reinterpret_cast<uint64_t>(patch_location);
      int64_t value = symbol_addr + addend - actual_pc;
      if (!fits_in_range<int32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "PC32 relocation out of range");
      }
      *reinterpret_cast<int32_t*>(patch_location) = static_cast<int32_t>(value);
      return OK();
    }

    default:
      return make_error<RelocationError>(type, "Unsupported relocation type");
  }

  return OK();
}

template <>
Result<> RelocationHandler<Machine::S390X>::trampoline(uint8_t* trampoline_addr,
                                                       uint64_t target_addr)
{
  // LARL R1, +8 (load address of target_addr into R1)
  uint8_t* code = trampoline_addr;
  code[0] = 0xC0;
  code[1] = 0x10; // LARL R1
  code[2] = 0x00;
  code[3] = 0x00;
  code[4] = 0x00;
  code[5] = 0x04; // offset +8

  // BR R1 (branch to R1)
  code[6] = 0x07;
  code[7] = 0xF1; // BR R1

  *reinterpret_cast<uint64_t*>(&trampoline_addr[8]) = target_addr;

  return OK();
}

template <>
size_t RelocationHandler<Machine::S390X>::trampoline_size()
{
  return 16; // 16 bytes total.
}

template <>
bool RelocationHandler<Machine::S390X>::needs_trampoline(uint32_t type,
                                                         int64_t distance)
{
  switch (type) {
    case R_390_PC32:
      // 32-bit PC-relative relocations need trampolines if distance > ±2GB.
      return distance < INT32_MIN || distance > INT32_MAX;
    default:
      return false;
  }
}

template <>
Result<> RelocationHandler<Machine::MIPS64>::apply(uint32_t type,
                                                   uint8_t* patch_location,
                                                   uint64_t symbol_addr,
                                                   int64_t addend,
                                                   [[maybe_unused]] uint64_t pc)
{
  switch (type) {
    case R_MIPS_NONE:
      // No operation.
      return OK();

    case R_MIPS_64: {
      // Direct 64-bit relocation.
      uint64_t value = symbol_addr + addend;
      *reinterpret_cast<uint64_t*>(patch_location) = value;
      return OK();
    }

    case R_MIPS_32: {
      // Direct 32-bit relocation.
      uint64_t value = symbol_addr + addend;
      if (!fits_in_range<uint32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "32-bit relocation out of range");
      }
      *reinterpret_cast<uint32_t*>(patch_location) = static_cast<uint32_t>(
          value);
      return OK();
    }

    default:
      return make_error<RelocationError>(type, "Unsupported relocation type");
  }

  return OK();
}

template <>
Result<> RelocationHandler<Machine::MIPS64>::trampoline(
    uint8_t* trampoline_addr,
    uint64_t target_addr)
{
  uint32_t* insn = reinterpret_cast<uint32_t*>(trampoline_addr);
  insn[0] = 0xDF390010; // LD $t9, 16($zero) - simplified
  insn[1] = 0x03200008; // JR $t9
  insn[2] = 0x00000000; // NOP (delay slot)
  insn[3] = 0x00000000; // Padding
  *reinterpret_cast<uint64_t*>(&trampoline_addr[16]) = target_addr;

  return OK();
}

#ifndef R_LARCH_NONE
#define R_LARCH_NONE 0
#endif
#ifndef R_LARCH_32
#define R_LARCH_32 1
#endif
#ifndef R_LARCH_64
#define R_LARCH_64 2
#endif
#ifndef R_LARCH_32_PCREL
#define R_LARCH_32_PCREL 99
#endif

template <>
Result<> RelocationHandler<Machine::LOONGARCH64>::apply(uint32_t type,
                                                        uint8_t* patch_location,
                                                        uint64_t symbol_addr,
                                                        int64_t addend,
                                                        uint64_t pc)
{
  switch (type) {
    case R_LARCH_NONE:
      // No operation.
      return OK();

    case R_LARCH_64: {
      // Direct 64-bit relocation.
      uint64_t value = symbol_addr + addend;
      *reinterpret_cast<uint64_t*>(patch_location) = value;
      return OK();
    }

    case R_LARCH_32: {
      // Direct 32-bit relocation.
      uint64_t value = symbol_addr + addend;
      if (!fits_in_range<uint32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "32-bit relocation out of range");
      }
      *reinterpret_cast<uint32_t*>(patch_location) = static_cast<uint32_t>(
          value);
      return OK();
    }

    case R_LARCH_32_PCREL: {
      // PC-relative 32-bit
      uint64_t actual_pc = pc ? pc : reinterpret_cast<uint64_t>(patch_location);
      int64_t value = symbol_addr + addend - actual_pc;
      if (!fits_in_range<int32_t>(value)) {
        return make_error<RelocationError>(type,
                                           "32_PCREL relocation out of range");
      }
      *reinterpret_cast<int32_t*>(patch_location) = static_cast<int32_t>(value);
      return OK();
    }

    default:
      return make_error<RelocationError>(type, "Unsupported relocation type");
  }

  return OK();
}

template <>
Result<> RelocationHandler<Machine::LOONGARCH64>::trampoline(
    uint8_t* trampoline_addr,
    uint64_t target_addr)
{
  // pcaddu12i $t0, 0   (4 bytes): load PC to $t0
  // ld.d $t0, $t0, 8   (4 bytes): load target from $t0+8
  // jirl $zero, $t0, 0 (4 bytes): jump to $t0
  // target_addr        (8 bytes): 64-bit address
  uint32_t* insn = reinterpret_cast<uint32_t*>(trampoline_addr);
  insn[0] = 0x1C00000C; // PCADDU12I $t0, 0 - simplified
  insn[1] = 0x28C0218C; // LD.D $t0, $t0, 8 - simplified
  insn[2] = 0x4C000180; // JIRL $zero, $t0, 0 - simplified
  insn[3] = 0x00000000; // Padding
  *reinterpret_cast<uint64_t*>(&trampoline_addr[16]) = target_addr;

  return OK();
}

template <>
size_t RelocationHandler<Machine::LOONGARCH64>::trampoline_size()
{
  return 24; // 24 bytes total.
}

template <>
bool RelocationHandler<Machine::LOONGARCH64>::needs_trampoline(uint32_t type,
                                                               int64_t distance)
{
  switch (type) {
    case R_LARCH_32_PCREL:
      // 32-bit PC-relative relocations need trampolines if distance > ±2GB.
      return distance < INT32_MIN || distance > INT32_MAX;
    default:
      return false;
  }
}

} // namespace bpftrace::async
