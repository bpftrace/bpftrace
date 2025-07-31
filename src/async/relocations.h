#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

#include "arch/arch.h"
#include "util/result.h"

namespace bpftrace::async {

class RelocationError : public ErrorInfo<RelocationError> {
public:
  static char ID;

  RelocationError(int relocation_type, std::string msg)
      : relocation_type_(relocation_type), msg_(std::move(msg)){};
  void log(llvm::raw_ostream& OS) const override;

private:
  int relocation_type_;
  std::string msg_;
};

template <bpftrace::arch::Machine M>
class RelocationHandler {
public:
  static Result<> apply(uint32_t type,
                        uint8_t* patch_location,
                        uint64_t symbol_addr,
                        int64_t addend,
                        uint64_t pc = 0);

  // Generate a trampoline for long-distance calls.
  static Result<> trampoline(uint8_t* trampoline_addr, uint64_t target_addr);

  // Get the size needed for a trampoline.
  static size_t trampoline_size();

  // Check if this relocation type needs a trampoline.
  static bool needs_trampoline(uint32_t type, int64_t distance);
};

} // namespace bpftrace::async
