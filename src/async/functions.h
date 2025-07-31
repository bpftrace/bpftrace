#pragma once

#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>

#include "arch/arch.h"
#include "async/memory.h"
#include "util/result.h"

namespace bpftrace::async {

class SymbolNotFoundError : public ErrorInfo<SymbolNotFoundError> {
public:
  static char ID;

  SymbolNotFoundError(std::string symbol_name) : symbol_name_(symbol_name){};
  void log(llvm::raw_ostream& OS) const override;

private:
  std::string symbol_name_;
};

class ELFError : public ErrorInfo<ELFError> {
public:
  static char ID;

  ELFError(int err) : err_(err){};
  void log(llvm::raw_ostream& OS) const override;

private:
  int err_;
};

class Functions {
public:
  // Constructor that takes ELF object file data, and links it within the
  // current process address space. Standardized libc function callbacks are
  // provided, as well as some specialized runtime callbacks.
  static Result<Functions> load(
      const std::span<const char>& object,
      std::map<std::string, void*> external_functions);

  // Returns an execution function.
  template <typename FuncType>
  Result<FuncType> function(const std::string& symbol_name = "") const;

  // Returns an arbitrary symbol address.
  Result<void*> symbol(const std::string& symbol_name) const;

private:
  Functions(std::shared_ptr<MemoryRegion> exec_region,
            std::shared_ptr<MemoryRegion> trampoline_region,
            std::shared_ptr<MemoryRegion> got_region,
            std::map<std::string, uint64_t> symbol_table)
      : exec_region_(std::move(exec_region)),
        trampoline_region_(std::move(trampoline_region)),
        got_region_(std::move(got_region)),
        symbol_table_(std::move(symbol_table)){};

  std::shared_ptr<MemoryRegion> exec_region_;
  std::shared_ptr<MemoryRegion> trampoline_region_;
  std::shared_ptr<MemoryRegion> got_region_;
  std::map<std::string, uint64_t> symbol_table_;
};

template <typename FuncType>
Result<FuncType> Functions::function(const std::string& symbol_name) const
{
  auto addr = symbol(symbol_name);
  if (!addr) {
    return addr.takeError();
  }
  return reinterpret_cast<FuncType>(*addr);
}

} // namespace bpftrace::async
