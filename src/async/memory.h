#pragma once

#include <cstddef>
#include <memory>
#include <sys/mman.h>

#include "util/result.h"

namespace bpftrace::async {

class MemoryAllocationError : public ErrorInfo<MemoryAllocationError> {
public:
  static char ID;

  MemoryAllocationError(size_t size, int err) : size_(size), err_(err){};
  void log(llvm::raw_ostream& OS) const override;

private:
  size_t size_;
  int err_;
};

class MemoryProtectionError : public ErrorInfo<MemoryProtectionError> {
public:
  static char ID;

  MemoryProtectionError(void* addr, size_t size, int prot, int err)
      : addr_(addr), size_(size), prot_(prot), err_(err){};
  void log(llvm::raw_ostream& OS) const override;

private:
  void* addr_;
  size_t size_;
  int prot_;
  int err_;
};

// RAII wrapper for memory-mapped regions with proper permission management.
class MemoryRegion {
public:
  MemoryRegion(const MemoryRegion&) = delete;
  MemoryRegion& operator=(const MemoryRegion&) = delete;
  MemoryRegion(MemoryRegion&& other) = delete;
  MemoryRegion& operator=(MemoryRegion&& other) = delete;
  ~MemoryRegion();

  // Create an empty region.
  MemoryRegion() : addr_(nullptr), size_(0){};

  // Does not use this directly: only use allocate.
  MemoryRegion(void* addr, size_t size) : addr_(addr), size_(size){};

  // Allocate a new memory region with the specified size and protection.
  static Result<std::shared_ptr<MemoryRegion>> allocate(size_t size,
                                                        int protection);

  // Change the memory protection of this region.
  Result<> protect(int prot);

  // Get the base address of the memory region.
  void* addr() const
  {
    return addr_;
  }

  // Get the size of the memory region in bytes.
  size_t size() const
  {
    return size_;
  }

private:
  void* addr_;
  size_t size_;
};

} // namespace bpftrace::async
