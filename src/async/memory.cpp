#include <cerrno>
#include <cstring>
#include <string>
#include <unistd.h>

#include "async/memory.h"

namespace bpftrace::async {

char MemoryAllocationError::ID;
char MemoryProtectionError::ID;

void MemoryAllocationError::log(llvm::raw_ostream& OS) const
{
  OS << "Failed to allocate " << size_
     << " bytes of memory: " << strerror(err_);
}

void MemoryProtectionError::log(llvm::raw_ostream& OS) const
{
  OS << "Failed to change memory protection for region " << addr_
     << " (size: " << size_ << ", protection: " << prot_
     << "): " << strerror(err_);
}

Result<std::shared_ptr<MemoryRegion>> MemoryRegion::allocate(size_t size,
                                                             int protection)
{
  if (size == 0) {
    return std::make_shared<MemoryRegion>();
  }

  // Create the new mapping.
  size_t page_size = getpagesize();
  size_t aligned_size = (size + page_size - 1) & ~(page_size - 1);
  void* addr = mmap(
      nullptr, aligned_size, protection, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (addr == MAP_FAILED) {
    return make_error<MemoryAllocationError>(aligned_size, errno);
  }

  return std::make_shared<MemoryRegion>(addr, aligned_size);
}

Result<> MemoryRegion::protect(int new_protection)
{
  if (size_ == 0) {
    return OK();
  }

  if (mprotect(addr_, size_, new_protection) != 0) {
    return make_error<MemoryProtectionError>(
        addr_, size_, new_protection, errno);
  }

  return OK();
}

MemoryRegion::~MemoryRegion()
{
  if (size_ > 0) {
    munmap(addr_, size_);
  }
}

} // namespace bpftrace::async
