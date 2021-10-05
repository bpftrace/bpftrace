#include "async_event_types.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Type.h>

#include "irbuilderbpf.h"

namespace bpftrace {
namespace AsyncEvent {

std::vector<llvm::Type*> Print::asLLVMType(ast::IRBuilderBPF& b)
{
  return {
    b.getInt64Ty(), // asyncid
    b.getInt32Ty(), // map id
    b.getInt32Ty(), // top
    b.getInt32Ty(), // div
  };
}

std::vector<llvm::Type*> PrintNonMap::asLLVMType(ast::IRBuilderBPF& b,
                                                 size_t size)
{
  return {
    b.getInt64Ty(),                            // asyncid
    b.getInt64Ty(),                            // print id
    llvm::ArrayType::get(b.getInt8Ty(), size), // content
  };
}

std::vector<llvm::Type*> MapEvent::asLLVMType(ast::IRBuilderBPF& b)
{
  return {
    b.getInt64Ty(), // asyncid
    b.getInt32Ty(), // map id
  };
}

std::vector<llvm::Type*> Time::asLLVMType(ast::IRBuilderBPF& b)
{
  return {
    b.getInt64Ty(), // asyncid
    b.getInt32Ty(), // time id
  };
}

std::vector<llvm::Type*> Strftime::asLLVMType(ast::IRBuilderBPF& b)
{
  return {
    b.getInt64Ty(), // strftime id
    b.getInt64Ty(), // strftime arg, time elapsed since boot
  };
}

std::vector<llvm::Type*> Buf::asLLVMType(ast::IRBuilderBPF& b, size_t length)
{
  return {
    b.getInt8Ty(),                               // buffer length
    llvm::ArrayType::get(b.getInt8Ty(), length), // buffer content
  };
}

std::vector<llvm::Type*> HelperError::asLLVMType(ast::IRBuilderBPF& b)
{
  return {
    b.getInt64Ty(), // asyncid
    b.getInt64Ty(), // error_id
    b.getInt32Ty(), // return value
  };
}

std::vector<llvm::Type*> Watchpoint::asLLVMType(ast::IRBuilderBPF& b)
{
  return {
    b.getInt64Ty(), // asyncid
    b.getInt64Ty(), // watchpoint_idx
    b.getInt64Ty(), // addr
  };
}

std::vector<llvm::Type*> WatchpointUnwatch::asLLVMType(ast::IRBuilderBPF& b)
{
  return {
    b.getInt64Ty(), // asyncid
    b.getInt64Ty(), // addr
  };
}

} // namespace AsyncEvent
} // namespace bpftrace
