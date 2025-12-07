#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Type.h>

#include "ast/async_event_types.h"
#include "ast/irbuilderbpf.h"

namespace bpftrace::AsyncEvent {

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
    b.getInt32Ty(), // strftime id
    b.getInt32Ty(), // timestamp mode
    b.getInt64Ty(), // strftime arg, nanoseconds
  };
}

std::vector<llvm::Type*> Buf::asLLVMType(ast::IRBuilderBPF& b, uint32_t length)
{
  return {
    b.getInt32Ty(),                              // buffer length
    llvm::ArrayType::get(b.getInt8Ty(), length), // buffer content
  };
}

std::vector<llvm::Type*> RuntimeError::asLLVMType(ast::IRBuilderBPF& b)
{
  return {
    b.getInt64Ty(), // asyncid
    b.getInt64Ty(), // error_id
    b.getInt32Ty(), // return value
  };
}

std::vector<llvm::Type*> CgroupPath::asLLVMType(ast::IRBuilderBPF& b)
{
  return {
    b.getInt64Ty(), // cgroup path (pseudo-event) id
    b.getInt64Ty(), // cgroup id
  };
}

std::vector<llvm::Type*> SkbOutput::asLLVMType(ast::IRBuilderBPF& b)
{
  return {
    b.getInt64Ty(), // asyncid
    b.getInt64Ty(), // skb_output id
    b.getInt64Ty(), // time elapsed since boot
  };
}

std::vector<llvm::Type*> Exit::asLLVMType(ast::IRBuilderBPF& b)
{
  return {
    b.getInt64Ty(), // asyncid
    b.getInt8Ty(),  // exit_code
  };
}

std::vector<llvm::Type*> Join::asLLVMType(ast::IRBuilderBPF& b, uint32_t length)
{
  return {
    b.getInt64Ty(),                              // action_id
    b.getInt64Ty(),                              // join_id
    llvm::ArrayType::get(b.getInt8Ty(), length), // join content
  };
}

} // namespace bpftrace::AsyncEvent
