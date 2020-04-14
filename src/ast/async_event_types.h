#pragma once

#include "irbuilderbpf.h"
#include <cstdint>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Type.h>

/*
  The main goal here is to keep the struct definitions close to each other,
  making it easier to spot type mismatches.
*/

namespace bpftrace {
namespace AsyncEvent {

struct Print
{
  uint64_t action_id;
  uint32_t mapid;
  uint32_t top;
  uint32_t div;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b)
  {
    return {
      b.getInt64Ty(), // asyncid
      b.getInt32Ty(), // map id
      b.getInt32Ty(), // top
      b.getInt32Ty(), // div
    };
  }
} __attribute__((packed));

struct MapEvent
{
  uint64_t action_id;
  uint32_t mapid;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b)
  {
    return {
      b.getInt64Ty(), // asyncid
      b.getInt32Ty(), // map id
    };
  }
} __attribute__((packed));

struct Time
{
  uint64_t action_id;
  uint32_t time_id;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b)
  {
    return {
      b.getInt64Ty(), // asyncid
      b.getInt32Ty(), // time id
    };
  }
} __attribute__((packed));

struct Buf
{
  uint8_t length;
  char content[];

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b, size_t length)
  {
    return {
      b.getInt8Ty(),                               // buffer length
      llvm::ArrayType::get(b.getInt8Ty(), length), // buffer content
    };
  }
} __attribute__((packed));

} // namespace AsyncEvent
} // namespace bpftrace
