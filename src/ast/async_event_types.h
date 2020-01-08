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

struct PrintNonMap
{
  uint64_t action_id;
  uint64_t print_id;
  // See below why we don't use a flexible length array
  uint8_t content[0];

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b, size_t size)
  {
    return {
      b.getInt64Ty(),                            // asyncid
      b.getInt64Ty(),                            // print id
      llvm::ArrayType::get(b.getInt8Ty(), size), // content
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

struct Strftime
{
  uint64_t strftime_id;
  uint64_t nsecs_since_boot;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b)
  {
    return {
      b.getInt64Ty(), // strftime id
      b.getInt64Ty(), // strftime arg, time elapsed since boot
    };
  }
} __attribute__((packed));

struct Buf
{
  uint8_t length;
  // Seems like GCC 7.4.x can't handle `char content[]`. Work around by using
  // 0 sized array (a GCC extension that clang also accepts:
  // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=70932). It also looks like
  // the issue doesn't exist in GCC 7.5.x.
  char content[0];

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b, size_t length)
  {
    return {
      b.getInt8Ty(),                               // buffer length
      llvm::ArrayType::get(b.getInt8Ty(), length), // buffer content
    };
  }
} __attribute__((packed));

struct HelperError
{
  uint64_t action_id;
  uint64_t error_id;
  int32_t return_value;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b)
  {
    return {
      b.getInt64Ty(), // asyncid
      b.getInt64Ty(), // error_id
      b.getInt32Ty(), // return value
    };
  }
} __attribute__((packed));

struct Watchpoint
{
  uint64_t action_id;
  uint64_t watchpoint_idx;
  uint64_t addr;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b)
  {
    return {
      b.getInt64Ty(), // asyncid
      b.getInt64Ty(), // watchpoint_idx
      b.getInt64Ty(), // addr
    };
  }
} __attribute__((packed));

struct WatchpointUnwatch
{
  uint64_t action_id;
  uint64_t addr;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b)
  {
    return {
      b.getInt64Ty(), // asyncid
      b.getInt64Ty(), // addr
    };
  }
} __attribute__((packed));

} // namespace AsyncEvent
} // namespace bpftrace
