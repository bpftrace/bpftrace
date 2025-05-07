#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// Forward declare some LLVM types here. We do not #include any LLVM
// headers b/c that will pull in LLVM's ABI checking machinery. We want
// this header to be independent of LLVM during link time so that AOT
// does not need to link against LLVM.
namespace llvm {
class Type;
} // namespace llvm

namespace bpftrace::ast {
class IRBuilderBPF;
} // namespace bpftrace::ast

// The main goal here is to keep the struct definitions close to each other,
// making it easier to spot type mismatches.
//
// If you update a type, remember to update the .cpp too!

namespace bpftrace {

// TODO: move this `AsyncAction` enum to `async_action.h`
enum class AsyncAction {
  // clang-format off
  printf      = 0,     // printf reserves 0-9999 for printf_ids
  printf_end  = 9999,
  syscall     = 10000, // system reserves 10000-19999 for printf_ids
  syscall_end = 19999,
  cat         = 20000, // cat reserves 20000-29999 for printf_ids
  cat_end     = 29999,
  exit        = 30000,
  print,
  clear,
  zero,
  time,
  join,
  helper_error,
  print_non_map,
  strftime,
  watchpoint_attach,
  watchpoint_detach,
  skboutput,
  // clang-format on
};

namespace AsyncEvent {

struct Print {
  uint64_t action_id;
  uint32_t mapid;
  uint32_t top;
  uint32_t div;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b);
} __attribute__((packed));

struct PrintNonMap {
  uint64_t action_id;
  uint64_t print_id;
  // See below why we don't use a flexible length array
  uint8_t content[0];

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b, size_t size);
} __attribute__((packed));

struct MapEvent {
  uint64_t action_id;
  uint32_t mapid;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b);
} __attribute__((packed));

struct Time {
  uint64_t action_id;
  uint32_t time_id;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b);
} __attribute__((packed));

struct Strftime {
  uint32_t strftime_id;
  uint32_t mode;
  uint64_t nsecs;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b);
} __attribute__((packed));

struct Buf {
  uint32_t length;
  // Seems like GCC 7.4.x can't handle `char content[]`. Work around by using
  // 0 sized array (a GCC extension that clang also accepts:
  // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=70932). It also looks like
  // the issue doesn't exist in GCC 7.5.x.
  char content[0];

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b, uint32_t length);
} __attribute__((packed));

struct HelperError {
  uint64_t action_id;
  uint64_t error_id;
  int32_t return_value;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b);
} __attribute__((packed));

struct Watchpoint {
  uint64_t action_id;
  uint64_t watchpoint_idx;
  uint64_t addr;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b);
} __attribute__((packed));

struct WatchpointUnwatch {
  uint64_t action_id;
  uint64_t addr;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b);
} __attribute__((packed));

struct CgroupPath {
  uint64_t cgroup_path_id;
  uint64_t cgroup_id;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b);
} __attribute__((packed));

struct SkbOutput {
  uint64_t action_id;
  uint64_t skb_output_id;
  uint64_t nsecs_since_boot;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b);
} __attribute__((packed));

struct Exit {
  uint64_t action_id;
  uint8_t exit_code;

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b);
} __attribute__((packed));

struct Join {
  uint64_t action_id;
  uint64_t join_id;
  char content[0];

  std::vector<llvm::Type*> asLLVMType(ast::IRBuilderBPF& b, uint32_t length);
} __attribute__((packed));

} // namespace AsyncEvent
} // namespace bpftrace
