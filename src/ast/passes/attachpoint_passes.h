#pragma once

#include <optional>
#include <sstream>
#include <vector>

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "bpftrace.h"
#include "symbols/kernel.h"
#include "symbols/user.h"

namespace bpftrace::ast {

// Provides function information (kernel and user space) to AST passes.
class FunctionInfo : public bpftrace::ast::State<"function-info"> {
public:
  explicit FunctionInfo(symbols::KernelInfo &kernel_impl,
                        symbols::UserInfo &user_impl)
      : kernel_impl_(kernel_impl), user_impl_(user_impl)
  {
  }

  symbols::KernelInfo &kernel_info() const
  {
    return kernel_impl_;
  }
  symbols::UserInfo &user_info() const
  {
    return user_impl_;
  }

private:
  symbols::KernelInfo &kernel_impl_;
  symbols::UserInfo &user_impl_;
};

class AttachPointParser {
public:
  AttachPointParser(ASTContext &ctx,
                    BPFtrace &bpftrace,
                    FunctionInfo &func_info_state);
  ~AttachPointParser() = default;
  void parse();

private:
  enum State { OK = 0, INVALID, NEW_APS, SKIP };

  State parse_attachpoint(AttachPoint &ap);
  // This method splits an attach point definition into arguments,
  // where arguments are separated by `:`. The exception is `:`s inside
  // of quoted strings, which we must treat as a literal.
  //
  // This method also resolves positional parameters. Positional params
  // may be escaped with double quotes.
  //
  // Note that this function assumes the raw string is generally well
  // formed. More specifically, that there is no unescaped whitespace
  // and no unmatched quotes.
  State lex_attachpoint(const AttachPoint &ap);

  State special_parser();
  State test_parser();
  State benchmark_parser();
  State kprobe_parser(bool allow_offset = true);
  State kretprobe_parser();
  State uprobe_parser(bool allow_offset = true,
                      bool allow_abs_addr = true,
                      bool allow_src_loc = true);
  State uretprobe_parser();
  State usdt_parser();
  State tracepoint_parser();
  State profile_parser();
  State interval_parser();
  State software_parser();
  State hardware_parser();
  State watchpoint_parser();
  State fentry_parser();
  State iter_parser();
  State raw_tracepoint_parser();

  State frequency_parser();

  State argument_count_error(int expected,
                             std::optional<int> expected2 = std::nullopt);
  std::optional<uint64_t> stoull(const std::string &str);
  std::optional<int64_t> stoll(const std::string &str);

  ASTContext &ctx_;
  BPFtrace &bpftrace_;
  FunctionInfo &func_info_state_;
  AttachPoint *ap_{ nullptr }; // Non-owning pointer
  std::stringstream errs_;
  std::vector<std::string> parts_;
  AttachPointList new_attach_points;
  bool has_iter_ap_ = false;
};

// The attachpoints are expanded in their own separate pass.
Pass CreateParseAttachpointsPass();
Pass CreateCheckAttachpointsPass();

} // namespace bpftrace::ast
