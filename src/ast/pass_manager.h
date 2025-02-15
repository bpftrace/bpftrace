#pragma once

#include <functional>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace bpftrace {

class BPFtrace;

namespace ast {

class ASTContext;

// Context/config for passes
//
// Note: Most state should end up in the BPFtrace class instead of here

struct PassContext {
public:
  PassContext(BPFtrace &b, ASTContext &ast_ctx) : b(b), ast_ctx(ast_ctx) {};
  BPFtrace &b;
  ASTContext &ast_ctx;
};

using PassFPtr = std::function<void(PassContext &)>;

// Base pass
class Pass {
public:
  Pass() = delete;
  Pass(std::string name, PassFPtr fn) : fn_(fn), name(name) {};

  virtual ~Pass() = default;

  void Run(PassContext &ctx)
  {
    fn_(ctx);
  };

private:
  PassFPtr fn_;

public:
  std::string name;
};

class PassManager {
public:
  PassManager(std::ostream &out = std::cerr) : out_(out) {};

  void AddPass(Pass p);
  [[nodiscard]] int Run(PassContext &ctx);

private:
  std::vector<Pass> passes_;
  std::ostream &out_;
};

} // namespace ast
} // namespace bpftrace
