#pragma once

#include <string>
#include <unordered_map>
#include <memory>
#include <functional>
#include <vector>
#include <optional>

namespace bpftrace{

class BPFtrace;

namespace ast {

class Node;

/**
   Result of a pass run
 */
class PassResult
{
public:
  static PassResult Error(const std::string & msg);
  static PassResult Success(Node *root = nullptr);

  bool Ok() const { return success_; };
  const std::string & Error() {  return error_; };
  Node * Root() const { return root_; };

private:
  bool success_;
  std::string error_;
  Node * root_ = nullptr;
};

/**
   Context/config for passes
*/
class SemanticAnalyser;
struct PassContext
{
  BPFtrace& b;
  bool has_child;
  size_t max_ast_nodes;
  std::unique_ptr<SemanticAnalyser> semant;
};

using PassFPtr = std::function<PassResult(Node &, PassContext &)>;

/*
  Base pass
*/
class Pass
{
public:
  Pass() = delete;
  Pass(std::string name, PassFPtr fn) : fn_(fn), name(name){};

  virtual ~Pass() = default;

  PassResult Run(Node &root, PassContext &ctx)
  {
    return fn_(root, ctx);
  };

private:
  PassFPtr fn_;

public:
  std::string name;
};

/**
   Read only diagnostic AST passes
 */
class AnalysePass : public Pass
{
public:
  AnalysePass(std::string name, PassFPtr fn) : Pass(name, fn) {};
};

/**
   AST modifying passes
 */
class MutatePass : public Pass
{
public:
  MutatePass(std::string name, PassFPtr fn) : Pass(name, fn) {};
};

struct PMResult {
  Node * root;
  bool success;
  std::string failed_pass;
  std::string error;
};

class PassManager
{
public:
  PassManager() = default;

  void AddPass(Pass p);
  std::optional<Node *> Run(Node &n, PassContext &ctx);

private:
  std::vector<Pass> passes_;
};

} // namespace ast
} // namespace bpftrace
