#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace bpftrace {

class BPFtrace;

namespace ast {

class Node;
class SemanticAnalyser;
class Pass;

/**
   Result of a pass run
 */
class PassResult
{
public:
  static PassResult Error(const std::string &pass);
  static PassResult Error(const std::string &pass, int code);
  static PassResult Error(const std::string &pass, const std::string &msg);
  static PassResult Success(Node *root = nullptr);

  // Ok returns whether the pass was successful or not
  bool Ok() const
  {
    return success_;
  };

  const std::optional<std::string> GetErrorMsg()
  {
    return errmsg_;
  };

  const std::optional<int> GetErrorCode()
  {
    return errcode_;
  }

  /**
     Return the pass in which the failure occurred
   */
  const std::optional<std::string> GetErrorPass()
  {
    return errpass_;
  }

  Node *Root() const
  {
    return root_;
  };

private:
  PassResult(const std::string &pass) : success_(false), errpass_(pass)
  {
  }

  PassResult(const std::string &pass, int errcode)
      : success_(false), errpass_(pass), errcode_(errcode)
  {
  }

  PassResult(const std::string &pass, const std::string &msg)
      : success_(false), errpass_(pass), errmsg_(msg)
  {
  }

  PassResult(const std::string &pass, int errcode, const std::string &msg)
      : success_(false), errpass_(pass), errcode_(errcode), errmsg_(msg)
  {
  }

  PassResult(Node *root) : success_(true), root_(root)
  {
  }

  bool success_ = false;
  std::optional<std::string> errpass_;
  std::optional<int> errcode_;
  std::optional<std::string> errmsg_;
  Node *root_ = nullptr;
};

/**
   Context/config for passes

   Note: Most state should end up in the BPFtrace class instead of here
*/

struct PassContext
{
public:
  PassContext(BPFtrace &b) : b(b){};
  BPFtrace &b;

private:
  // As semantic pass and map creation are separate passes we need this
  SemanticAnalyser *semant;

  // Only ones allowed to access semant
  friend Pass CreateSemanticPass();
  friend Pass CreateMapCreatePass();
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

class PassManager
{
public:
  PassManager() = default;

  void AddPass(Pass p);
  [[nodiscard]] std::unique_ptr<Node> Run(std::unique_ptr<Node> n,
                                          PassContext &ctx);

private:
  std::vector<Pass> passes_;
};

} // namespace ast
} // namespace bpftrace
