#include <ostream>
#include <pass_manager.h>

#include "bpftrace.h"
#include "printer.h"

namespace bpftrace {
namespace ast {

namespace {
void print(Node *root, const std::string &name, std::ostream &out)
{
  out << "\nAST after: " << name << std::endl;
  out << "-------------------\n";
  ast::Printer printer(out);
  printer.print(root);
  out << std::endl;
}
} // namespace

void PassManager::AddPass(Pass p)
{
  passes_.push_back(std::move(p));
}

PassResult PassManager::Run(std::unique_ptr<Node> node, PassContext &ctx)
{
  Node *root = node.release();
  if (bt_debug != DebugLevel::kNone)
    print(root, "parser", std::cout);
  for (auto &pass : passes_)
  {
    auto result = pass.Run(*root, ctx);
    if (!result.Ok())
      return result;

    if (result.Root())
    {
      delete root;
      root = result.Root();
    }

    if (bt_debug != DebugLevel::kNone)
      print(root, pass.name, std::cout);
  }
  return PassResult::Success(root);
}

PassResult PassResult::Error(const std::string &pass)
{
  return PassResult(pass);
}

PassResult PassResult::Error(const std::string &pass, int code)
{
  return PassResult(pass, code);
}

PassResult PassResult::Error(const std::string &pass, const std::string &msg)
{
  return PassResult(pass, msg);
}

PassResult PassResult::Success(Node *root)
{
  return PassResult(root);
}

} // namespace ast
} // namespace bpftrace
