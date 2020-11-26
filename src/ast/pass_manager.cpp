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

std::unique_ptr<Node> PassManager::Run(std::unique_ptr<Node> node,
                                       PassContext &ctx)
{
  Node *root = node.release();
  if (bt_debug != DebugLevel::kNone)
    print(root, "parser", std::cout);
  for (auto &pass : passes_)
  {
    auto result = pass.Run(*root, ctx);
    if (!result.Ok())
      return {};

    if (result.Root())
    {
      delete root;
      root = result.Root();
    }

    if (bt_debug != DebugLevel::kNone)
      print(root, pass.name, std::cout);
  }
  return std::unique_ptr<Node>(root);
}

PassResult PassResult::Error(const std::string &msg)
{
  PassResult p;
  p.success_ = false;
  p.error_ = msg;
  return p;
}

PassResult PassResult::Success(Node *root)
{
  PassResult p;
  p.success_ = true;
  p.root_ = root;
  return p;
}
} // namespace ast
} // namespace bpftrace
