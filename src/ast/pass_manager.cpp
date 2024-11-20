#include "ast/pass_manager.h"

#include <ostream>

#include "ast/passes/printer.h"
#include "bpftrace.h"

namespace bpftrace::ast {

namespace {
void print(Program &program, const std::string &name, std::ostream &out)
{
  out << "\nAST after: " << name << std::endl;
  out << "-------------------\n";
  ast::Printer printer(out);
  printer.print(&program);
  out << std::endl;
}
} // namespace

void PassManager::AddPass(Pass p)
{
  passes_.push_back(std::move(p));
}

PassResult PassManager::Run(Program &program, PassContext &ctx)
{
  if (bt_debug.find(DebugStage::Ast) != bt_debug.end())
    print(program, "parser", std::cout);
  for (auto &pass : passes_) {
    auto result = pass.Run(program, ctx);
    if (bt_debug.find(DebugStage::Ast) != bt_debug.end())
      print(program, pass.name, std::cout);

    if (!result.Ok())
      return result;
  }
  return PassResult::Success();
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

PassResult PassResult::Success()
{
  return PassResult();
}

} // namespace bpftrace::ast
