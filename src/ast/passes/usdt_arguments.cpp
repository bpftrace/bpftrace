#include <set>

#include "ast/ast.h"
#include "ast/passes/resolve_imports.h"
#include "ast/passes/usdt_arguments.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

class USDTArgumentLift : public Visitor<USDTArgumentLift> {
public:
  explicit USDTArgumentLift(ASTContext &ast) : ast_(ast)
  {
  }

  using Visitor<USDTArgumentLift>::visit;
  void visit(Probe &probe);
  void visit(Expression &expr);

  ast::Variable *var(size_t arg, Node &node)
  {
    std::string ident = "__usdt_arg_" + std::to_string(arg);
    return ast_.make_node<ast::Variable>(ident, Location(node.loc));
  }
  ast::AssignVarStatement *var_decl(size_t arg, Node &node)
  {
    auto *int_arg = ast_.make_node<ast::Integer>(static_cast<uint64_t>(arg),
                                                 Location(node.loc));
    std::vector<Expression> args = { int_arg };
    Expression expr = ast_.make_node<ast::Call>("usdt_arg",
                                                std::move(args),
                                                Location(node.loc));
    return ast_.make_node<AssignVarStatement>(var(arg, node),
                                              expr,
                                              Location(node.loc));
  }

private:
  ASTContext &ast_;
  std::set<size_t> args_;
};

} // namespace

void USDTArgumentLift::visit(Probe &probe)
{
  bool is_usdt = false;
  for (const auto &ap : probe.attach_points) {
    if (probetype(ap->provider) == ProbeType::usdt) {
      is_usdt = true;
      break;
    }
  }
  if (!is_usdt) {
    return;
  }

  // Process this probe.
  Visitor<USDTArgumentLift>::visit(probe);
  if (args_.empty()) {
    return;
  }

  // Rewrite the block to include declarations.
  std::vector<Statement> stmt_list;
  for (const auto arg_num : args_) {
    stmt_list.emplace_back(var_decl(arg_num, probe));
  }
  auto existing_stmts = std::move(probe.block->stmts);
  stmt_list.insert(stmt_list.end(),
                   existing_stmts.begin(),
                   existing_stmts.end());
  probe.block->stmts = std::move(stmt_list);
  args_.clear();
}

void USDTArgumentLift::visit(Expression &expr)
{
  Visitor<USDTArgumentLift>::visit(expr);
  if (auto *builtin = expr.as<Builtin>()) {
    // Check if this matches `argXX` and replace with the variable.
    if (builtin->is_argx()) {
      size_t arg_num = std::stoul(builtin->ident.substr(3));
      args_.insert(arg_num);
      expr = var(arg_num, *builtin);
    }
  }
}

Pass CreateUSDTImportPass()
{
  return Pass::create("USDTImport",
                      [](ASTContext &ast, Imports &imports) -> Result<> {
                        bool has_usdt = false;
                        for (auto *probe : ast.root->probes) {
                          for (auto *ap : probe->attach_points) {
                            if (probetype(ap->provider) == ProbeType::usdt) {
                              has_usdt = true;
                              break;
                            }
                          }
                          if (has_usdt)
                            break;
                        }

                        if (has_usdt) {
                          auto usdt_arguments = USDTArgumentLift(ast);
                          usdt_arguments.visit(ast.root);
                          return imports.import_any(*ast.root, "stdlib/usdt");
                        }

                        return OK();
                      });
}

} // namespace bpftrace::ast
