#include "ast/passes/iter_desugar.h"

#include <string>
#include <utility>

#include "ast/ast.h"
#include "ast/passes/check_nargs.h"
#include "ast/visitor.h"
#include "bpf_iters.h"
#include "bpftrace.h"

namespace bpftrace::ast {

namespace {

// Lowers `for ($t : iter_task()) { print(1); }` into the equivalent
// bpftrace:
//
//   {
//     let $__iter_state_0 : struct bpf_iter_task;
//     if (kfunc::bpf_iter_task_new(&$__iter_state_0,
//                                  (struct task_struct *)0, 0) == 0) {
//       while true {
//         let $t = kfunc::bpf_iter_task_next(&$__iter_state_0);
//         if $t {
//           {
//             print(1);
//             continue;
//           }
//         } else {
//           break;
//         }
//       }
//     }
//     kfunc::bpf_iter_task_destroy(&$__iter_state_0);
//   }
//
// `break` in the body leaves the while and falls into the destroy. `continue`
// re-runs the condition and fetches the next element. `return` has already
// been rewritten into `break` plus a flag that we check after the destroy call
class IterDesugar : public Visitor<IterDesugar> {
public:
  IterDesugar(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace) {};

  using Visitor<IterDesugar>::visit;
  void visit(Statement &stmt);

private:
  Expression struct_ptr_cast(const Location &loc,
                             const std::string &name,
                             Expression expr);
  Expression state_arg(const Location &loc, const std::string &ident);
  Statement desugar(For &f, Call &it, const BpfIterItem &info);

  ASTContext &ast_;
  BPFtrace &bpftrace_;
  size_t next_id_ = 0;
};

Expression IterDesugar::struct_ptr_cast(const Location &loc,
                                        const std::string &name,
                                        Expression expr)
{
  auto *record = ast_.make_node<ParsedType>(loc,
                                            ParsedType::Kind::Struct,
                                            name);
  auto *ptr = ast_.make_node<ParsedType>(loc, record);
  auto *type_of = ast_.make_node<Typeof>(loc, ptr);
  return ast_.make_node<Cast>(loc, type_of, std::move(expr));
}

Expression IterDesugar::state_arg(const Location &loc, const std::string &ident)
{
  auto *var = ast_.make_node<Variable>(loc, ident);
  return ast_.make_node<VariableAddr>(loc, var);
}

Statement IterDesugar::desugar(For &f, Call &it, const BpfIterItem &info)
{
  const auto &loc = f.loc;
  const std::string state = "$__iter_state_" + std::to_string(next_id_++);

  // let $__iter_state_N : struct <kfunc>;
  auto *state_type = ast_.make_node<ParsedType>(loc,
                                                ParsedType::Kind::Struct,
                                                info.kfunc);
  auto *state_decl = ast_.make_node<VarDeclStatement>(
      loc,
      ast_.make_node<Variable>(loc, state),
      ast_.make_node<Typeof>(loc, state_type));

  // kfunc::<kfunc>_new(state, task, flags or arg)
  ExpressionList new_args({ state_arg(loc, state) });
  if (it.vargs.empty()) {
    new_args.emplace_back(
        struct_ptr_cast(loc, "task_struct", ast_.make_node<Integer>(loc, 0)));
  } else {
    new_args.emplace_back(it.vargs.at(0));
  }
  if (info.flags) {
    new_args.emplace_back(ast_.make_node<Integer>(loc, *info.flags));
  } else if (it.vargs.size() > 1) {
    new_args.emplace_back(it.vargs.at(1));
  } else {
    new_args.emplace_back(ast_.make_node<Integer>(loc, 0));
  }

  // let $x = kfunc::<kfunc>_next(state);
  auto *next_call = ast_.make_node<Call>(loc,
                                         info.kfunc + "_next",
                                         ExpressionList(
                                             { state_arg(loc, state) }),
                                         Call::Namespace::KFunc);
  auto *decl = ast_.make_node<VarDeclStatement>(f.decl->loc, f.decl);
  auto *assign = ast_.make_node<AssignVarStatement>(f.decl->loc,
                                                    decl,
                                                    next_call);

  // if ($x) { body } else { break; }
  auto *brk = ast_.make_node<BlockExpr>(
      loc,
      StatementList({ ast_.make_node<Jump>(loc, JumpType::BREAK) }),
      ast_.make_node<None>(loc));
  auto *step = ast_.make_node<ExprStatement>(
      loc,
      ast_.make_node<IfExpr>(loc,
                             ast_.make_node<Variable>(f.decl->loc,
                                                      f.decl->ident),
                             f.block,
                             brk));

  // while (true) { ... }
  auto *body = ast_.make_node<BlockExpr>(loc,
                                         StatementList({ assign, step }),
                                         ast_.make_node<None>(loc));
  auto *loop = ast_.make_node<While>(loc,
                                     ast_.make_node<Boolean>(loc, true),
                                     body);
  loop->is_iter = true;

  // if (kfunc::<kfunc>_new(...) == 0) { while ... }
  auto *guarded = ast_.make_node<BlockExpr>(loc,
                                            StatementList({ loop }),
                                            ast_.make_node<None>(loc));
  auto *guard = ast_.make_node<ExprStatement>(
      loc,
      ast_.make_node<IfExpr>(
          loc,
          ast_.make_node<Binop>(loc,
                                ast_.make_node<Call>(loc,
                                                     info.kfunc + "_new",
                                                     std::move(new_args),
                                                     Call::Namespace::KFunc),
                                Operator::EQ,
                                ast_.make_node<Integer>(loc, 0)),
          guarded,
          ast_.make_node<None>(loc)));

  // kfunc::<kfunc>_destroy(state). Always runs, including when new() failed,
  // because the kernel requires the iterator to be released on every path
  // once it has been touched.
  auto *destroy = ast_.make_node<ExprStatement>(
      loc,
      ast_.make_node<Call>(loc,
                           info.kfunc + "_destroy",
                           ExpressionList({ state_arg(loc, state) }),
                           Call::Namespace::KFunc));

  auto *block = ast_.make_node<BlockExpr>(loc,
                                          StatementList(
                                              { state_decl, guard, destroy }),
                                          ast_.make_node<None>(loc));
  return ast_.make_node<ExprStatement>(loc, block);
}

void IterDesugar::visit(Statement &stmt)
{
  Visitor<IterDesugar>::visit(stmt);

  auto *f = stmt.as<For>();
  if (f == nullptr) {
    return;
  }

  auto *it = f->iterable.as<Call>();
  if (it == nullptr) {
    return;
  }

  const auto *info = find_bpf_iter(it->func);
  if (info == nullptr) {
    return;
  }

  if (!check_nargs(*it, info->min_args, info->max_args)) {
    return;
  }

  if (!bpftrace_.feature_->has_kfunc(info->kfunc + "_new")) {
    it->addError() << "Missing required kernel feature: " << info->kfunc
                   << " (open-coded iterators require kernel 6.7 or later)";
    return;
  }

  if (bpftrace_.btf_->get_stype(info->yields).IsNoneTy()) {
    it->addError() << "Cannot resolve \"" << info->yields << "\" required by "
                   << it->func << "(); kernel BTF may be unavailable";
    return;
  }

  stmt = desugar(*f, *it, *info);
}

} // namespace

Pass CreateIterDesugarPass()
{
  return Pass::create("IterDesugar", [](ASTContext &ast, BPFtrace &b) {
    IterDesugar desugar(ast, b);
    desugar.visit(ast.root);
  });
};

} // namespace bpftrace::ast
