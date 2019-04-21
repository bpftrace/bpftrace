#include <regex>

#include "printer.h"
#include "ast.h"

namespace bpftrace {
namespace ast {

void Printer::visit(Integer &integer)
{
  std::string indent(depth_, ' ');
  out_ << indent << "int: " << integer.n << std::endl;
}

void Printer::visit(PositionalParameter &param)
{
  std::string indent(depth_, ' ');
  out_ << indent << "builtin: $" << param.n << std::endl;
}

void Printer::visit(String &string)
{
  std::string indent(depth_, ' ');

  std::string str = string.str;
  str = std::regex_replace(str, std::regex("\\\\"), "\\\\");
  str = std::regex_replace(str, std::regex("\n"), "\\n");
  str = std::regex_replace(str, std::regex("\t"), "\\t");
  str = std::regex_replace(str, std::regex("\""), "\\\"");

  out_ << indent << "string: " << str << std::endl;
}

void Printer::visit(StackMode &mode)
{
  std::string indent(depth_, ' ');
  out_ << indent << "stack_mode: " << mode.mode << std::endl;
}

void Printer::visit(Builtin &builtin)
{
  std::string indent(depth_, ' ');
  out_ << indent << "builtin: " << builtin.ident << std::endl;
}

void Printer::visit(Identifier &identifier)
{
  std::string indent(depth_, ' ');
  out_ << indent << "identifier: " << identifier.ident << std::endl;
}

void Printer::visit(Call &call)
{
  std::string indent(depth_, ' ');
  out_ << indent << "call: " << call.func << std::endl;

  ++depth_;
  if (call.vargs) {
    for (Expression *expr : *call.vargs) {
      expr->accept(*this);
    }
  }
  --depth_;
}

void Printer::visit(Map &map)
{
  std::string indent(depth_, ' ');
  out_ << indent << "map: " << map.ident << std::endl;

  ++depth_;
  if (map.vargs) {
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
    }
  }
  --depth_;
}

void Printer::visit(Variable &var)
{
  std::string indent(depth_, ' ');
  out_ << indent << "variable: " << var.ident << std::endl;
}

void Printer::visit(Binop &binop)
{
  std::string indent(depth_, ' ');
  out_ << indent << opstr(binop) << std::endl;

  ++depth_;
  binop.left->accept(*this);
  binop.right->accept(*this);
  --depth_;
}

void Printer::visit(Unop &unop)
{
  std::string indent(depth_, ' ');
  out_ << indent << opstr(unop) << std::endl;

  ++depth_;
  unop.expr->accept(*this);
  --depth_;
}

void Printer::visit(Ternary &ternary)
{
  std::string indent(depth_, ' ');
  out_ << indent << "?:" << std::endl;

  ++depth_;
  ternary.cond->accept(*this);
  ternary.left->accept(*this);
  ternary.right->accept(*this);
  --depth_;
}

void Printer::visit(FieldAccess &acc)
{
  std::string indent(depth_, ' ');
  out_ << indent << "." << std::endl;

  ++depth_;
  acc.expr->accept(*this);
  --depth_;

  out_ << indent << " " << acc.field << std::endl;
}

void Printer::visit(ArrayAccess &arr)
{
  std::string indent(depth_, ' ');
  out_ << indent << "[]" << std::endl;

  ++depth_;
  arr.expr->accept(*this);
  arr.indexpr->accept(*this);
  --depth_;
}

void Printer::visit(Cast &cast)
{
  std::string indent(depth_, ' ');
  if (cast.is_pointer)
    out_ << indent << "(" << cast.cast_type << "*)" << std::endl;
  else
    out_ << indent << "(" << cast.cast_type << ")" << std::endl;

  ++depth_;
  cast.expr->accept(*this);
  --depth_;
}

void Printer::visit(ExprStatement &expr)
{
  expr.expr->accept(*this);
}

void Printer::visit(AssignMapStatement &assignment)
{
  std::string indent(depth_, ' ');
  out_ << indent << "=" << std::endl;

  ++depth_;
  assignment.map->accept(*this);
  assignment.expr->accept(*this);
  --depth_;
}

void Printer::visit(AssignVarStatement &assignment)
{
  std::string indent(depth_, ' ');
  out_ << indent << "=" << std::endl;

  ++depth_;
  assignment.var->accept(*this);
  assignment.expr->accept(*this);
  --depth_;
}

void Printer::visit(If &if_block)
{
  std::string indent(depth_, ' ');

  out_ << indent << "if" << std::endl;

  ++depth_;
  if_block.cond->accept(*this);

  ++depth_;
  out_ << indent << " then" << std::endl;

  for (Statement *stmt : *if_block.stmts) {
    stmt->accept(*this);
  }

  if (if_block.else_stmts) {
    out_ << indent << " else" << std::endl;
    for (Statement *stmt : *if_block.else_stmts) {
      stmt->accept(*this);
    }
  }
  depth_ -= 2;
}

void Printer::visit(Unroll &unroll)
{
  std::string indent(depth_, ' ');
  out_ << indent << "unroll " << unroll.var << std::endl;
  ++depth_;

  for (Statement *stmt : *unroll.stmts) {
    stmt->accept(*this);
  }
  --depth_;
}

void Printer::visit(Predicate &pred)
{
  std::string indent(depth_, ' ');
  out_ << indent << "pred" << std::endl;

  ++depth_;
  pred.expr->accept(*this);
  --depth_;
}

void Printer::visit(AttachPoint &ap)
{
  std::string indent(depth_, ' ');
  out_ << indent << ap.name(ap.func) << std::endl;
}

void Printer::visit(Probe &probe)
{
  for (AttachPoint *ap : *probe.attach_points) {
    ap->accept(*this);
  }

  ++depth_;
  if (probe.pred) {
    probe.pred->accept(*this);
  }
  for (Statement *stmt : *probe.stmts) {
    stmt->accept(*this);
  }
  --depth_;
}

void Printer::visit(Program &program)
{
  if (program.c_definitions.size() > 0)
    out_ << program.c_definitions << std::endl;

  std::string indent(depth_, ' ');
  out_ << indent << "Program" << std::endl;

  ++depth_;
  for (Probe *probe : *program.probes)
    probe->accept(*this);
  --depth_;
}

} // namespace ast
} // namespace bpftrace
