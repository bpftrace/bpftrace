#include <cctype>
#include <iomanip>
#include <regex>
#include <sstream>

#include "printer.h"
#include "ast.h"

namespace bpftrace {
namespace ast {

void Printer::print(Node *root)
{
  depth_ = 0;
  Visit(*root);
}

std::string Printer::type(const SizedType &ty)
{
  std::stringstream buf;
  if (print_types)
  {
    buf << " :: type[" << ty << ", ctx: " << ty.IsCtxAccess();
    if (ty.GetAS() != AddrSpace::none)
      buf << ", AS(" << ty.GetAS() << ")";
    buf << "]";
  }
  return buf.str();
}

void Printer::visit(Integer &integer)
{
  std::string indent(depth_, ' ');
  out_ << indent << "int: " << integer.n << type(integer.type) << std::endl;
}

void Printer::visit(PositionalParameter &param)
{
  std::string indent(depth_, ' ');

  switch (param.ptype) {
    case PositionalParameterType::positional:
      out_ << indent << "param: $" << param.n << type(param.type) << std::endl;
      break;
    case PositionalParameterType::count:
      out_ << indent << "param: $#" << type(param.type) << std::endl;
      break;
    default:
      break;
  }
}

void Printer::visit(String &string)
{
  std::string indent(depth_, ' ');
  std::stringstream ss;

  for (char c: string.str)
  {
    // the argument of isprint() must be an unsigned char or EOF
    int code = static_cast<unsigned char>(c);
    if (std::isprint(code))
    {
      if (c == '\\')
        ss << "\\\\";
      else if (c == '"')
        ss << "\\\"";
      else
        ss << c;
    }
    else
    {
      if (c == '\n')
        ss << "\\n";
      else if (c == '\t')
        ss << "\\t";
      else if (c == '\r')
        ss << "\\r";
      else
        ss << "\\x" << std::setfill('0') << std::setw(2)
           << std::hex << code;
    }
  }

  out_ << indent << "string: " << ss.str() << type(string.type) << std::endl;
}

void Printer::visit(StackMode &mode)
{
  std::string indent(depth_, ' ');
  out_ << indent << "stack_mode: " << mode.mode << type(mode.type) << std::endl;
}

void Printer::visit(Builtin &builtin)
{
  std::string indent(depth_, ' ');
  out_ << indent << "builtin: " << builtin.ident << type(builtin.type)
       << std::endl;
}

void Printer::visit(Identifier &identifier)
{
  std::string indent(depth_, ' ');
  out_ << indent << "identifier: " << identifier.ident << type(identifier.type)
       << std::endl;
}

void Printer::visit(Call &call)
{
  std::string indent(depth_, ' ');
  out_ << indent << "call: " << call.func << type(call.type) << std::endl;

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
  out_ << indent << "map: " << map.ident << type(map.type) << std::endl;

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
  out_ << indent << "variable: " << var.ident << type(var.type) << std::endl;
}

void Printer::visit(Binop &binop)
{
  std::string indent(depth_, ' ');
  out_ << indent << opstr(binop) << type(binop.type) << std::endl;

  ++depth_;
  binop.left->accept(*this);
  binop.right->accept(*this);
  --depth_;
}

void Printer::visit(Unop &unop)
{
  if (unop.is_post_op)
  {
    std::string indent(depth_ + 1, ' ');

    unop.expr->accept(*this);
    out_ << indent << opstr(unop) << std::endl;
  }
  else
  {
    std::string indent(depth_, ' ');
    out_ << indent << opstr(unop) << std::endl;

    ++depth_;
    unop.expr->accept(*this);
    --depth_;
  }

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

  if (acc.field.size())
    out_ << indent << " " << acc.field << std::endl;
  else
    out_ << indent << " " << acc.index << std::endl;
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

void Printer::visit(Tuple &tuple)
{
  std::string indent(depth_, ' ');
  out_ << indent << "tuple:" << std::endl;

  ++depth_;
  for (Expression *expr : *tuple.elems)
    expr->accept(*this);
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
  out_ << indent << "unroll" << std::endl;

  ++depth_;
  unroll.expr->accept(*this);
  out_ << indent << " block" << std::endl;

  ++depth_;
  for (Statement *stmt : *unroll.stmts) {
    stmt->accept(*this);
  }
  depth_ -= 2;
}

void Printer::visit(While &while_block)
{
  std::string indent(depth_, ' ');

  out_ << indent << "while(" << std::endl;

  ++depth_;
  while_block.cond->accept(*this);

  ++depth_;
  out_ << indent << " )" << std::endl;

  for (Statement *stmt : *while_block.stmts)
  {
    stmt->accept(*this);
  }
}

void Printer::visit(Jump &jump)
{
  std::string indent(depth_, ' ');
  out_ << indent << opstr(jump) << std::endl;
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
