#include "ast/passes/printer.h"

#include <cctype>
#include <iomanip>
#include <regex>
#include <sstream>

#include "ast/ast.h"
#include "struct.h"

namespace bpftrace::ast {

void Printer::print()
{
  ++depth_;
  visit(ctx_.root);
  --depth_;
}

std::string Printer::type(const SizedType &ty)
{
  if (ty.IsNoneTy())
    return "";
  std::stringstream buf;
  buf << " :: [" << ty;
  if (ty.IsCtxAccess())
    buf << ", ctx: 1";
  if (ty.GetAS() != AddrSpace::none)
    buf << ", AS(" << ty.GetAS() << ")";
  buf << "]";
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

  for (char c : string.str) {
    // the argument of isprint() must be an unsigned char or EOF
    int code = static_cast<unsigned char>(c);
    if (std::isprint(code)) {
      if (c == '\\')
        ss << "\\\\";
      else if (c == '"')
        ss << "\\\"";
      else
        ss << c;
    } else {
      if (c == '\n')
        ss << "\\n";
      else if (c == '\t')
        ss << "\\t";
      else if (c == '\r')
        ss << "\\r";
      else
        ss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << code;
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
  visit(call.vargs);
  --depth_;
}

void Printer::visit(Sizeof &szof)
{
  std::string indent(depth_, ' ');
  out_ << indent << "sizeof: " << type(szof.type) << std::endl;

  ++depth_;
  visit(szof.expr);
  --depth_;
}

void Printer::visit(Offsetof &offof)
{
  std::string indent(depth_, ' ');
  out_ << indent << "offsetof: " << type(offof.type) << std::endl;

  ++depth_;
  std::string indentParam(depth_, ' ');

  // Print the args
  if (offof.expr) {
    visit(*offof.expr);
  } else {
    out_ << indentParam << offof.record << std::endl;
  }

  for (const auto &field : offof.field) {
    out_ << indentParam << field << std::endl;
  }
  --depth_;
}

void Printer::visit(Map &map)
{
  std::string indent(depth_, ' ');
  out_ << indent << "map: " << map.ident << type(map.type) << std::endl;

  ++depth_;
  visit(map.key_expr);
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
  visit(binop.left);
  visit(binop.right);
  --depth_;
}

void Printer::visit(Unop &unop)
{
  std::string indent(depth_, ' ');
  out_ << indent << opstr(unop) << type(unop.type) << std::endl;

  ++depth_;
  visit(unop.expr);
  --depth_;
}

void Printer::visit(Ternary &ternary)
{
  std::string indent(depth_, ' ');
  out_ << indent << "?:" << type(ternary.type) << std::endl;

  ++depth_;
  visit(ternary.cond);
  visit(ternary.left);
  visit(ternary.right);
  --depth_;
}

void Printer::visit(FieldAccess &acc)
{
  std::string indent(depth_, ' ');
  out_ << indent << "." << type(acc.type) << std::endl;

  ++depth_;
  visit(acc.expr);
  --depth_;

  if (acc.field.size())
    out_ << indent << " " << acc.field << std::endl;
  else
    out_ << indent << " " << acc.index << std::endl;
}

void Printer::visit(ArrayAccess &arr)
{
  std::string indent(depth_, ' ');
  out_ << indent << "[]" << type(arr.type) << std::endl;

  ++depth_;
  visit(arr.expr);
  visit(arr.indexpr);
  --depth_;
}

void Printer::visit(Cast &cast)
{
  std::string indent(depth_, ' ');
  out_ << indent << "(" << cast.type << ")" << std::endl;

  ++depth_;
  visit(cast.expr);
  --depth_;
}

void Printer::visit(Tuple &tuple)
{
  std::string indent(depth_, ' ');
  out_ << indent << "tuple:" << type(tuple.type) << std::endl;

  ++depth_;
  visit(tuple.elems);
  --depth_;
}

void Printer::visit(ExprStatement &expr)
{
  visit(expr.expr);
}

void Printer::visit(AssignMapStatement &assignment)
{
  std::string indent(depth_, ' ');
  out_ << indent << "=" << std::endl;

  ++depth_;
  visit(assignment.map);
  visit(assignment.expr);
  --depth_;
}

void Printer::visit(AssignVarStatement &assignment)
{
  std::string indent(depth_, ' ');

  if (assignment.var_decl_stmt) {
    visit(assignment.var_decl_stmt);
    ++depth_;
    visit(assignment.expr);
    --depth_;
  } else {
    out_ << indent << "=" << std::endl;

    ++depth_;
    visit(assignment.var);
    visit(assignment.expr);
    --depth_;
  }
}

void Printer::visit(AssignConfigVarStatement &assignment)
{
  std::string indent(depth_, ' ');
  out_ << indent << "=" << std::endl;

  ++depth_;
  std::string indentVar(depth_, ' ');
  out_ << indentVar << "config var: " << assignment.config_var << std::endl;
  visit(assignment.expr);
  --depth_;
}

void Printer::visit(VarDeclStatement &decl)
{
  std::string indent(depth_, ' ');
  out_ << indent << "decl" << std::endl;
  ++depth_;
  visit(decl.var);
  --depth_;
}

void Printer::visit(If &if_node)
{
  std::string indent(depth_, ' ');

  out_ << indent << "if" << std::endl;

  ++depth_;
  visit(if_node.cond);

  ++depth_;
  out_ << indent << " then" << std::endl;

  visit(if_node.if_block);

  if (!if_node.else_block->stmts.empty()) {
    out_ << indent << " else" << std::endl;
    visit(if_node.else_block);
  }
  depth_ -= 2;
}

void Printer::visit(Unroll &unroll)
{
  std::string indent(depth_, ' ');
  out_ << indent << "unroll" << std::endl;

  ++depth_;
  visit(unroll.expr);
  out_ << indent << " block" << std::endl;

  ++depth_;
  visit(unroll.block);
  depth_ -= 2;
}

void Printer::visit(While &while_block)
{
  std::string indent(depth_, ' ');

  out_ << indent << "while(" << std::endl;

  ++depth_;
  visit(while_block.cond);

  ++depth_;
  out_ << indent << " )" << std::endl;

  visit(while_block.block);
}

void Printer::visit(For &for_loop)
{
  std::string indent(depth_, ' ');
  out_ << indent << "for" << std::endl;

  ++depth_;
  if (for_loop.ctx_type.IsRecordTy() &&
      !for_loop.ctx_type.GetFields().empty()) {
    out_ << indent << " ctx\n";
    for (const auto &field : for_loop.ctx_type.GetFields()) {
      out_ << indent << "  " << field.name << type(field.type) << "\n";
    }
  }

  out_ << indent << " decl\n";
  ++depth_;
  visit(for_loop.decl);
  --depth_;

  out_ << indent << " expr\n";
  ++depth_;
  visit(for_loop.expr);
  --depth_;

  out_ << indent << " stmts\n";
  ++depth_;
  visit(for_loop.stmts);
  --depth_;

  --depth_;
}

void Printer::visit(Config &config)
{
  std::string indent(depth_, ' ');

  out_ << indent << "config" << std::endl;

  ++depth_;
  visit(config.stmts);
  --depth_;
}

void Printer::visit(Jump &jump)
{
  std::string indent(depth_, ' ');
  out_ << indent << opstr(jump) << std::endl;
  ++depth_;
  visit(jump.return_value);
  --depth_;
}

void Printer::visit(Predicate &pred)
{
  std::string indent(depth_, ' ');
  out_ << indent << "pred" << std::endl;

  ++depth_;
  visit(pred.expr);
  --depth_;
}

void Printer::visit(AttachPoint &ap)
{
  std::string indent(depth_, ' ');
  out_ << indent << ap.name() << std::endl;
}

void Printer::visit(Probe &probe)
{
  visit(probe.attach_points);

  ++depth_;
  visit(probe.pred);
  visit(probe.block);
  --depth_;
}

void Printer::visit(Subprog &subprog)
{
  std::string indent(depth_, ' ');
  out_ << indent << subprog.name() << ": " << subprog.return_type;

  out_ << "(";
  for (size_t i = 0; i < subprog.args.size(); i++) {
    auto &arg = subprog.args.at(i);
    out_ << arg->name() << " : " << arg->type;
    if (i < subprog.args.size() - 1)
      out_ << ", ";
  }
  out_ << ")" << std::endl;

  ++depth_;
  visit(subprog.stmts);
  --depth_;
}

void Printer::visit(Program &program)
{
  if (program.c_definitions.size() > 0)
    out_ << program.c_definitions << std::endl;

  std::string indent(depth_, ' ');
  out_ << indent << "Program" << std::endl;

  ++depth_;
  visit(program.config);
  --depth_;

  ++depth_;
  visit(program.functions);
  visit(program.probes);
  --depth_;
}

} // namespace bpftrace::ast
