#include "ast/passes/printer.h"

#include <cctype>
#include <iomanip>
#include <sstream>

#include "ast/ast.h"
#include "struct.h"

namespace bpftrace::ast {

std::string Printer::type(const SizedType &ty)
{
  if (ty.IsNoneTy())
    return "";
  std::stringstream buf;
  buf << " :: [" << typestr(ty);
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
  out_ << indent << "int: " << integer.value << type(integer.type())
       << std::endl;
}

void Printer::visit(NegativeInteger &integer)
{
  std::string indent(depth_, ' ');
  out_ << indent << "negative int: " << integer.value << type(integer.type())
       << std::endl;
}

void Printer::visit(Boolean &boolean)
{
  std::string indent(depth_, ' ');
  out_ << indent << "bool: " << (boolean.value ? "true" : "false") << std::endl;
}

void Printer::visit(PositionalParameter &param)
{
  std::string indent(depth_, ' ');
  out_ << indent << "param: $" << param.n << std::endl;
}

void Printer::visit([[maybe_unused]] PositionalParameterCount &param)
{
  std::string indent(depth_, ' ');
  out_ << indent << "param: $#" << std::endl;
}

void Printer::visit(String &string)
{
  std::string indent(depth_, ' ');
  std::stringstream ss;

  for (char c : string.value) {
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

  out_ << indent << "string: " << ss.str() << std::endl;
}

void Printer::visit([[maybe_unused]] None &none)
{
  // Just omit this, since it adds tons of noise.
}

void Printer::visit(Builtin &builtin)
{
  std::string indent(depth_, ' ');
  out_ << indent << "builtin: " << builtin.ident << type(builtin.builtin_type)
       << std::endl;
}

void Printer::visit(Identifier &identifier)
{
  std::string indent(depth_, ' ');
  out_ << indent << "identifier: " << identifier.ident
       << type(identifier.ident_type) << std::endl;
}

void Printer::visit(Call &call)
{
  std::string indent(depth_, ' ');
  out_ << indent << "call: " << call.func << type(call.return_type)
       << std::endl;

  ++depth_;
  visit(call.vargs);
  --depth_;
}

void Printer::visit(Sizeof &szof)
{
  std::string indent(depth_, ' ');
  out_ << indent << "sizeof: " << std::endl;

  ++depth_;
  visit(szof.record);
  --depth_;
}

void Printer::visit(Offsetof &offof)
{
  std::string indent(depth_, ' ');
  out_ << indent << "offsetof: " << std::endl;

  ++depth_;
  std::string indentParam(depth_, ' ');

  // Print the args
  if (std::holds_alternative<Expression>(offof.record)) {
    visit(std::get<Expression>(offof.record));
  } else {
    out_ << indentParam << std::get<SizedType>(offof.record) << std::endl;
  }

  for (const auto &field : offof.field) {
    out_ << indentParam << field << std::endl;
  }
  --depth_;
}

void Printer::visit(Typeof &typeof)
{
  std::string indent(depth_, ' ');
  out_ << indent << "typeof: " << std::endl;

  ++depth_;
  visit(typeof.record);
  --depth_;
}

void Printer::visit(Typeinfo &typeinfo)
{
  std::string indent(depth_, ' ');
  out_ << indent << "typeinfo: " << std::endl;

  ++depth_;
  visit(typeinfo.typeof);
  --depth_;
}

void Printer::visit(MapDeclStatement &decl)
{
  std::string indent(depth_, ' ');
  out_ << indent << "map decl: " << decl.ident << std::endl;

  ++depth_;
  std::string indentType(depth_, ' ');
  out_ << indentType << "bpf type: " << decl.bpf_type << std::endl;
  out_ << indentType << "max entries: " << decl.max_entries << std::endl;
  --depth_;
}

void Printer::visit(Map &map)
{
  // Use a slightly customized format for the map type here, since it is never
  // going to be marked as `is_ctx` or have an associated address space.
  std::string indent(depth_, ' ');
  out_ << indent << "map: " << map.ident;
  if (!map.key_type.IsNoneTy() || !map.value_type.IsNoneTy()) {
    out_ << " :: ";
  }
  if (!map.key_type.IsNoneTy()) {
    out_ << "[" << typestr(map.key_type) << "]";
  }
  if (!map.value_type.IsNoneTy()) {
    out_ << typestr(map.value_type);
  }
  out_ << std::endl;
}

void Printer::visit(MapAddr &map_addr)
{
  std::string indent(depth_, ' ');

  out_ << indent << "&" << std::endl;

  ++depth_;
  visit(map_addr.map);
  --depth_;
}

void Printer::visit(Variable &var)
{
  std::string indent(depth_, ' ');
  out_ << indent << "variable: " << var.ident << type(var.var_type)
       << std::endl;
}

void Printer::visit(VariableAddr &var_addr)
{
  std::string indent(depth_, ' ');

  out_ << indent << "&" << std::endl;

  ++depth_;
  visit(var_addr.var);
  --depth_;
}

void Printer::visit(Binop &binop)
{
  std::string indent(depth_, ' ');
  out_ << indent << opstr(binop) << type(binop.result_type) << std::endl;

  ++depth_;
  visit(binop.left);
  visit(binop.right);
  --depth_;
}

void Printer::visit(Unop &unop)
{
  std::string indent(depth_, ' ');
  out_ << indent << opstr(unop) << type(unop.result_type) << std::endl;

  ++depth_;
  visit(unop.expr);
  --depth_;
}

void Printer::visit(IfExpr &if_expr)
{
  std::string indent(depth_, ' ');
  out_ << indent << "if" << type(if_expr.result_type) << std::endl;

  ++depth_;
  visit(if_expr.cond);

  ++depth_;
  out_ << indent << " then" << std::endl;
  visit(if_expr.left);

  if (!if_expr.right.is<None>()) {
    out_ << indent << " else" << std::endl;
    visit(if_expr.right);
  }

  depth_ -= 2;
}

void Printer::visit(FieldAccess &acc)
{
  std::string indent(depth_, ' ');
  out_ << indent << "." << type(acc.field_type) << std::endl;

  ++depth_;
  visit(acc.expr);
  --depth_;

  out_ << indent << " " << acc.field << std::endl;
}

void Printer::visit(ArrayAccess &arr)
{
  std::string indent(depth_, ' ');
  out_ << indent << "[]" << type(arr.element_type) << std::endl;

  ++depth_;
  visit(arr.expr);
  visit(arr.indexpr);
  --depth_;
}

void Printer::visit(TupleAccess &acc)
{
  std::string indent(depth_, ' ');
  out_ << indent << "." << type(acc.element_type) << std::endl;

  ++depth_;
  visit(acc.expr);
  --depth_;

  out_ << indent << " " << acc.index << std::endl;
}

void Printer::visit(MapAccess &acc)
{
  std::string indent(depth_, ' ');
  out_ << indent << "[]" << type(acc.type()) << std::endl;

  ++depth_;
  visit(acc.map);
  visit(acc.key);
  --depth_;
}

void Printer::visit(Cast &cast)
{
  std::string indent(depth_, ' ');
  out_ << indent << "(" << cast.type() << ")" << std::endl;

  ++depth_;
  visit(cast.expr);
  --depth_;
}

void Printer::visit(Tuple &tuple)
{
  std::string indent(depth_, ' ');
  out_ << indent << "tuple:" << type(tuple.type()) << std::endl;

  ++depth_;
  visit(tuple.elems);
  --depth_;
}

void Printer::visit(ExprStatement &expr)
{
  visit(expr.expr);
}

void Printer::visit(AssignScalarMapStatement &assignment)
{
  std::string indent(depth_, ' ');
  out_ << indent << "=" << std::endl;

  ++depth_;
  visit(assignment.map);
  visit(assignment.expr);
  --depth_;
}

void Printer::visit(AssignMapStatement &assignment)
{
  std::string indent(depth_, ' ');
  out_ << indent << "=" << std::endl;

  ++depth_;
  visit(assignment.map_access);
  visit(assignment.expr);
  --depth_;
}

void Printer::visit(AssignVarStatement &assignment)
{
  std::string indent(depth_, ' ');

  if (std::holds_alternative<VarDeclStatement *>(assignment.var_decl)) {
    visit(std::get<VarDeclStatement *>(assignment.var_decl));
    ++depth_;
    visit(assignment.expr);
    --depth_;
  } else {
    out_ << indent << "=" << std::endl;

    ++depth_;
    visit(std::get<Variable *>(assignment.var_decl));
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
  out_ << indentVar << "var: " << assignment.var << std::endl;
  std::visit(
      [&](auto &v) {
        if constexpr (std::is_same_v<std::decay_t<decltype(v)>, std::string>) {
          out_ << indentVar << "string: " << v << std::endl;
        } else if constexpr (std::is_same_v<std::decay_t<decltype(v)>, bool>) {
          out_ << indentVar << "bool: " << (v ? "true" : "false") << std::endl;
        } else {
          out_ << indentVar << "int: " << v << std::endl;
        }
      },
      assignment.value);
  --depth_;
}

void Printer::visit(VarDeclStatement &decl)
{
  std::string indent(depth_, ' ');

  if (decl.typeof) {
    out_ << indent << "decl" << type(decl.typeof->type()) << std::endl;
  } else {
    out_ << indent << "decl" << std::endl;
  }

  ++depth_;
  visit(decl.var);
  --depth_;
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

void Printer::visit(Range &range)
{
  std::string indent(depth_, ' ');

  out_ << indent << "start\n";
  ++depth_;
  visit(range.start);
  --depth_;

  out_ << indent << "end\n";
  ++depth_;
  visit(range.end);
  --depth_;
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
  visit(for_loop.iterable);
  --depth_;

  out_ << indent << " stmts\n";
  ++depth_;
  visit(for_loop.block);
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

void Printer::visit(AttachPoint &ap)
{
  std::string indent(depth_, ' ');
  out_ << indent << ap.name() << std::endl;
}

void Printer::visit(Probe &probe)
{
  visit(probe.attach_points);

  ++depth_;
  visit(probe.block);
  --depth_;
}

void Printer::visit(SubprogArg &arg)
{
  std::string indent(depth_, ' ');

  ++depth_;
  out_ << indent << arg.var->ident << type(arg.typeof->type()) << std::endl;
  --depth_;
}

void Printer::visit(Subprog &subprog)
{
  std::string indent(depth_, ' ');
  out_ << indent << "subprog: " << subprog.name
       << type(subprog.return_type->type()) << std::endl;

  ++depth_;

  if (!subprog.args.empty()) {
    ++depth_;
    out_ << indent << " args" << std::endl;
    visit(subprog.args);
    --depth_;
  }

  visit(subprog.block);

  --depth_;
}

void Printer::visit(RootImport &imp)
{
  std::string indent(depth_, ' ');
  out_ << indent << "import " << imp.name << std::endl;
}

void Printer::visit(StatementImport &imp)
{
  std::string indent(depth_, ' ');
  out_ << indent << "import " << imp.name << std::endl;
}

void Printer::visit(Program &program)
{
  for (const auto &stmt : program.c_statements) {
    out_ << stmt->data << std::endl;
  }

  std::string indent(depth_, ' ');
  out_ << indent << "Program" << std::endl;

  ++depth_;
  visit(program.config);
  --depth_;

  ++depth_;
  visit(program.imports);
  --depth_;

  ++depth_;
  visit(program.map_decls);
  --depth_;

  ++depth_;
  visit(program.functions);
  visit(program.probes);
  --depth_;
}

} // namespace bpftrace::ast
