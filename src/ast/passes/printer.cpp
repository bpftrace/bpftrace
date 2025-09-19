#include <cctype>
#include <iomanip>
#include <sstream>
#include <variant>

#include "ast/ast.h"
#include "ast/passes/printer.h"

namespace bpftrace::ast {

void Printer::visit(Integer &integer)
{
  if (integer.original) {
    // This typically means that it has special characters such as separately,
    // suffixes, etc. We preserve these as an esthetic choice.
    out_ << *integer.original;
  } else {
    out_ << integer.value;
  }
}

void Printer::visit(NegativeInteger &integer)
{
  out_ << integer.value;
}

void Printer::visit(Boolean &boolean)
{
  out_ << boolean.value;
}

void Printer::visit(PositionalParameter &param)
{
  out_ << "$" << param.n;
}

void Printer::visit([[maybe_unused]] PositionalParameterCount &param)
{
  out_ << "$#";
}

static std::string escape(const std::string &s)
{
  std::stringstream ss;
  for (char c : s) {
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
  return ss.str();
}

void Printer::visit(String &string)
{
  out_ << "\"" << escape(string.value) << "\"";
}

void Printer::visit([[maybe_unused]] None &none)
{
  // Does not have a syntactic representation.
}

void Printer::visit(Builtin &builtin)
{
  out_ << builtin.ident;
}

void Printer::visit(Identifier &identifier)
{
  out_ << identifier.ident;
}

void Printer::visit(Call &call)
{
  out_ << call.func;
  out_ << "(";
  bool first = true;
  for (auto &arg : call.vargs) {
    if (first) {
      first = false;
    } else {
      out_ << ", ";
    }
    visit(arg);
  }
  out_ << ")";
}

void Printer::visit(Sizeof &szof)
{
  out_ << "sizeof(";
  visit(szof.record);
  out_ << ")";
}

void Printer::visit(Offsetof &offof)
{
  out_ << "offsetof(";
  visit(offof.record);
  out_ << ", ";
  bool first = true;
  for (const auto &field : offof.field) {
    if (!first) {
      out_ << ".";
    } else {
      first = false;
    }
    out_ << field;
  }
  out_ << ")";
}

void Printer::visit(Typeof &typeof)
{
  if (std::holds_alternative<Expression>(typeof.record)) {
    out_ << "typeof(";
    visit(typeof.record);
    out_ << ")";
  } else {
    // Prefer the simpler form for direct types.
    out_ << typestr(std::get<SizedType>(typeof.record));
  }
}

void Printer::visit(Typeinfo &typeinfo)
{
  out_ << "typeof(";
  // This is simplified from the AST.
  if (std::holds_alternative<Expression>(typeinfo.typeof->record)) {
    visit(std::get<Expression>(typeinfo.typeof->record));
  } else {
    visit(std::get<SizedType>(typeinfo.typeof->record));
  }
  out_ << ")";
}

void Printer::visit(MapDeclStatement &decl)
{
  out_ << "let " << decl.ident << " = " << decl.bpf_type << "("
       << decl.max_entries << ")" << std::endl;
}

void Printer::visit(Map &map)
{
  out_ << map.ident;
}

void Printer::visit(MapAddr &map_addr)
{
  out_ << "&" << map_addr.map->ident;
}

void Printer::visit(Variable &var)
{
  out_ << var.ident;
}

void Printer::visit(VariableAddr &var_addr)
{
  out_ << "&" << var_addr.var->ident;
}

void Printer::visit(Binop &binop)
{
  visit(binop.left);
  out_ << " " << opstr(binop) << " ";
  visit(binop.right);
}

void Printer::visit(Unop &unop)
{
  switch (unop.op) {
    case Operator::LNOT:
      out_ << "!";
      visit(unop.expr);
      break;
    case Operator::BNOT:
      out_ << "~";
      visit(unop.expr);
      break;
    case Operator::MINUS:
      out_ << "-";
      visit(unop.expr);
      break;
    case Operator::MUL:
      out_ << "*";
      visit(unop.expr);
      break;
    case Operator::INCREMENT:
      if (unop.is_post_op) {
        visit(unop.expr);
        out_ << "++";

        break;
      } else {
        out_ << "++";
        visit(unop.expr);
      }
      break;
    case Operator::DECREMENT:
      if (unop.is_post_op) {
        visit(unop.expr);
        out_ << "--";

        break;
      } else {
        out_ << "--";
        visit(unop.expr);
      }
      break;
    default:
      out_ << "???";
      visit(unop.expr);
      break;
  }
}

void Printer::visit(IfExpr &if_expr)
{
  out_ << "if ";
  visit(if_expr.cond);
  out_ << " ";
  if (if_expr.left.is<BlockExpr>()) {
    visit(if_expr.left);
  } else {
    out_ << "{ ";
    visit(if_expr.left);
    out_ << " }";
  }
  if (if_expr.right.is<BlockExpr>()) {
    visit(if_expr.right);
  } else if (!if_expr.right.is<None>()) {
    out_ << " else { ";
    visit(if_expr.right);
    out_ << " }";
  }
}

void Printer::visit(FieldAccess &acc)
{
  visit(acc.expr);
  out_ << "." << acc.field;
}

void Printer::visit(ArrayAccess &arr)
{
  visit(arr.expr);
  out_ << "[";
  visit(arr.indexpr);
  out_ << "]";
}

void Printer::visit(TupleAccess &acc)
{
  visit(acc.expr);
  out_ << "." << acc.index;
}

void Printer::visit(MapAccess &acc)
{
  visit(acc.map);
  out_ << "[";
  visit(acc.key);
  out_ << "]";
}

void Printer::visit(Cast &cast)
{
  out_ << "(";
  visit(cast.typeof);
  out_ << ")";
  // Avoid ambiguity: if the expression is a unop, then it needs to be
  // put into parenthesis or it may be ambiguously parsed as a binop.
  if (cast.expr.is<Unop>()) {
    out_ << "(";
    visit(cast.expr);
    out_ << ")";
  } else {
    // Binops and others will be automatically parenthesized.
    visit(cast.expr);
  }
}

void Printer::visit(Tuple &tuple)
{
  out_ << "(";
  for (size_t i = 0; i < tuple.elems.size(); i++) {
    visit(tuple.elems.at(i));
    if (i == 0 || i < tuple.elems.size() - 1) {
      out_ << ",";
    }
  }
  out_ << ")";
}

void Printer::visit(AssignScalarMapStatement &assignment)
{
  visit(assignment.map);
  out_ << " = ";
  visit(assignment.expr);
}

void Printer::visit(AssignMapStatement &assignment)
{
  visit(assignment.map);
  out_ << "[";
  visit(assignment.key);
  out_ << "]";
  out_ << " = ";
  visit(assignment.expr);
}

void Printer::visit(AssignVarStatement &assignment)
{
  visit(assignment.var_decl);
  out_ << " = ";
  visit(assignment.expr);
}

void Printer::visit(AssignConfigVarStatement &assignment)
{
  print_indent();
  out_ << assignment.var << " = ";
  std::visit([&](auto &v) { out_ << v; }, assignment.value);
  out_ << ";" << std::endl;
}

void Printer::visit(VarDeclStatement &decl)
{
  out_ << "let ";
  visit(decl.var);
  if (decl.typeof) {
    out_ << " : ";
    visit(decl.typeof);
  }
}

void Printer::visit(Unroll &unroll)
{
  out_ << "unroll (";
  visit(unroll.expr);
  out_ << ") ";
  visit(unroll.block);
}

void Printer::visit(While &while_block)
{
  out_ << "while (";
  visit(while_block.cond);
  out_ << ") ";
  visit(while_block.block);
}

void Printer::visit(Range &range)
{
  if (!range.start.is_literal() || with_types_) {
    out_ << "(";
    visit(range.start);
    out_ << ")";
  } else {
    visit(range.start);
  }
  out_ << "..";
  if (!range.end.is_literal()) {
    out_ << "(";
    visit(range.end);
    out_ << ")";
  } else {
    visit(range.end);
  }
}

void Printer::visit(For &for_loop)
{
  std::string indent(depth_, ' ');
  out_ << "for (";
  visit(for_loop.decl);
  out_ << " : ";
  visit(for_loop.iterable);
  out_ << ") ";
  print_type(for_loop.ctx_type);
  visit(for_loop.block);
}

void Printer::visit(Config &config)
{
  std::string indent(depth_, ' ');

  out_ << "config = {" << std::endl;
  ++depth_;
  visit(config.stmts);
  --depth_;
  out_ << "}" << std::endl;
}

void Printer::visit(Jump &jump)
{
  switch (jump.ident) {
    case JumpType::RETURN:
      if (jump.return_value) {
        out_ << "return ";
        visit(jump.return_value);
      } else {
        out_ << "return";
      }
      break;
    case JumpType::BREAK:
      out_ << "break";
      break;
    case JumpType::CONTINUE:
      out_ << "continue";
      break;
    default:
      break;
  }
}

void Printer::visit(AttachPoint &ap)
{
  std::string escaped = escape(ap.raw_input);
  if (escaped != ap.raw_input) {
    out_ << "\"" << escaped << "\"";
  } else {
    out_ << ap.raw_input;
  }
}

void Printer::visit(Probe &probe)
{
  bool first = true;
  for (const auto &ap : probe.attach_points) {
    if (first) {
      first = false;
    } else {
      out_ << "," << std::endl;
    }
    visit(ap);
  }
  out_ << " ";
  visit(probe.block);
  out_ << std::endl;
}

void Printer::visit(SubprogArg &arg)
{
  out_ << arg.var->ident << " : " << arg.var->type() << std::endl;
}

void Printer::visit(Subprog &subprog)
{
  bool first = true;
  out_ << "fn " << subprog.name << "(";
  for (const auto &arg : subprog.args) {
    if (first) {
      first = false;
    } else {
      out_ << ", ";
    }
    visit(arg);
  }
  out_ << ")" << subprog.return_type << " ";
  out_ << subprog.block;
  out_ << std::endl;
}

void Printer::visit(Import &imp)
{
  out_ << "import \"" << imp.name << "\";" << std::endl;
}

void Printer::visit(BlockExpr &block)
{
  if (block.stmts.empty()) {
    if (block.expr.is<None>()) {
      out_ << "{}";
    } else {
      out_ << "{ ";
      visit(block.expr);
      out_ << " }";
    }
  } else {
    out_ << "{" << std::endl;
    depth_++;
    visit(block.stmts);
    if (!block.expr.is<None>()) {
      print_indent();
      visit(block.expr);
      out_ << std::endl;
    }
    depth_--;
    print_indent();
    out_ << "}";
  }
}

void Printer::visit(Comptime &comptime)
{
  out_ << "comptime ";
  visit(comptime.expr);
}

void Printer::visit(Program &program)
{
  bool first = true;
  auto check_first = [&] {
    if (!first) {
      out_ << std::endl;
    } else {
      first = false;
    }
  };

  if (program.header && program.header->size() > 0) {
    check_first();
    std::cerr << *program.header;
  }

  if (!program.c_statements.empty()) {
    check_first();
    for (const auto &stmt : program.c_statements) {
      out_ << stmt->data << std::endl;
    }
  }

  if (program.config != nullptr && !program.config->stmts.empty()) {
    check_first();
    print_meta(program.config->loc);
    visit(program.config);
    first = false;
  }

  if (program.imports.empty()) {
    check_first();
    for (auto &import : program.imports) {
      print_meta(import->loc);
      visit(import);
    }
  }

  if (!program.map_decls.empty()) {
    check_first();
    for (auto &decl : program.map_decls) {
      print_meta(decl->loc);
      visit(decl);
    }
  }

  if (!program.functions.empty()) {
    check_first();
    for (auto &fn : program.functions) {
      print_meta(fn->loc);
      visit(fn);
    }
  }

  if (!program.probes.empty()) {
    check_first();
    for (auto &probe : program.probes) {
      print_meta(probe->loc);
      visit(probe);
    }
  }
}

static bool is_block(Expression &expr, bool block_ok)
{
  if (auto *if_expr = expr.as<IfExpr>()) {
    return is_block(if_expr->left, true) &&
           (if_expr->right.is<None>() || is_block(if_expr->right, true));
  } else if (block_ok && expr.is<BlockExpr>()) {
    return true;
  } else {
    return false;
  }
}

void Printer::visit(Statement &stmt)
{
  print_meta(stmt.node().loc);
  print_indent();
  visit(stmt.value);
  // Emit a semi-colon if it is not a block statement.
  if (!stmt.is<For>() && !stmt.is<While>() && !stmt.is<Unroll>()) {
    auto *expr = stmt.as<ExprStatement>();
    if (expr == nullptr || !is_block(expr->expr, false)) {
      out_ << ";";
    }
  }
  out_ << std::endl;
}

void Printer::visit(Expression &expr)
{
  bool needs_braces = expr.is<Binop>();
  if (needs_braces) {
    out_ << "(";
  }
  visit(expr.value);
  if (needs_braces) {
    out_ << ")";
  }
  print_type(expr.type());
}

void Printer::print_type(const SizedType &ty)
{
  if (!with_types_ || ty.IsNoneTy())
    return;
  out_ << " /* " << typestr(ty, true);
  if (ty.IsCtxAccess())
    out_ << ", ctx: 1";
  if (ty.GetAS() != AddrSpace::none)
    out_ << ", AS(" << ty.GetAS() << ")";
  out_ << " */";
}

void Printer::print_meta(const Location &loc)
{
  auto comments = loc->comments();
  auto parts = util::split_string(comments, '\n');
  for (const auto &part : parts) {
    print_indent();
    out_ << "// " << part << std::endl;
  }
  for (size_t i = 0; i < loc->vspace(); i++) {
    out_ << std::endl;
  }
}

void Printer::print_indent()
{
  for (int i = 0; i < depth_ * 2; i++) {
    out_ << ' ';
  }
}

} // namespace bpftrace::ast
