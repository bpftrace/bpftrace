#include <cctype>
#include <iomanip>
#include <sstream>
#include <variant>

#include "ast/ast.h"
#include "ast/passes/printer.h"
#include "types.h"
#include "util/strings.h"

namespace bpftrace::ast {

constexpr size_t kIndentWidth = 2;

static bool is_whitespace(const std::string& s)
{
  return std::ranges::all_of(s, [](char c) { return std::isspace(c); });
}

namespace {
struct Text {
  Text(std::string data) : data(std::move(data)) {};
  std::string data;
};
struct Comment {
  Comment(std::string data) : data(std::move(data)) {};
  std::string data;
};
struct Line {
  Line() = default;
  size_t columns() const
  {
    // Compute the number of columns in this line. For now,
    // we just reify the line and return the character count.
    return reify().size();
  }
  std::string reify() const
  {
    bool all_whitespace = true;
    std::stringstream ss;
    for (size_t i = 0; i < segments.size(); i++) {
      const auto& seg = segments[i];
      if (std::holds_alternative<Text>(seg)) {
        const auto& s = std::get<Text>(seg).data;
        ss << s;
        all_whitespace = all_whitespace && is_whitespace(s);
      } else if (std::holds_alternative<Comment>(seg)) {
        if (!all_whitespace) {
          ss << " ";
        }
        if (i == segments.size() - 1) {
          ss << "// " << std::get<Comment>(seg).data;
        } else {
          ss << "/* " << std::get<Comment>(seg).data << " */";
        }
      }
    }
    return ss.str();
  }
  std::vector<std::variant<Text, Comment>> segments;
};
} // namespace

struct BufferState {
  std::vector<Line> lines;
  size_t current_depth = 0;
};

Buffer::Buffer() : state(std::make_unique<BufferState>())
{
  state->lines.emplace_back();
};

Buffer::~Buffer() = default;

Buffer&& Buffer::append(Buffer&& other, size_t indent)
{
  if (other.lines() == 0) {
    return std::move(*this);
  } else {
    // Record the current column, and extend from there.
    size_t col = state->lines.back().columns();
    if (indent > 0) {
      state->lines.emplace_back();
      col = indent;
    }
    for (size_t i = 0; i < other.state->lines.size(); i++) {
      auto& line = other.state->lines[i];
      if (col != 0 && state->lines.back().segments.empty()) {
        state->lines.back().segments.emplace_back(Text(std::string(col, ' ')));
      }
      state->lines.back().segments.insert(
          state->lines.back().segments.end(),
          std::make_move_iterator(line.segments.begin()),
          std::make_move_iterator(line.segments.end()));
      // Only add a new line if there are more lines or we are in indenting
      // mode, which carries an implicit newline at the end of the block.
      if (indent > 0 || i < other.state->lines.size() - 1) {
        state->lines.emplace_back();
      }
    }
  }

  // We extend from our current final line.
  return std::move(*this);
}

Buffer&& Buffer::text(std::string str)
{
  state->lines.back().segments.emplace_back(Text(std::move(str)));
  return std::move(*this);
}

Buffer&& Buffer::comment(std::string str)
{
  state->lines.back().segments.emplace_back(Comment(std::move(str)));
  return std::move(*this);
}

Buffer&& Buffer::metadata(MetadataIndex metadata,
                          std::optional<size_t> min_vspace)
{
  bool inline_style = !min_vspace.has_value();
  if (!inline_style) {
    size_t total_vspace = 0;
    if (min_vspace) {
      for (size_t i = 0; i < *min_vspace; i++) {
        state->lines.emplace_back();
      }
    }
    for (const auto& part : metadata.all()) {
      if (std::holds_alternative<size_t>(part)) {
        for (size_t i = 0; i < std::get<size_t>(part); i++) {
          if (min_vspace && total_vspace < *min_vspace) {
            // Already done above.
          } else {
            state->lines.emplace_back();
          }
          total_vspace++;
        }
      } else {
        // This is a full-line comment.
        state->lines.back().segments.emplace_back(
            Comment(std::get<std::string>(part)));
        state->lines.emplace_back();
      }
    }
  } else {
    // In the style is inline, then we drop any vertical space.
    // This is basically condensing comments that are inline for
    // an expression into an inline comment. If they should be
    // multiple lines, then they can associated with a top-level
    // node, like the statement itself.
    for (const auto& part : metadata.all()) {
      if (std::holds_alternative<std::string>(part)) {
        state->lines.back().segments.emplace_back(
            Comment(std::get<std::string>(part)));
      }
    }
  }
  return std::move(*this);
}

Buffer&& Buffer::line_break()
{
  state->lines.emplace_back();
  return std::move(*this);
}

size_t Buffer::width() const
{
  size_t max_width = 0;
  for (const auto& line : state->lines) {
    max_width = std::max(max_width, line.columns());
  }
  return max_width;
}

size_t Buffer::lines() const
{
  if (state->lines.back().segments.empty()) {
    return state->lines.size() - 1;
  } else {
    return state->lines.size();
  }
}

std::ostream& operator<<(std::ostream& out, const Buffer& buffer)
{
  for (size_t i = 0; i < buffer.lines(); i++) {
    const auto& line = buffer.state->lines[i];
    auto s = line.reify();
    out << util::rtrim(s) << std::endl;
  }
  return out;
}

template <typename T, typename Fn>
static void foreach(std::ostream& out,
                    std::vector<T>& items,
                    const std::string& sep,
                    Fn fn)
{
  bool first = true;
  for (auto& item : items) {
    if (first) {
      first = false;
    } else {
      out << sep;
    }
    first = false;
    fn(item);
  }
}

static bool is_primitive(const Expression& expr)
{
  if (expr.is<Integer>() || expr.is<NegativeInteger>() || expr.is<String>() ||
      expr.is<Boolean>() || expr.is<PositionalParameter>() ||
      expr.is<PositionalParameterCount>() || expr.is<None>() ||
      expr.is<Identifier>() || expr.is<Builtin>() || expr.is<Sizeof>() ||
      expr.is<Offsetof>() || expr.is<Typeinfo>() || expr.is<Variable>() ||
      expr.is<ArrayAccess>() || expr.is<TupleAccess>() ||
      expr.is<MapAccess>() || expr.is<Call>() || expr.is<Map>()) {
    return true;
  }
  if (auto* comptime = expr.as<Comptime>()) {
    return is_primitive(comptime->expr);
  }
  return false;
}

Buffer Formatter::visit(CStatement& cstmt)
{
  return Buffer().text(cstmt.data);
}

Buffer Formatter::visit(Integer& integer)
{
  if (integer.original) {
    // This typically means that it has special characters such as separately,
    // suffixes, etc. We preserve these as an esthetic choice.
    return Buffer().text(*integer.original);
  } else {
    return Buffer().text(std::to_string(integer.value));
  }
}

Buffer Formatter::visit(NegativeInteger& integer)
{
  return Buffer().text(std::to_string(integer.value));
}

Buffer Formatter::visit(Boolean& boolean)
{
  return boolean.value ? Buffer().text("true") : Buffer().text("false");
}

Buffer Formatter::visit(PositionalParameter& param)
{
  return Buffer().text("$" + std::to_string(param.n));
}

Buffer Formatter::visit([[maybe_unused]] PositionalParameterCount& param)
{
  return Buffer().text("$#");
}

static std::string escape(const std::string& s)
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

Buffer Formatter::visit(String& string)
{
  return Buffer().text("\"" + escape(string.value) + "\"");
}

Buffer Formatter::visit([[maybe_unused]] None& none)
{
  // Does not have a syntactic representation. We should never get
  // here during a normal traversal, but we can just emit "none".
  return Buffer().text("none");
}

Buffer Formatter::visit(Builtin& builtin)
{
  return Buffer().text(builtin.ident);
}

Buffer Formatter::visit(Identifier& identifier)
{
  return Buffer().text(identifier.ident);
}

Buffer Formatter::format(std::vector<Expression>& exprs,
                         MetadataIndex& metadata,
                         size_t max_width)
{
  // We need to carefully extract the metadata for all the arguments, and
  // position them correctly. Depending on the width, we will do either
  // multiline in inline.
  std::vector<Buffer> args;
  size_t total_width = 0;
  for (size_t i = 0; i < exprs.size(); i++) {
    auto arg = format(exprs[i],
                      metadata,
                      (i < exprs.size() - 1) ? max_width - 1 : max_width,
                      true);
    if (i < exprs.size() - 1) {
      arg = arg.text(", ");
    }
    total_width += arg.width();
    args.emplace_back(std::move(arg));
  }
  if (total_width < max_width) {
    // Join into a single line.
    auto single_line_args = Buffer();
    for (size_t i = 0; i < exprs.size(); i++) {
      single_line_args = single_line_args.append(std::move(args[i]));
    }
    return single_line_args;
  } else {
    // Split each call to its own line.
    auto multi_line_args = Buffer();
    for (size_t i = 0; i < exprs.size(); i++) {
      if (i > 0) {
        multi_line_args = multi_line_args.line_break();
      }
      multi_line_args = multi_line_args.append(std::move(args[i]));
    }
    return multi_line_args;
  }
}

Buffer Formatter::visit(Call& call)
{
  auto args = format(call.vargs, metadata, max_width - (call.func.size() + 2));
  if (args.width() > max_width) {
    // Return with the newline break style.
    //
    //    foo(
    //      a,
    //      b
    //    );
    return Buffer()
        .text(call.func + "(")
        .append(std::move(args), kIndentWidth)
        .text(")");
  } else {
    // Return as is, with the inline or multi-line style.
    //
    //    foo(a, b, c)
    //
    //    foo(a,
    //        b,
    //        c);
    //
    return Buffer().text(call.func + "(").append(std::move(args)).text(")");
  }
}

Buffer Formatter::visit(Sizeof& szof)
{
  // N.B. Does not support splitting.
  return Buffer()
      .text("sizeof(")
      .append(std::visit(
          [&](auto& v) { return format(v, metadata, max_width - 8, true); },
          szof.record))
      .text(")");
}

Buffer Formatter::visit(Offsetof& ofof)
{
  // N.B. Does not support splitting.
  auto fields = Buffer();
  for (size_t i = 0; i < ofof.field.size(); i++) {
    if (i > 0) {
      fields = fields.text(".");
    }
    fields = fields.text(ofof.field[i]);
  }
  auto expr = format(ofof.record, metadata, max_width);
  return Buffer()
      .text("offsetof(")
      .append(std::move(expr))
      .text(", ")
      .append(std::move(fields))
      .text(")");
}

Buffer Formatter::visit(Typeof& typeof)
{
  if (std::holds_alternative<Expression>(typeof.record)) {
    return Buffer().text("typeof(").append(
        format(
            std::get<Expression>(typeof.record), metadata, max_width - 8, true)
            .text(")"));
  } else {
    // Prefer the simpler form for direct types.
    return format(
        std::get<SizedType>(typeof.record), metadata, max_width, bare);
  }
}

Buffer Formatter::visit(Typeinfo& typeinfo)
{
  if (std::holds_alternative<Expression>(typeinfo.typeof->record)) {
    // Omit the `typeof` for `typeinfo`.
    return Buffer()
        .text("typeinfo(")
        .append(format(typeinfo.typeof->record, metadata, max_width - 10, true))
        .text(")");
  } else {
    // Use the default representation.
    return Buffer()
        .text("typeinfo(")
        .append(format(typeinfo.typeof, metadata, max_width - 10, true))
        .text(")");
  }
}

Buffer Formatter::visit(MapDeclStatement& decl)
{
  std::stringstream bpf_type;
  bpf_type << decl.bpf_type;
  return Buffer()
      .text("let ")
      .text(decl.ident)
      .text(" = ")
      .text(bpf_type.str())
      .text("(")
      .text(std::to_string(decl.max_entries))
      .text(");");
}

Buffer Formatter::visit(Map& map)
{
  return Buffer().text(map.ident);
}

Buffer Formatter::visit(MapAddr& map_addr)
{
  return Buffer().text("&").text(map_addr.map->ident);
}

Buffer Formatter::visit(Variable& var)
{
  return Buffer().text(var.ident);
}

Buffer Formatter::visit(VariableAddr& var_addr)
{
  return Buffer().text("&").text(var_addr.var->ident);
}

static bool is_comparison(const Binop& binop)
{
  switch (binop.op) {
    case Operator::EQ:
    case Operator::NE:
    case Operator::LE:
    case Operator::GE:
    case Operator::LT:
    case Operator::GT:
      return true;
    default:
      return false;
  }
  return false;
}

Buffer Formatter::visit(Binop& binop)
{
  auto ops = opstr(binop);

  // Special case: allow chaining of comparisons. We don't strictly
  // require the use of nested brackets as long as the comparison
  // is ambiguious, but we will add brackets if either side involves
  // other comparison operators.
  std::vector<Expression> chained_entries;
  bool is_logical = binop.op == Operator::LAND || binop.op == Operator::LOR;
  std::function<void(Expression & expr)> expand;
  expand = [&](Expression& expr) {
    if (is_logical && expr.is<Binop>() && expr.as<Binop>()->op == binop.op) {
      auto* other_binop = expr.as<Binop>();
      expand(other_binop->left);
      expand(other_binop->right);
    } else {
      chained_entries.push_back(expr);
    }
  };
  expand(binop.left);
  expand(binop.right);
  std::vector<Buffer> chained_buffers;
  size_t total_width = 0;
  for (size_t i = 0; i < chained_entries.size(); i++) {
    auto& expr = chained_entries[i];
    bool bare = is_primitive(expr) ||
                (expr.is<Binop>() && is_comparison(*expr.as<Binop>()));
    auto expr_metadata = metadata.before(expr.node().loc->current.begin);
    chained_buffers.emplace_back(format(expr,
                                        expr_metadata,
                                        (i < chained_entries.size() - 1)
                                            ? max_width - (ops.size() + 1)
                                            : max_width,
                                        bare));
    total_width += chained_buffers.back().width();
  }
  auto buffer = Buffer();
  for (size_t i = 0; i < chained_buffers.size(); i++) {
    auto& other_buf = chained_buffers[i];
    buffer = buffer.append(std::move(other_buf));
    if (i < chained_buffers.size() - 1) {
      if (total_width > max_width) {
        buffer = buffer.text(" " + ops).line_break();
      } else {
        buffer = buffer.text(" " + ops + " ");
      }
    }
  }
  return buffer;
}

Buffer Formatter::visit(Unop& unop)
{
  auto ops = opstr(unop);
  auto expr = format(unop.expr, metadata, max_width - ops.size());
  return Buffer().text(opstr(unop)).append(std::move(expr));
}

Buffer Formatter::visit(IfExpr& if_expr)
{
  // Figure out the full set of branches.
  std::vector<std::pair<Buffer, Buffer>> if_pairs;
  std::optional<Buffer> final_else;
  size_t total_width = 0;

  // Check if this is a ternary expression. You could technically
  // technically have a ternary expression using blocks, but we prefer
  // to convert that to a full if expression.
  if (!if_expr.left.is<BlockExpr>() && !if_expr.right.is<BlockExpr>() &&
      !if_expr.right.is<None>()) {
    auto cond = format(if_expr.cond, metadata, max_width);
    auto left = format(if_expr.left, metadata, max_width - 2);
    auto right = format(if_expr.right, metadata, max_width - 2);
    if (cond.width() + left.width() + right.width() + 8 > max_width) {
      return Buffer()
          .append(std::move(cond))
          .line_break()
          .text("? ")
          .append(std::move(left))
          .line_break()
          .text(": ")
          .append(std::move(right));
    } else {
      return Buffer()
          .append(std::move(cond))
          .text(" ? ")
          .append(std::move(left))
          .text(" : ")
          .append(std::move(right));
    }
  }

  // Since we will manually inject the braces anyways, ensure
  // that we format the block expression without them.
  auto as_raw_block = [&](Expression& expr) {
    if (expr.is<BlockExpr>()) {
      return format(
          *expr.as<BlockExpr>(), metadata, max_width - kIndentWidth, true);
    } else {
      return format(expr, metadata, max_width - kIndentWidth, true);
    }
  };

  auto* it = &if_expr;
  while (it != nullptr) {
    // Special case: comptime is bare for if expressions.
    auto cond = format(
        it->cond, metadata, max_width - 5, it->cond.is<Comptime>());
    auto expr = as_raw_block(it->left);
    total_width += cond.width() + 5;
    total_width += expr.width() + 3;
    if_pairs.emplace_back(std::move(cond), std::move(expr));
    if (it->right.is<IfExpr>()) {
      it = it->right.as<IfExpr>();
      continue;
    } else {
      if (!it->right.is<None>()) {
        final_else.emplace(as_raw_block(it->right));
      }
      break;
    }
  }

  // Is this a non-expression statement?
  auto buffer = Buffer();
  bool non_expr = (if_expr.left.is<BlockExpr>() &&
                   if_expr.left.as<BlockExpr>()->expr.is<None>()) ||
                  if_expr.right.is<None>();
  bool any_multiline = std::ranges::any_of(if_pairs, [&](auto& v) {
    return v.first.lines() > 1 || v.second.lines() > 1;
  });
  if (non_expr || total_width > max_width || if_pairs.size() > 1 ||
      any_multiline) {
    // Use the multi-line syntax for this.
    for (size_t i = 0; i < if_pairs.size(); i++) {
      buffer = buffer.text(i > 0 ? " else if " : "if ")
                   .append(std::move(if_pairs[i].first))
                   .text(" {")
                   .append(std::move(if_pairs[i].second), kIndentWidth)
                   .text("}");
    }
    if (final_else) {
      buffer = buffer.text(" else {")
                   .append(std::move(*final_else), kIndentWidth)
                   .text("}");
    }
    return buffer;
  }

  // Everything fits on a single line.
  for (size_t i = 0; i < if_pairs.size(); i++) {
    buffer = buffer.text(i > 0 ? " else if " : "if ")
                 .append(std::move(if_pairs[i].first))
                 .text(" { ")
                 .append(std::move(if_pairs[i].second))
                 .text(" }");
  }
  if (final_else) {
    buffer = buffer.text(" else { ").append(std::move(*final_else)).text(" }");
  }
  return buffer;
}

Buffer Formatter::visit(FieldAccess& acc)
{
  // Special case: allow chaining of field accesses. We never split on the
  // field access, although we may compress any other underlying expressions.
  bool bare = is_primitive(acc.expr) || acc.expr.is<FieldAccess>();
  auto expr = format(
      acc.expr, metadata, max_width - (acc.field.size() + 1), bare);
  return expr.text(".").text(acc.field);
}

Buffer Formatter::visit(ArrayAccess& arr)
{
  auto expr = format(arr.expr, metadata, max_width - 1);
  auto indexpr = format(arr.indexpr, metadata, max_width - kIndentWidth);
  if (expr.width() + indexpr.width() + 2 > max_width) {
    return Buffer()
        .append(std::move(expr))
        .text("[")
        .append(std::move(indexpr), kIndentWidth)
        .text("]");
  } else {
    return Buffer()
        .append(std::move(expr))
        .text("[")
        .append(std::move(indexpr))
        .text("]");
  }
}

Buffer Formatter::visit(TupleAccess& acc)
{
  auto n = std::to_string(acc.index);
  auto elems = format(acc.expr, metadata, max_width - (n.size() + 1));
  return Buffer().append(std::move(elems)).text(".").text(n);
}

Buffer Formatter::visit(MapAccess& acc)
{
  Buffer key;
  if (auto* tuple = acc.key.as<Tuple>()) {
    // We need to explicitly override the bare behavior for tuples,
    // because they will never be bare by default.
    key = format(*tuple, metadata, max_width - kIndentWidth, true);
  } else {
    // Use the default bare behavior, most primitives will be bare.
    key = format(acc.key, metadata, max_width - kIndentWidth);
  }
  if (acc.map->ident.size() + key.width() + 2 > max_width) {
    return Buffer()
        .text(acc.map->ident)
        .text("[")
        .append(std::move(key), kIndentWidth)
        .text("]");
  } else {
    return Buffer()
        .text(acc.map->ident)
        .text("[")
        .append(std::move(key))
        .text("]");
  }
}

Buffer Formatter::visit(Cast& cast)
{
  // Casts are never split; too confusing.
  auto buffer = Buffer()
                    .text("(")
                    .append(format(cast.typeof, metadata, max_width))
                    .text(")");
  size_t expr_width = max_width - buffer.width();
  return Buffer()
      .append(std::move(buffer))
      .append(format(cast.expr, metadata, expr_width));
}

Buffer Formatter::visit(Tuple& tuple)
{
  auto elems = format(tuple.elems, metadata, max_width - (bare ? 2 : 0));
  if (bare) {
    return elems;
  }
  if (elems.lines() > 1) {
    return Buffer().text("(").append(std::move(elems), kIndentWidth).text(")");
  } else {
    return Buffer().text("(").append(std::move(elems)).text(")");
  }
}

Buffer Formatter::visit(AssignScalarMapStatement& assignment)
{
  std::string ops;
  auto map = format(assignment.map, metadata, max_width);
  Buffer expr;

  // Is this a compound operator?
  auto* binop = assignment.expr.as<Binop>();
  if (binop && binop->left.is<Map>() &&
      *binop->left.as<Map>() == *assignment.map) {
    ops = opstr(*binop) + "=";
    expr = format(binop->right,
                  metadata,
                  max_width - (map.width() + 2 + ops.size()),
                  true);
  } else {
    ops = "=";
    expr = format(assignment.expr,
                  metadata,
                  max_width - (map.width() + 2 + ops.size()),
                  true);
  }

  return Buffer()
      .append(std::move(map))
      .text(" ")
      .text(ops)
      .text(" ")
      .append(std::move(expr))
      .text(";");
}

Buffer Formatter::visit(AssignMapStatement& assignment)
{
  std::string ops;
  auto map = format(assignment.map, metadata, max_width);
  Buffer expr;

  // Is this a compound operator?
  auto* binop = assignment.expr.as<Binop>();
  if (binop && binop->left.is<MapAccess>() &&
      *binop->left.as<MapAccess>()->map == *assignment.map) {
    ops = opstr(*binop) + "=";
    expr = format(binop->right,
                  metadata,
                  max_width - (map.width() + 2 + ops.size()),
                  true);
  } else {
    ops = "=";
    expr = format(assignment.expr,
                  metadata,
                  max_width - (map.width() + 2 + ops.size()),
                  true);
  }

  return Buffer()
      .append(std::move(map))
      .text(" ")
      .text(ops)
      .text(" ")
      .append(std::move(expr))
      .text(";");
}

Buffer Formatter::visit(AssignVarStatement& assignment)
{
  // N.B. if bare is set, then VarDeclStatement does not include ';'.
  auto var = format(assignment.var_decl, metadata, max_width, true);
  Buffer expr;

  // Is this a compound operator?
  std::string ops;
  auto* binop = assignment.expr.as<Binop>();
  if (binop && binop->left.is<Variable>() &&
      *binop->left.as<Variable>() == *assignment.var()) {
    ops = opstr(*binop) + "=";
    expr = format(binop->right,
                  metadata,
                  max_width - (var.width() + 2 + ops.size()),
                  true);
  } else {
    ops = "=";
    expr = format(assignment.expr,
                  metadata,
                  max_width - (var.width() + 2 + ops.size()),
                  true);
  }

  return Buffer()
      .append(std::move(var))
      .text(" ")
      .text(ops)
      .text(" ")
      .append(std::move(expr))
      .text(";");
}

Buffer Formatter::visit(AssignConfigVarStatement& assignment)
{
  return Buffer()
      .text(assignment.var)
      .text(" = ")
      .append(std::visit(
          [&](auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, bool>) {
              if (v) {
                return Buffer().text("true");
              } else {
                return Buffer().text("false");
              }
            } else if constexpr (std::is_same_v<T, uint64_t>) {
              return Buffer().text(std::to_string(v));
            } else if constexpr (std::is_same_v<T, std::string>) {
              // Prefer to use a naked identifier for the configuration,
              // it is rare that we need actual string paths.
              auto escaped = escape(v);
              if (escaped == v) {
                return Buffer().text(v);
              } else {
                return Buffer().text("\"" + escaped + "\"");
              }
            }
          },
          assignment.value))
      .text(";");
}

Buffer Formatter::visit(VarDeclStatement& decl)
{
  auto buffer = Buffer().text("let ").append(
      format(decl.var, metadata, max_width));
  if (decl.typeof) {
    buffer = buffer.text(" : ").append(
        format(decl.typeof, metadata, max_width));
  }
  if (bare) {
    return buffer;
  }
  return buffer.text(";");
}

Buffer Formatter::visit(Unroll& unroll)
{
  auto block = format(*unroll.block, metadata, max_width - 2);
  return Buffer()
      .text("unroll (")
      .append(format(unroll.expr, metadata, max_width - 11))
      .text(") {")
      .append(std::move(block), kIndentWidth)
      .text("}");
}

Buffer Formatter::visit(Range& range)
{
  Buffer start;
  if (range.start.is_literal() && mode != FormatMode::Debug) {
    start = format(range.start, metadata, max_width, true);
  } else {
    start = Buffer()
                .text("(")
                .append(format(range.start, metadata, max_width - 4, true))
                .text(")");
  }
  Buffer end;
  if (range.end.is_literal() && mode != FormatMode::Debug) {
    end = format(range.end, metadata, max_width, true);
  } else {
    end = Buffer()
              .text("(")
              .append(format(range.end, metadata, max_width - 4, true))
              .text(")");
  }
  // For simplicity, never split the range.
  return Buffer().append(std::move(start)).text("..").append(std::move(end));
}

Buffer Formatter::visit(For& for_loop)
{
  return Buffer()
      .text("for ")
      .append(format(for_loop.decl, metadata, max_width))
      .text(" : ")
      .append(format(for_loop.iterable, metadata, max_width))
      .text(" {")
      .append(format(*for_loop.block, metadata, max_width - kIndentWidth),
              kIndentWidth)
      .text("}");
}

Buffer Formatter::visit(Config& config)
{
  if (config.stmts.empty()) {
    return Buffer().text("config = {}");
  } else {
    return Buffer()
        .text("config = {")
        .append(format(config.stmts, metadata, max_width - kIndentWidth),
                kIndentWidth)
        .text("}");
  }
}

Buffer Formatter::visit(Jump& jump)
{
  switch (jump.ident) {
    case JumpType::RETURN:
      if (jump.return_value) {
        return Buffer()
            .text("return ")
            .append(format(*jump.return_value, metadata, true))
            .text(";");
      } else {
        return Buffer().text("return").text(";");
      }
    case JumpType::BREAK:
      return Buffer().text("break;");
    case JumpType::CONTINUE:
      return Buffer().text("continue;");
  }
  __builtin_unreachable();
}

Buffer Formatter::visit(AttachPoint& ap)
{
  // The attachpoints can unfortunately contain all kinds of weirdness, and
  // have a specialized lexer that is separate from the normal parser process.
  // This lexer is applied *after* expanding the provider, so we at least
  // normalize that. However, the best thing to do here is just emit the
  // original raw string, which should contain quotes and everything needed.
  return Buffer().text(ap.raw_input);
}

Buffer Formatter::visit(Probe& probe)
{
  // Emit all attachpoints with their respective comments. These are both
  // top-level statements and require a separator. If the user has them
  // specified inline, they will be preserved in that way.
  std::vector<Buffer> aps;
  size_t total_width = 0;
  for (size_t i = 0; i < probe.attach_points.size(); i++) {
    auto buffer = format(probe.attach_points[i],
                         metadata,
                         (i < probe.attach_points.size() - 1) ? max_width - 1
                                                              : max_width);
    if (i < probe.attach_points.size() - 1) {
      buffer = buffer.text(", ");
    }
    total_width += buffer.width();
    aps.emplace_back(std::move(buffer));
  }

  // Match the parsed predicate pattern, and format appropriately.
  MetadataIndex pred_metadata;
  MetadataIndex block_metadata;
  std::optional<Buffer> pred;
  Buffer block;
  auto* if_expr = probe.block->expr.as<IfExpr>();
  if (if_expr && probe.block->stmts.empty() && if_expr->left.is<BlockExpr>() &&
      if_expr->right.is<None>()) {
    auto* block_expr = if_expr->left.as<BlockExpr>();
    pred_metadata = metadata.before(if_expr->cond.node().loc->current.begin);
    pred.emplace(format(if_expr->cond, metadata, max_width, true));
    total_width += pred->width();
    block_metadata = metadata.before(block_expr->loc->current.begin);
    block = format(*block_expr, metadata, max_width - 2);
  } else {
    block_metadata = metadata.before(probe.block->loc->current.begin);
    block = format(*probe.block, metadata, max_width - 2);
  }

  auto buffer = Buffer();
  if (total_width + 2 > max_width) {
    for (auto& buf : aps) {
      buffer = buffer.append(std::move(buf)).line_break();
    }
    if (pred) {
      // The predicate appears on the same line as the brace for the probe.
      buffer = buffer.metadata(pred_metadata)
                   .text("/")
                   .append(std::move(*pred))
                   .text("/ ");
    }
    buffer = buffer.metadata(block_metadata)
                 .text("{")
                 .append(std::move(block), kIndentWidth)
                 .text("}");
  } else {
    for (auto& buf : aps) {
      buffer = buffer.append(std::move(buf));
    }
    if (pred) {
      // N.B. Need extra spacing here for the probe.
      buffer = buffer.metadata(pred_metadata)
                   .text(" /")
                   .append(std::move(*pred))
                   .text("/");
    }
    buffer = buffer.metadata(block_metadata)
                 .text(" {")
                 .append(std::move(block), kIndentWidth)
                 .text("}");
  }
  return buffer;
}

Buffer Formatter::visit(SubprogArg& arg)
{
  return Buffer()
      .text(arg.var->ident)
      .text(" : ")
      .append(format(arg.typeof,
                     metadata,
                     max_width - (arg.var->ident.size() + 3)));
}

Buffer Formatter::visit(Subprog& subprog)
{
  auto block_metadata = metadata.before(subprog.block->loc->current.begin);
  return Buffer()
      .text("fn ")
      .text(subprog.name)
      .text("(")
      .append(
          format(subprog.args, metadata, max_width - (subprog.name.size() + 5)))
      .text(") : ")
      .append(format(subprog.return_type, metadata, max_width))
      .text(" ")
      .metadata(block_metadata)
      .text("{")
      .append(format(subprog.block, metadata, max_width - kIndentWidth),
              kIndentWidth)
      .text("}");
}

Buffer Formatter::visit(Import& imp)
{
  return Buffer().text("import \"").text(imp.name).text("\";");
}

Buffer Formatter::visit(BlockExpr& block)
{
  // Blocks must be handled special, either when they are known
  // (e.g. there is a direct BlockExpr pointer), or when they are
  // generic expressions (see handling in Expression& formatter).
  auto buffer = Buffer();
  for (size_t i = 0; i < block.stmts.size(); i++) {
    auto stmt_buffer = format(block.stmts[i], metadata, max_width);
    if (stmt_buffer.width() > 0 && i > 0) {
      buffer = buffer.line_break();
    }
    buffer = buffer.append(std::move(stmt_buffer));
  }

  // If there is an expression, we tack it on.
  auto extra_metadata = metadata.before(block.loc->current.end);
  if (!block.expr.is<None>()) {
    // Since this expression appears in a block, we can pull any expression
    // related comments forward and print them as multiline comments.
    auto expr_metadata = extra_metadata.before(
        block.expr.node().loc->current.begin);
    auto expr = format(block.expr, extra_metadata, max_width, true);
    // Join the rest of remaining metadata.
    buffer = buffer.metadata(expr_metadata, buffer.lines() > 0 ? 1 : 0);
    buffer = buffer.append(std::move(expr));
    // There's already vspace built-in to the expression, so we just print
    // any trailing comment without additional vspace.
    return buffer.metadata(extra_metadata);
  } else {
    // If there's anything left in the metadata, we need to add it. These are
    // effectively trailing comments in the block, potentially with vspace.
    return buffer.metadata(extra_metadata);
  }
}

Buffer Formatter::visit(Comptime& comptime)
{
  auto expr = format(comptime.expr, metadata, max_width - 9);
  return Buffer().text("comptime ").append(std::move(expr));
}

Buffer Formatter::visit(RootStatement& root)
{
  // Pull out all comments ahead of the block itself.
  auto comments = metadata.before(root.node().loc->current.begin);
  auto buffer = format(root.value, metadata, max_width);
  return Buffer().metadata(comments, 0).append(std::move(buffer)).line_break();
}

Buffer Formatter::visit(Program& program)
{
  auto buffer = Buffer();

  if (program.header && !program.header->empty()) {
    buffer = buffer.text(*program.header).line_break();
  }

  // We preserve the order of all the top-level statements. By using
  // this map, we will iterate through them in order. The parser can
  // support strict ordering if it likes, but for printing we want to
  // ensure that we are respecting the original source order.
  std::map<SourceLocation, RootStatement> top_level;

  if (program.config != nullptr) {
    top_level.emplace(program.config->loc->current, program.config);
  }
  for (auto* import : program.imports) {
    top_level.emplace(import->loc->current, import);
  }
  for (auto* cstmt : program.c_statements) {
    top_level.emplace(cstmt->loc->current, cstmt);
  }
  for (auto* map_decl : program.map_decls) {
    top_level.emplace(map_decl->loc->current, map_decl);
  }
  for (auto* macro : program.macros) {
    top_level.emplace(macro->loc->current, macro);
  }
  for (auto* function : program.functions) {
    top_level.emplace(function->loc->current, function);
  }
  for (auto* probe : program.probes) {
    top_level.emplace(probe->loc->current, probe);
  }

  for (auto& [_, entry] : top_level) {
    // Extract the full metadata, and then format the buffer with that
    // metadata. Anything left is the preceeding comment, and will be
    // printed first to the buffer.
    auto pre_metadata = metadata.before(entry.node().loc->current.begin);
    auto local_buffer = format(entry, metadata, max_width);
    buffer = buffer.metadata(std::move(pre_metadata), 0)
                 .append(std::move(local_buffer));
  }

  // It's possible that there are trailing comments, not associated with any
  // macros, probes or functions. Include these at the end, where they were.
  buffer = buffer.metadata(std::move(metadata), 0);
  return buffer;
}

Buffer Formatter::visit(Macro& macro)
{
  auto args = format(macro.vargs, metadata, max_width - 10);
  auto block_metadata = metadata.before(macro.block->loc->current.begin);
  auto block = format(*macro.block, metadata, max_width - kIndentWidth);
  return Buffer()
      .text("macro ")
      .text(macro.name)
      .text("(")
      .append(std::move(args))
      .text(") ")
      .metadata(block_metadata)
      .text("{")
      .append(std::move(block), kIndentWidth)
      .text("}");
}

Buffer Formatter::visit(Statement& stmt)
{
  // Special case: do nothing for no-op statements. This is because the
  // none expression will print nothing, and we always end the statement
  // with a line break, which we don't want to happen in that case.
  if (stmt.is<ExprStatement>() && stmt.as<ExprStatement>()->expr.is<None>()) {
    return {};
  }
  // Pull out any leading comments for the statement and make them block
  // comments. Otherwise they will end up as inline comments.
  auto comments = metadata.before(stmt.loc()->current.begin);
  auto buffer = format(stmt.value, metadata, max_width);
  return Buffer().metadata(comments, 0).append(std::move(buffer));
}

Buffer Formatter::visit(While& while_block)
{
  auto cond = format(while_block.cond, metadata, max_width - 8);
  auto block = format(*while_block.block, metadata, max_width - 2);
  return Buffer()
      .text("while ")
      .append(std::move(cond))
      .text(" {")
      .append(std::move(block), kIndentWidth)
      .text("}");
}

Buffer Formatter::visit(ExprStatement& expr)
{
  auto buffer = format(expr.expr, metadata, max_width, true);
  if (!expr.expr.is<IfExpr>() && !expr.expr.is<BlockExpr>()) {
    return buffer.text(";");
  } else {
    return buffer;
  }
}

Buffer Formatter::visit(Expression& expr)
{
  auto local_metadata = metadata.before(expr.node().loc->current.end);
  // Note that tuples may only be bare in map access keys.
  bool bare_okay = (bare && !expr.is<Tuple>()) ||
                   (is_primitive(expr) && mode != FormatMode::Debug);
  size_t local_width = max_width - (bare_okay ? 0 : 2);
  Buffer buffer;
  if (!bare_okay) {
    buffer = buffer.text("(");
  }
  if (expr.is<BlockExpr>()) {
    // For a block expression, we determine whether this can be
    // suitable represented as a single line or whether this needs
    // to be split into its own scope with multiple lines.
    auto block = format(
        *expr.as<BlockExpr>(), local_metadata, max_width - 2, true);
    if (block.lines() > 1 || block.width() > local_width) {
      buffer =
          buffer.text("{").append(std::move(block), kIndentWidth).text("}");
    } else {
      buffer = buffer.text("{ ").append(std::move(block)).text(" }");
    }
  } else {
    // For other expressions, we determine if we can represent these
    // unambiguously without parentheses, otherwise they are added.
    buffer = buffer.append(
        format(expr.value, local_metadata, local_width, true));
  }
  if (mode == FormatMode::Debug) {
    // Don't count this in the width; it's debug mode.
    buffer = buffer.comment(typestr(expr.type()));
  }
  if (bare_okay) {
    return buffer;
  }
  return buffer.text(")");
}

Buffer Formatter::visit(const SizedType& type)
{
  return Buffer().text(typestr(type));
}

} // namespace bpftrace::ast
