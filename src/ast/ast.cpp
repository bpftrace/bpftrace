#include "ast/ast.h"

#include <algorithm>
#include <utility>

#include "ast/context.h"
#include "log.h"
#include "util/format.h"

namespace bpftrace::ast {

static constexpr std::string_view ENUM = "enum ";

Integer::Integer(Diagnostics &d, int64_t n, Location &&loc, bool is_negative)
    : Expression(d, std::move(loc)), n(n), is_negative(is_negative)
{
  is_literal = true;
}

String::String(Diagnostics &d, std::string str, Location &&loc)
    : Expression(d, std::move(loc)), str(std::move(str))
{
  is_literal = true;
}

StackMode::StackMode(Diagnostics &d, std::string mode, Location &&loc)
    : Expression(d, std::move(loc)), mode(std::move(mode))
{
  is_literal = true;
}

Builtin::Builtin(Diagnostics &d, std::string ident, Location &&loc)
    : Expression(d, std::move(loc)), ident(std::move(ident))
{
}

Identifier::Identifier(Diagnostics &d, std::string ident, Location &&loc)
    : Expression(d, std::move(loc)), ident(std::move(ident))
{
}

PositionalParameter::PositionalParameter(Diagnostics &d, long n, Location &&loc)
    : Expression(d, std::move(loc)), n(n)
{
  is_literal = true;
}

PositionalParameterCount::PositionalParameterCount(Diagnostics &d,
                                                   Location &&loc)
    : Expression(d, std::move(loc))
{
  is_literal = true;
}

Call::Call(Diagnostics &d, std::string func, Location &&loc)
    : Expression(d, std::move(loc)), func(std::move(func))
{
}

Call::Call(Diagnostics &d,
           std::string func,
           ExpressionList &&vargs,
           Location &&loc)
    : Expression(d, std::move(loc)),
      func(std::move(func)),
      vargs(std::move(vargs))
{
}

Sizeof::Sizeof(Diagnostics &d, SizedType type, Location &&loc)
    : Expression(d, std::move(loc)), argtype(std::move(type))
{
}

Sizeof::Sizeof(Diagnostics &d, Expression *expr, Location &&loc)
    : Expression(d, std::move(loc)), expr(expr)
{
}

Offsetof::Offsetof(Diagnostics &d,
                   SizedType record,
                   std::vector<std::string> &field,
                   Location &&loc)
    : Expression(d, std::move(loc)), record(std::move(record)), field(field)
{
}

Offsetof::Offsetof(Diagnostics &d,
                   Expression *expr,
                   std::vector<std::string> &field,
                   Location &&loc)
    : Expression(d, std::move(loc)), expr(expr), field(field)
{
}

MapDeclStatement::MapDeclStatement(Diagnostics &d,
                                   std::string ident,
                                   std::string bpf_type,
                                   int max_entries,
                                   Location &&loc)
    : Node(d, std::move(loc)),
      ident(std::move(ident)),
      bpf_type(std::move(bpf_type)),
      max_entries(max_entries)
{
}

Map::Map(Diagnostics &d, std::string ident, Location &&loc)
    : Expression(d, std::move(loc)), ident(std::move(ident))
{
  is_map = true;
}

Map::Map(Diagnostics &d, std::string ident, Expression &expr, Location &&loc)
    : Expression(d, std::move(loc)), ident(std::move(ident)), key_expr(&expr)
{
  is_map = true;
  key_expr->key_for_map = this;
}

Variable::Variable(Diagnostics &d, std::string ident, Location &&loc)
    : Expression(d, std::move(loc)), ident(std::move(ident))
{
  is_variable = true;
}

Binop::Binop(Diagnostics &d,
             Expression *left,
             Operator op,
             Expression *right,
             Location &&loc)
    : Expression(d, std::move(loc)), left(left), right(right), op(op)
{
}

Unop::Unop(Diagnostics &d,
           Operator op,
           Expression *expr,
           bool is_post_op,
           Location &&loc)
    : Expression(d, std::move(loc)), expr(expr), op(op), is_post_op(is_post_op)
{
}

Ternary::Ternary(Diagnostics &d,
                 Expression *cond,
                 Expression *left,
                 Expression *right,
                 Location &&loc)
    : Expression(d, std::move(loc)), cond(cond), left(left), right(right)
{
}

FieldAccess::FieldAccess(Diagnostics &d,
                         Expression *expr,
                         std::string field,
                         Location &&loc)
    : Expression(d, std::move(loc)), expr(expr), field(std::move(field))
{
}

ArrayAccess::ArrayAccess(Diagnostics &d,
                         Expression *expr,
                         Expression *indexpr,
                         Location &&loc)
    : Expression(d, std::move(loc)), expr(expr), indexpr(indexpr)
{
}

TupleAccess::TupleAccess(Diagnostics &d,
                         Expression *expr,
                         ssize_t index,
                         Location &&loc)
    : Expression(d, std::move(loc)), expr(expr), index(index)
{
}

Cast::Cast(Diagnostics &d,
           SizedType cast_type,
           Expression *expr,
           Location &&loc)
    : Expression(d, std::move(loc)), expr(expr)
{
  type = cast_type;
}

Tuple::Tuple(Diagnostics &d, ExpressionList &&elems, Location &&loc)
    : Expression(d, std::move(loc)), elems(std::move(elems))
{
}

ExprStatement::ExprStatement(Diagnostics &d, Expression *expr, Location &&loc)
    : Statement(d, std::move(loc)), expr(expr)
{
}

AssignMapStatement::AssignMapStatement(Diagnostics &d,
                                       Map *map,
                                       Expression *expr,
                                       Location &&loc)
    : Statement(d, std::move(loc)), map(map), expr(expr)
{
  // If this is a block expression, then we skip through that and actually set
  // the map on the underlying expression. This is done recursively. It is only
  // done to support functions that need to know the type of the map to which
  // they are being assigned.
  Expression *value = expr;
  while (true) {
    auto *block = dynamic_cast<Block *>(value);
    if (block == nullptr) {
      break;
    }
    value = block->expr; // Must be non-null if expression.
  };
  value->map = map;
};

AssignVarStatement::AssignVarStatement(Diagnostics &d,
                                       Variable *var,
                                       Expression *expr,
                                       Location &&loc)
    : Statement(d, std::move(loc)), var(var), expr(expr)
{
  expr->var = var;
}

AssignVarStatement::AssignVarStatement(Diagnostics &d,
                                       VarDeclStatement *var_decl_stmt,
                                       Expression *expr,
                                       Location &&loc)
    : Statement(d, std::move(loc)),
      var_decl_stmt(var_decl_stmt),
      var(var_decl_stmt->var),
      expr(expr)
{
  expr->var = var;
}

AssignConfigVarStatement::AssignConfigVarStatement(Diagnostics &d,
                                                   Identifier *config_var,
                                                   Expression *expr,
                                                   Location &&loc)
    : Statement(d, std::move(loc)), config_var(config_var), expr(expr)
{
}

VarDeclStatement::VarDeclStatement(Diagnostics &d,
                                   Variable *var,
                                   SizedType type,
                                   Location &&loc)
    : Statement(d, std::move(loc)), var(var), set_type(true)
{
  var->type = std::move(type);
}

VarDeclStatement::VarDeclStatement(Diagnostics &d,
                                   Variable *var,
                                   Location &&loc)
    : Statement(d, std::move(loc)), var(var)
{
  var->type = CreateNone();
}

Predicate::Predicate(Diagnostics &d, Expression *expr, Location &&loc)
    : Node(d, std::move(loc)), expr(expr)
{
}

AttachPoint::AttachPoint(Diagnostics &d,
                         std::string raw_input,
                         bool ignore_invalid,
                         Location &&loc)
    : Node(d, std::move(loc)),
      raw_input(std::move(raw_input)),
      ignore_invalid(ignore_invalid)
{
}

Block::Block(Diagnostics &d, StatementList &&stmts, Location &&loc)
    : Expression(d, std::move(loc)), stmts(std::move(stmts))
{
}

Block::Block(Diagnostics &d,
             StatementList &&stmts,
             Expression *expr,
             Location &&loc)
    : Expression(d, std::move(loc)), stmts(std::move(stmts)), expr(expr)
{
}

If::If(Diagnostics &d,
       Expression *cond,
       Block *if_block,
       Block *else_block,
       Location &&loc)
    : Statement(d, std::move(loc)),
      cond(cond),
      if_block(if_block),
      else_block(else_block)
{
}

Unroll::Unroll(Diagnostics &d, Expression *expr, Block *block, Location &&loc)
    : Statement(d, std::move(loc)), expr(expr), block(block)
{
}

Probe::Probe(Diagnostics &d,
             AttachPointList &&attach_points,
             Predicate *pred,
             Block *block,
             Location &&loc)
    : Node(d, std::move(loc)),
      attach_points(std::move(attach_points)),
      pred(pred),
      block(block)
{
}

SubprogArg::SubprogArg(Diagnostics &d,
                       std::string name,
                       SizedType type,
                       Location &&loc)
    : Node(d, std::move(loc)), type(std::move(type)), name_(std::move(name))
{
}

std::string SubprogArg::name() const
{
  return name_;
}

Subprog::Subprog(Diagnostics &d,
                 std::string name,
                 SizedType return_type,
                 SubprogArgList &&args,
                 StatementList &&stmts,
                 Location &&loc)
    : Node(d, std::move(loc)),
      args(std::move(args)),
      return_type(std::move(return_type)),
      stmts(std::move(stmts)),
      name_(std::move(name))
{
}

Import::Import(Diagnostics &d, std::string name, Location &&loc)
    : Node(d, std::move(loc)), name_(std::move(name))
{
}

Program::Program(Diagnostics &d,
                 std::string c_definitions,
                 Config *config,
                 ImportList &&imports,
                 MapDeclList &&map_decls,
                 SubprogList &&functions,
                 ProbeList &&probes,
                 Location &&loc)
    : Node(d, std::move(loc)),
      c_definitions(std::move(c_definitions)),
      config(config),
      imports(std::move(imports)),
      functions(std::move(functions)),
      probes(std::move(probes)),
      map_decls(std::move(map_decls))
{
}

std::string opstr(const Jump &jump)
{
  switch (jump.ident) {
    case JumpType::RETURN:
      return "return";
    case JumpType::BREAK:
      return "break";
    case JumpType::CONTINUE:
      return "continue";
    default:
      return {};
  }

  return {}; // unreached
}

std::string opstr(const Binop &binop)
{
  switch (binop.op) {
    case Operator::EQ:
      return "==";
    case Operator::NE:
      return "!=";
    case Operator::LE:
      return "<=";
    case Operator::GE:
      return ">=";
    case Operator::LT:
      return "<";
    case Operator::GT:
      return ">";
    case Operator::LAND:
      return "&&";
    case Operator::LOR:
      return "||";
    case Operator::LEFT:
      return "<<";
    case Operator::RIGHT:
      return ">>";
    case Operator::PLUS:
      return "+";
    case Operator::MINUS:
      return "-";
    case Operator::MUL:
      return "*";
    case Operator::DIV:
      return "/";
    case Operator::MOD:
      return "%";
    case Operator::BAND:
      return "&";
    case Operator::BOR:
      return "|";
    case Operator::BXOR:
      return "^";
    default:
      return {};
  }

  return {}; // unreached
}

std::string opstr(const Unop &unop)
{
  switch (unop.op) {
    case Operator::LNOT:
      return "!";
    case Operator::BNOT:
      return "~";
    case Operator::MINUS:
      return "-";
    case Operator::MUL:
      return "dereference";
    case Operator::INCREMENT:
      if (unop.is_post_op)
        return "++ (post)";
      return "++ (pre)";
    case Operator::DECREMENT:
      if (unop.is_post_op)
        return "-- (post)";
      return "-- (pre)";
    default:
      return {};
  }

  return {}; // unreached
}

AttachPoint &AttachPoint::create_expansion_copy(ASTContext &ctx,
                                                const std::string &match) const
{
  // Create a new node with the same raw tracepoint. We initialize all the
  // information about the attach point, and then override/reset values
  // depending on the specific probe type.
  auto &ap = *ctx.make_node<AttachPoint>(raw_input,
                                         ignore_invalid,
                                         Location(loc));
  ap.index_ = index_;
  ap.provider = provider;
  ap.target = target;
  ap.lang = lang;
  ap.ns = ns;
  ap.func = func;
  ap.pin = pin;
  ap.usdt = usdt;
  ap.freq = freq;
  ap.len = len;
  ap.mode = mode;
  ap.async = async;
  ap.expansion = expansion;
  ap.address = address;
  ap.func_offset = func_offset;

  switch (probetype(ap.provider)) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      ap.func = match;
      if (match.find(":") != std::string::npos)
        ap.target = util::erase_prefix(ap.func);
      break;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::tracepoint:
    case ProbeType::rawtracepoint:
      // Tracepoint, raw tracepoint, uprobe, and fentry/fexit probes specify
      // both a target (category for tracepoints, binary for uprobes, and
      // kernel module for fentry/fexit and a function name.
      ap.func = match;
      ap.target = util::erase_prefix(ap.func);
      break;
    case ProbeType::usdt:
      // USDT probes specify a target binary path, a provider, and a function
      // name.
      ap.func = match;
      ap.target = util::erase_prefix(ap.func);
      ap.ns = util::erase_prefix(ap.func);
      break;
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
      // Watchpoint probes come with target prefix. Strip the target to get the
      // function
      ap.func = match;
      util::erase_prefix(ap.func);
      break;
    case ProbeType::software:
    case ProbeType::hardware:
    case ProbeType::interval:
    case ProbeType::profile:
    case ProbeType::special:
    case ProbeType::iter:
    case ProbeType::invalid:
      break;
    default:
      LOG(BUG) << "Unknown probe type";
  }
  return ap;
}

std::string AttachPoint::name() const
{
  std::string n = provider;
  if (!target.empty())
    n += ":" + target;
  if (!lang.empty())
    n += ":" + lang;
  if (!ns.empty())
    n += ":" + ns;
  if (!func.empty()) {
    n += ":" + func;
    if (func_offset != 0)
      n += "+" + std::to_string(func_offset);
  }
  if (address != 0)
    n += ":" + std::to_string(address);
  if (freq != 0)
    n += ":" + std::to_string(freq);
  if (len != 0)
    n += ":" + std::to_string(len);
  if (!mode.empty())
    n += ":" + mode;
  return n;
}

int AttachPoint::index() const
{
  return index_;
}

void AttachPoint::set_index(int index)
{
  index_ = index;
}

std::string Probe::name() const
{
  std::vector<std::string> ap_names;
  std::ranges::transform(attach_points,

                         std::back_inserter(ap_names),
                         [](const AttachPoint *ap) { return ap->name(); });
  return util::str_join(ap_names, ",");
}

std::string Probe::args_typename() const
{
  return "struct " + name() + "_args";
}

int Probe::index() const
{
  return index_;
}

void Probe::set_index(int index)
{
  index_ = index;
}

std::string Subprog::name() const
{
  return name_;
}

bool Probe::has_ap_of_probetype(ProbeType probe_type)
{
  return std::ranges::any_of(attach_points, [probe_type](auto *ap) {
    return probetype(ap->provider) == probe_type;
  });
}

SizedType ident_to_record(const std::string &ident, int pointer_level)
{
  SizedType result = CreateRecord(ident);
  for (int i = 0; i < pointer_level; i++)
    result = CreatePointer(result);
  return result;
}

SizedType ident_to_sized_type(const std::string &ident)
{
  if (ident.starts_with(ENUM)) {
    auto enum_name = ident.substr(ENUM.size());
    // This is an automatic promotion to a uint64
    // even though it's possible that highest variant value of that enum
    // fits into a smaller int. This will also affect casts from a smaller
    // int and cause an ERROR: Integer size mismatch.
    // This could potentially be revisited or the cast relaxed
    // if we check the variant values during semantic analysis.
    return CreateEnum(64, enum_name);
  }
  return ident_to_record(ident);
}

} // namespace bpftrace::ast
