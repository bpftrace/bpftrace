#include <algorithm>
#include <utility>

#include "ast/ast.h"
#include "ast/context.h"
#include "log.h"
#include "util/format.h"

namespace bpftrace::ast {

Diagnostic &Node::addError() const
{
  return ctx_.diagnostics_->addError(loc);
}

Diagnostic &Node::addWarning() const
{
  return ctx_.diagnostics_->addWarning(loc);
}

static constexpr std::string_view ENUM = "enum ";

Integer::Integer(ASTContext &ctx, int64_t n, Location &&loc)
    : Expression(ctx, std::move(loc)), value(n)
{
}

NegativeInteger::NegativeInteger(ASTContext &ctx, int64_t n, Location &&loc)
    : Expression(ctx, std::move(loc)), value(n)
{
}

String::String(ASTContext &ctx, std::string str, Location &&loc)
    : Expression(ctx, std::move(loc)), value(std::move(str))
{
}

Builtin::Builtin(ASTContext &ctx, std::string ident, Location &&loc)
    : Expression(ctx, std::move(loc)), ident(std::move(ident))
{
}

Identifier::Identifier(ASTContext &ctx, std::string ident, Location &&loc)
    : Expression(ctx, std::move(loc)), ident(std::move(ident))
{
}

PositionalParameter::PositionalParameter(ASTContext &ctx,
                                         long n,
                                         Location &&loc)
    : Expression(ctx, std::move(loc)), n(n)
{
}

PositionalParameterCount::PositionalParameterCount(ASTContext &ctx,
                                                   Location &&loc)
    : Expression(ctx, std::move(loc))
{
}

Call::Call(ASTContext &ctx, std::string func, Location &&loc)
    : Expression(ctx, std::move(loc)), func(std::move(func))
{
}

Call::Call(ASTContext &ctx,
           std::string func,
           ExpressionList &&vargs,
           Location &&loc)
    : Expression(ctx, std::move(loc)),
      func(std::move(func)),
      vargs(std::move(vargs))
{
}

Sizeof::Sizeof(ASTContext &ctx, SizedType type, Location &&loc)
    : Expression(ctx, std::move(loc)), argtype(std::move(type))
{
}

Sizeof::Sizeof(ASTContext &ctx, Expression *expr, Location &&loc)
    : Expression(ctx, std::move(loc)), expr(expr)
{
}

Offsetof::Offsetof(ASTContext &ctx,
                   SizedType record,
                   std::vector<std::string> &field,
                   Location &&loc)
    : Expression(ctx, std::move(loc)), record(std::move(record)), field(field)
{
}

Offsetof::Offsetof(ASTContext &ctx,
                   Expression *expr,
                   std::vector<std::string> &field,
                   Location &&loc)
    : Expression(ctx, std::move(loc)), expr(expr), field(field)
{
}

MapDeclStatement::MapDeclStatement(ASTContext &ctx,
                                   std::string ident,
                                   std::string bpf_type,
                                   int max_entries,
                                   Location &&loc)
    : Node(ctx, std::move(loc)),
      ident(std::move(ident)),
      bpf_type(std::move(bpf_type)),
      max_entries(max_entries)
{
}

Map::Map(ASTContext &ctx,
         std::string ident,
         Expression *key_expr,
         Location &&loc)
    : Expression(ctx, std::move(loc)),
      ident(std::move(ident)),
      key_expr(key_expr)
{
  if (key_expr) {
    key_expr->key_for_map = this;
  }
}

Variable::Variable(ASTContext &ctx, std::string ident, Location &&loc)
    : Expression(ctx, std::move(loc)), ident(std::move(ident))
{
}

Binop::Binop(ASTContext &ctx,
             Expression *left,
             Operator op,
             Expression *right,
             Location &&loc)
    : Expression(ctx, std::move(loc)), left(left), right(right), op(op)
{
}

Unop::Unop(ASTContext &ctx,
           Operator op,
           Expression *expr,
           bool is_post_op,
           Location &&loc)
    : Expression(ctx, std::move(loc)),
      expr(expr),
      op(op),
      is_post_op(is_post_op)
{
}

Ternary::Ternary(ASTContext &ctx,
                 Expression *cond,
                 Expression *left,
                 Expression *right,
                 Location &&loc)
    : Expression(ctx, std::move(loc)), cond(cond), left(left), right(right)
{
}

FieldAccess::FieldAccess(ASTContext &ctx,
                         Expression *expr,
                         std::string field,
                         Location &&loc)
    : Expression(ctx, std::move(loc)), expr(expr), field(std::move(field))
{
}

ArrayAccess::ArrayAccess(ASTContext &ctx,
                         Expression *expr,
                         Expression *indexpr,
                         Location &&loc)
    : Expression(ctx, std::move(loc)), expr(expr), indexpr(indexpr)
{
}

TupleAccess::TupleAccess(ASTContext &ctx,
                         Expression *expr,
                         ssize_t index,
                         Location &&loc)
    : Expression(ctx, std::move(loc)), expr(expr), index(index)
{
}

Cast::Cast(ASTContext &ctx,
           SizedType cast_type,
           Expression *expr,
           Location &&loc)
    : Expression(ctx, std::move(loc)), expr(expr)
{
  type = cast_type;
}

Tuple::Tuple(ASTContext &ctx, ExpressionList &&elems, Location &&loc)
    : Expression(ctx, std::move(loc)), elems(std::move(elems))
{
}

ExprStatement::ExprStatement(ASTContext &ctx, Expression *expr, Location &&loc)
    : Statement(ctx, std::move(loc)), expr(expr)
{
}

AssignMapStatement::AssignMapStatement(ASTContext &ctx,
                                       Map *map,
                                       Expression *expr,
                                       Location &&loc)
    : Statement(ctx, std::move(loc)), map(map), expr(expr)
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

AssignVarStatement::AssignVarStatement(ASTContext &ctx,
                                       Variable *var,
                                       Expression *expr,
                                       Location &&loc)
    : Statement(ctx, std::move(loc)), var(var), expr(expr)
{
  expr->var = var;
}

AssignVarStatement::AssignVarStatement(ASTContext &ctx,
                                       VarDeclStatement *var_decl_stmt,
                                       Expression *expr,
                                       Location &&loc)
    : Statement(ctx, std::move(loc)),
      var_decl_stmt(var_decl_stmt),
      var(var_decl_stmt->var),
      expr(expr)
{
  expr->var = var;
}

AssignConfigVarStatement::AssignConfigVarStatement(ASTContext &ctx,
                                                   std::string var,
                                                   uint64_t value,
                                                   Location &&loc)
    : Node(ctx, std::move(loc)), var(std::move(var)), value(std::move(value))
{
}

AssignConfigVarStatement::AssignConfigVarStatement(ASTContext &ctx,
                                                   std::string var,
                                                   std::string value,
                                                   Location &&loc)
    : Node(ctx, std::move(loc)), var(std::move(var)), value(std::move(value))
{
}

VarDeclStatement::VarDeclStatement(ASTContext &ctx,
                                   Variable *var,
                                   SizedType type,
                                   Location &&loc)
    : Statement(ctx, std::move(loc)), var(var), set_type(true)
{
  var->type = std::move(type);
}

VarDeclStatement::VarDeclStatement(ASTContext &ctx,
                                   Variable *var,
                                   Location &&loc)
    : Statement(ctx, std::move(loc)), var(var)
{
  var->type = CreateNone();
}

Predicate::Predicate(ASTContext &ctx, Expression *expr, Location &&loc)
    : Node(ctx, std::move(loc)), expr(expr)
{
}

AttachPoint::AttachPoint(ASTContext &ctx,
                         std::string raw_input,
                         bool ignore_invalid,
                         Location &&loc)
    : Node(ctx, std::move(loc)),
      raw_input(std::move(raw_input)),
      ignore_invalid(ignore_invalid)
{
}

Block::Block(ASTContext &ctx, StatementList &&stmts, Location &&loc)
    : Expression(ctx, std::move(loc)), stmts(std::move(stmts))
{
}

Block::Block(ASTContext &ctx,
             StatementList &&stmts,
             Expression *expr,
             Location &&loc)
    : Expression(ctx, std::move(loc)), stmts(std::move(stmts)), expr(expr)
{
}

If::If(ASTContext &ctx,
       Expression *cond,
       Block *if_block,
       Block *else_block,
       Location &&loc)
    : Statement(ctx, std::move(loc)),
      cond(cond),
      if_block(if_block),
      else_block(else_block)
{
}

Unroll::Unroll(ASTContext &ctx, Expression *expr, Block *block, Location &&loc)
    : Statement(ctx, std::move(loc)), expr(expr), block(block)
{
}

Probe::Probe(ASTContext &ctx,
             AttachPointList &&attach_points,
             Predicate *pred,
             Block *block,
             Location &&loc)
    : Node(ctx, std::move(loc)),
      attach_points(std::move(attach_points)),
      pred(pred),
      block(block)
{
}

SubprogArg::SubprogArg(ASTContext &ctx,
                       std::string name,
                       SizedType type,
                       Location &&loc)
    : Node(ctx, std::move(loc)), type(std::move(type)), name_(std::move(name))
{
}

std::string SubprogArg::name() const
{
  return name_;
}

Subprog::Subprog(ASTContext &ctx,
                 std::string name,
                 SizedType return_type,
                 SubprogArgList &&args,
                 StatementList &&stmts,
                 Location &&loc)
    : Node(ctx, std::move(loc)),
      args(std::move(args)),
      return_type(std::move(return_type)),
      stmts(std::move(stmts)),
      name_(std::move(name))
{
}

Import::Import(ASTContext &ctx, std::string name, Location &&loc)
    : Node(ctx, std::move(loc)), name_(std::move(name))
{
}

Program::Program(ASTContext &ctx,
                 std::string c_definitions,
                 Config *config,
                 ImportList &&imports,
                 MapDeclList &&map_decls,
                 SubprogList &&functions,
                 ProbeList &&probes,
                 Location &&loc)
    : Node(ctx, std::move(loc)),
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
