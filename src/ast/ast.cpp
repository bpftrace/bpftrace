#include "ast/ast.h"

#include <algorithm>

#include "ast/visitors.h"
#include "log.h"

namespace bpftrace {
namespace ast {

#define MAKE_ACCEPT(Ty)                                                        \
  void Ty::accept(VisitorBase &v)                                              \
  {                                                                            \
    v.visit(*this);                                                            \
  };

MAKE_ACCEPT(Integer)
MAKE_ACCEPT(String)
MAKE_ACCEPT(StackMode)
MAKE_ACCEPT(Builtin)
MAKE_ACCEPT(Identifier)
MAKE_ACCEPT(PositionalParameter)
MAKE_ACCEPT(Call)
MAKE_ACCEPT(Sizeof)
MAKE_ACCEPT(Offsetof)
MAKE_ACCEPT(Map)
MAKE_ACCEPT(Variable)
MAKE_ACCEPT(Binop)
MAKE_ACCEPT(Unop)
MAKE_ACCEPT(Ternary)
MAKE_ACCEPT(FieldAccess)
MAKE_ACCEPT(ArrayAccess)
MAKE_ACCEPT(Cast)
MAKE_ACCEPT(Tuple)
MAKE_ACCEPT(ExprStatement)
MAKE_ACCEPT(AssignMapStatement)
MAKE_ACCEPT(AssignVarStatement)
MAKE_ACCEPT(AssignConfigVarStatement)
MAKE_ACCEPT(Predicate)
MAKE_ACCEPT(AttachPoint)
MAKE_ACCEPT(If)
MAKE_ACCEPT(Unroll)
MAKE_ACCEPT(While)
MAKE_ACCEPT(For)
MAKE_ACCEPT(Config)
MAKE_ACCEPT(Jump)
MAKE_ACCEPT(Probe)
MAKE_ACCEPT(SubprogArg)
MAKE_ACCEPT(Subprog)
MAKE_ACCEPT(Program)

#undef MAKE_ACCEPT

Call::~Call()
{
  if (vargs)
    for (Expression *expr : *vargs)
      delete expr;

  delete vargs;
  vargs = nullptr;
}
Sizeof::~Sizeof()
{
  if (expr)
    delete expr;
  expr = nullptr;
}
Offsetof::~Offsetof()
{
  if (expr)
    delete expr;
  expr = nullptr;
}
Map::~Map()
{
  if (vargs)
    for (Expression *expr : *vargs)
      delete expr;

  delete vargs;
  vargs = nullptr;
}
Binop::~Binop()
{
  delete left;
  delete right;
  left = nullptr;
  right = nullptr;
}

Unop::~Unop()
{
  delete expr;
  expr = nullptr;
}

FieldAccess::~FieldAccess()
{
  delete expr;
  expr = nullptr;
}

ArrayAccess::~ArrayAccess()
{
  delete expr;
  delete indexpr;
  expr = nullptr;
  indexpr = nullptr;
}

Cast::~Cast()
{
  delete expr;
  expr = nullptr;
}

Tuple::~Tuple()
{
  for (Expression *expr : *elems)
    delete expr;
  delete elems;
}

ExprStatement::~ExprStatement()
{
  delete expr;
  expr = nullptr;
}

AssignMapStatement::~AssignMapStatement()
{
  // In a compound assignment, the expression owns the map so
  // we shouldn't free
  if (!compound)
    delete map;
  delete expr;
  map = nullptr;
  expr = nullptr;
}

AssignVarStatement::~AssignVarStatement()
{
  // In a compound assignment, the expression owns the map so
  // we shouldn't free
  if (!compound)
    delete var;
  delete expr;
  var = nullptr;
  expr = nullptr;
}

AssignConfigVarStatement::~AssignConfigVarStatement()
{
  delete expr;
  expr = nullptr;
}

If::~If()
{
  delete cond;
  cond = nullptr;

  if (stmts)
    for (Statement *s : *stmts)
      delete s;
  delete stmts;
  stmts = nullptr;

  if (else_stmts)
    for (Statement *s : *else_stmts)
      delete s;
  delete else_stmts;
  else_stmts = nullptr;
}

Unroll::~Unroll()
{
  if (stmts)
    for (Statement *s : *stmts)
      delete s;
  delete stmts;
  stmts = nullptr;
}
Jump::~Jump()
{
  if (return_value)
    delete return_value;
  return_value = nullptr;
}
Predicate::~Predicate()
{
  delete expr;
  expr = nullptr;
}
Ternary::~Ternary()
{
  delete cond;
  delete left;
  delete right;
  cond = nullptr;
  left = nullptr;
  right = nullptr;
}

While::~While()
{
  delete cond;
  for (auto *stmt : *stmts)
    delete stmt;
  delete stmts;
}

For::~For()
{
  delete decl;
  delete expr;
  for (auto *stmt : *stmts)
    delete stmt;
  delete stmts;
}

Config::~Config()
{
  for (auto *stmt : *stmts)
    delete stmt;
  delete stmts;
}

Scope::~Scope()
{
  if (stmts)
    for (auto *stmt : *stmts)
      delete stmt;
  delete stmts;
  stmts = nullptr;
}

Probe::~Probe()
{
  if (attach_points)
    for (AttachPoint *ap : *attach_points)
      delete ap;
  delete attach_points;
  attach_points = nullptr;

  delete pred;
  pred = nullptr;
}

Subprog::~Subprog()
{
  if (args)
    for (SubprogArg *a : *args)
      delete a;
  delete args;
}

Program::~Program()
{
  if (functions)
    for (Subprog *s : *functions)
      delete s;
  delete functions;
  if (probes)
    for (Probe *p : *probes)
      delete p;
  delete probes;
  probes = nullptr;
  delete config;
  config = nullptr;
}

Integer::Integer(int64_t n, location loc) : Expression(loc), n(n)
{
  is_literal = true;
}

String::String(const std::string &str, location loc) : Expression(loc), str(str)
{
  is_literal = true;
}

StackMode::StackMode(const std::string &mode, location loc)
    : Expression(loc), mode(mode)
{
  is_literal = true;
}

Builtin::Builtin(const std::string &ident, location loc)
    : Expression(loc), ident(is_deprecated(ident))
{
}

Identifier::Identifier(const std::string &ident, location loc)
    : Expression(loc), ident(ident)
{
}

PositionalParameter::PositionalParameter(PositionalParameterType ptype,
                                         long n,
                                         location loc)
    : Expression(loc), ptype(ptype), n(n)
{
  is_literal = true;
}

Call::Call(const std::string &func, location loc)
    : Expression(loc), func(is_deprecated(func)), vargs(nullptr)
{
}

Call::Call(const std::string &func, ExpressionList *vargs, location loc)
    : Expression(loc), func(is_deprecated(func)), vargs(vargs)
{
}

Sizeof::Sizeof(SizedType type, location loc)
    : Expression(loc), expr(nullptr), argtype(type)
{
}

Sizeof::Sizeof(Expression *expr, location loc) : Expression(loc), expr(expr)
{
}

Offsetof::Offsetof(SizedType record, std::string &field, location loc)
    : Expression(loc), record(record), expr(nullptr), field(field)
{
}

Offsetof::Offsetof(Expression *expr, std::string &field, location loc)
    : Expression(loc), expr(expr), field(field)
{
}

Map::Map(const std::string &ident, location loc)
    : Expression(loc), ident(ident), vargs(nullptr)
{
  is_map = true;
}

Map::Map(const std::string &ident, ExpressionList *vargs, location loc)
    : Expression(loc), ident(ident), vargs(vargs)
{
  is_map = true;
  for (auto expr : *vargs) {
    expr->key_for_map = this;
  }
}

Variable::Variable(const std::string &ident, location loc)
    : Expression(loc), ident(ident)
{
  is_variable = true;
}

Binop::Binop(Expression *left, Operator op, Expression *right, location loc)
    : Expression(loc), left(left), right(right), op(op)
{
}

Unop::Unop(Operator op, Expression *expr, location loc)
    : Expression(loc), expr(expr), op(op), is_post_op(false)
{
}

Unop::Unop(Operator op, Expression *expr, bool is_post_op, location loc)
    : Expression(loc), expr(expr), op(op), is_post_op(is_post_op)
{
}

Ternary::Ternary(Expression *cond,
                 Expression *left,
                 Expression *right,
                 location loc)
    : Expression(loc), cond(cond), left(left), right(right)
{
}

FieldAccess::FieldAccess(Expression *expr,
                         const std::string &field,
                         location loc)
    : Expression(loc), expr(expr), field(field)
{
}

FieldAccess::FieldAccess(Expression *expr, ssize_t index, location loc)
    : Expression(loc), expr(expr), index(index)
{
}

ArrayAccess::ArrayAccess(Expression *expr, Expression *indexpr, location loc)
    : Expression(loc), expr(expr), indexpr(indexpr)
{
}

Cast::Cast(SizedType cast_type, Expression *expr, location loc)
    : Expression(loc), expr(expr)
{
  type = cast_type;
}

Tuple::Tuple(ExpressionList *elems, location loc)
    : Expression(loc), elems(elems)
{
}

ExprStatement::ExprStatement(Expression *expr, location loc)
    : Statement(loc), expr(expr)
{
}

AssignMapStatement::AssignMapStatement(Map *map,
                                       Expression *expr,
                                       bool compound,
                                       location loc)
    : Statement(loc), map(map), expr(expr), compound(compound)
{
  expr->map = map;
};

AssignVarStatement::AssignVarStatement(Variable *var,
                                       Expression *expr,
                                       bool compound,
                                       location loc)
    : Statement(loc), var(var), expr(expr), compound(compound)
{
  expr->var = var;
}

AssignConfigVarStatement::AssignConfigVarStatement(
    const std::string &config_var,
    Expression *expr,
    location loc)
    : Statement(loc), config_var(config_var), expr(expr)
{
}

Predicate::Predicate(Expression *expr, location loc) : Node(loc), expr(expr)
{
}

AttachPoint::AttachPoint(const std::string &raw_input, location loc)
    : Node(loc), raw_input(raw_input)
{
}

If::If(Expression *cond, StatementList *stmts) : cond(cond), stmts(stmts)
{
}

If::If(Expression *cond, StatementList *stmts, StatementList *else_stmts)
    : cond(cond), stmts(stmts), else_stmts(else_stmts)
{
}

Unroll::Unroll(Expression *expr, StatementList *stmts, location loc)
    : Statement(loc), expr(expr), stmts(stmts)
{
}

Scope::Scope(StatementList *stmts) : stmts(stmts)
{
}

Probe::Probe(AttachPointList *attach_points,
             Predicate *pred,
             StatementList *stmts)
    : Scope(stmts), attach_points(attach_points), pred(pred)
{
}

SubprogArg::SubprogArg(std::string name, SizedType type)
    : type(std::move(type)), name_(std::move(name))
{
}

std::string SubprogArg::name() const
{
  return name_;
}

Subprog::Subprog(std::string name,
                 SizedType return_type,
                 SubprogArgList *args,
                 StatementList *stmts)
    : Scope(stmts),
      args(args),
      return_type(std::move(return_type)),
      name_(std::move(name))
{
}

Program::Program(const std::string &c_definitions,
                 Config *config,
                 SubprogList *functions,
                 ProbeList *probes)
    : c_definitions(c_definitions),
      config(config),
      functions(functions),
      probes(probes)
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
      return "++";
    case Operator::DECREMENT:
      return "--";
    default:
      return {};
  }

  return {}; // unreached
}

AttachPoint AttachPoint::create_expansion_copy(const std::string &match) const
{
  AttachPoint ap = *this; // copy here
  switch (probetype(ap.provider)) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      ap.func = match;
      if (match.find(":") != std::string::npos)
        ap.target = erase_prefix(ap.func);
      break;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::kfunc:
    case ProbeType::kretfunc:
    case ProbeType::tracepoint:
      // Tracepoint, uprobe, and k(ret)func probes specify both a target
      // (category for tracepoints, binary for uprobes, and kernel module
      // for k(ret)func) and a function name.
      ap.func = match;
      ap.target = erase_prefix(ap.func);
      break;
    case ProbeType::usdt:
      // USDT probes specify a target binary path, a provider, and a function
      // name.
      ap.func = match;
      ap.target = erase_prefix(ap.func);
      ap.ns = erase_prefix(ap.func);
      break;
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
      // Watchpoint probes come with target prefix. Strip the target to get the
      // function
      ap.func = match;
      erase_prefix(ap.func);
      break;
    case ProbeType::rawtracepoint:
      ap.func = match;
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
  if (target != "")
    n += ":" + target;
  if (lang != "")
    n += ":" + lang;
  if (ns != "")
    n += ":" + ns;
  if (func != "") {
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
  if (mode.size())
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
  std::transform(attach_points->begin(),
                 attach_points->end(),
                 std::back_inserter(ap_names),
                 [](const AttachPoint *ap) { return ap->name(); });
  return str_join(ap_names, ",");
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

Expression::Expression(const Expression &other) : Node(other)
{
  type = other.type;
  is_literal = other.is_literal;
  is_variable = other.is_variable;
  is_map = other.is_map;
}

Call::Call(const Call &other) : Expression(other)
{
  func = other.func;
}

Sizeof::Sizeof(const Sizeof &other) : Expression(other)
{
}

Offsetof::Offsetof(const Offsetof &other) : Expression(other)
{
}

Binop::Binop(const Binop &other) : Expression(other)
{
  op = other.op;
}

Unop::Unop(const Unop &other) : Expression(other)
{
  op = other.op;
  is_post_op = other.is_post_op;
}

Map::Map(const Map &other) : Expression(other)
{
  ident = other.ident;
  skip_key_validation = other.skip_key_validation;
}

FieldAccess::FieldAccess(const FieldAccess &other)
    : Expression(other), expr(nullptr)
{
  field = other.field;
  index = other.index;
}

Unroll::Unroll(const Unroll &other) : Statement(other)
{
  var = other.var;
}

Program::Program(const Program &other) : Node(other)
{
  c_definitions = other.c_definitions;
  config = other.config;
}

Config::Config(const Config &other) : Statement(other)
{
}

Cast::Cast(const Cast &other) : Expression(other)
{
}

SubprogArg::SubprogArg(const SubprogArg &other) : Node(other)
{
  name_ = other.name_;
  type = other.type;
}

Subprog::Subprog(const Subprog &other) : Scope(other)
{
  name_ = other.name_;
}

Probe::Probe(const Probe &other) : Scope(static_cast<const Scope &>(other))
{
  need_expansion = other.need_expansion;
  tp_args_structs_level = other.tp_args_structs_level;
  index_ = other.index_;
}

std::string Subprog::name() const
{
  return name_;
}

bool Probe::has_ap_of_probetype(ProbeType probe_type)
{
  if (!attach_points)
    return false;
  for (auto ap : *attach_points) {
    if (probetype(ap->provider) == probe_type)
      return true;
  }
  return false;
}

While::While(const While &other) : Statement(other)
{
}

For::For(const For &other) : Statement(other)
{
}

Tuple::Tuple(const Tuple &other) : Expression(other)
{
}

If::If(const If &other) : Statement(other)
{
}

AssignVarStatement::AssignVarStatement(const AssignVarStatement &other)
    : Statement(other)
{
  compound = other.compound;
};

AssignMapStatement::AssignMapStatement(const AssignMapStatement &other)
    : Statement(other)
{
  compound = other.compound;
};

AssignConfigVarStatement::AssignConfigVarStatement(
    const AssignConfigVarStatement &other)
    : Statement(other){};

SizedType ident_to_record(const std::string &ident, int pointer_level)
{
  SizedType result = CreateRecord(ident, std::weak_ptr<Struct>());
  for (int i = 0; i < pointer_level; i++)
    result = CreatePointer(result);
  return result;
}

} // namespace ast
} // namespace bpftrace
