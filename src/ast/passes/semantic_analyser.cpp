#include <algorithm>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <cstring>
#include <optional>
#include <regex>
#include <string>
#include <sys/stat.h>

#include "arch/arch.h"
#include "ast/ast.h"
#include "ast/async_event_types.h"
#include "ast/context.h"
#include "ast/helpers.h"
#include "ast/integer_types.h"
#include "ast/passes/fold_literals.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/semantic_analyser.h"
#include "ast/passes/type_system.h"
#include "ast/tracepoint_helpers.h"
#include "bpftrace.h"
#include "btf/compat.h"
#include "collect_nodes.h"
#include "config.h"
#include "log.h"
#include "probe_matcher.h"
#include "probe_types.h"
#include "types.h"
#include "usdt.h"
#include "util/paths.h"
#include "util/strings.h"
#include "util/system.h"
#include "util/wildcard.h"

namespace bpftrace::ast {

namespace {

struct variable {
  SizedType type;
  bool can_resize;
  bool was_assigned;
};

class PassTracker {
public:
  void mark_final_pass()
  {
    assert(state_ == SecondChance);
    state_ = FinalPass;
  }
  void mark_second_chance()
  {
    assert(state_ == Converging);
    state_ = SecondChance;
  }
  void clear_second_chance()
  {
    assert(state_ == SecondChance);
    state_ = Converging;
  }
  bool is_final_pass() const
  {
    return state_ == FinalPass;
  }
  bool is_second_chance() const
  {
    return state_ == SecondChance;
  }
  void inc_num_unresolved()
  {
    num_unresolved_++;
  }
  void add_unresolved_branch(IfExpr &if_expr)
  {
    unresolved_branches_.push_back(&if_expr);
  }
  void reset_num_unresolved()
  {
    num_unresolved_ = 0;
    unresolved_branches_.clear();
  }
  int get_num_unresolved() const
  {
    return num_unresolved_;
  }
  const std::vector<IfExpr *> &get_unresolved_branches()
  {
    return unresolved_branches_;
  }
  int get_num_passes() const
  {
    return num_passes_;
  }
  void inc_num_passes()
  {
    num_passes_++;
  }

private:
  enum State {
    Converging,
    SecondChance,
    FinalPass,
  };
  State state_ = Converging;
  int num_unresolved_ = 0;
  std::vector<IfExpr *> unresolved_branches_;
  int num_passes_ = 1;
};

struct arg_type_spec {
  Type type = Type::integer;
  bool literal = false;

  // This indicates that this is just a placeholder as we use the index in the
  // vector of arg_type_spec as the number argument to check.
  bool skip_check = false;
};

struct map_type_spec {
  // This indicates that the argument must be a map type. The given function
  // may be called to determine the map type.
  std::function<SizedType(const Call &call)> type;
};

struct map_key_spec {
  // This indicates that the argument is a key expression for another map
  // argument, which is found in argument `map_index`.
  size_t map_index;
};

struct call_spec {
  size_t min_args = 0;
  size_t max_args = 0;
  // NOLINTBEGIN(readability-redundant-member-init)
  std::vector<std::variant<arg_type_spec, map_type_spec, map_key_spec>>
      arg_types = {};
  // NOLINTEND(readability-redundant-member-init)
};

class SemanticAnalyser : public Visitor<SemanticAnalyser> {
public:
  explicit SemanticAnalyser(ASTContext &ctx,
                            BPFtrace &bpftrace,
                            CDefinitions &c_definitions,
                            MapMetadata &map_metadata,
                            NamedParamDefaults &named_param_defaults,
                            TypeMetadata &type_metadata,
                            MacroRegistry &macro_registry,
                            bool has_child = true)
      : ctx_(ctx),
        bpftrace_(bpftrace),
        c_definitions_(c_definitions),
        map_metadata_(map_metadata),
        named_param_defaults_(named_param_defaults),
        type_metadata_(type_metadata),
        macro_registry_(macro_registry),
        has_child_(has_child)
  {
  }

  int analyse();

  using Visitor<SemanticAnalyser>::visit;
  void visit(String &string);
  void visit(StackMode &mode);
  void visit(Identifier &identifier);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Sizeof &szof);
  void visit(Offsetof &offof);
  void visit(Typeof &typeof);
  void visit(Typeinfo &typeinfo);
  void visit(Map &map);
  void visit(MapAddr &map_addr);
  void visit(MapDeclStatement &decl);
  void visit(Variable &var);
  void visit(VariableAddr &var_addr);
  void visit(Binop &binop);
  void visit(Unop &unop);
  void visit(While &while_block);
  void visit(For &f);
  void visit(Jump &jump);
  void visit(IfExpr &if_expr);
  void visit(FieldAccess &acc);
  void visit(ArrayAccess &arr);
  void visit(TupleAccess &acc);
  void visit(MapAccess &acc);
  void visit(Cast &cast);
  void visit(Tuple &tuple);
  void visit(Expression &expr);
  void visit(ExprStatement &expr);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(VarDeclStatement &decl);
  void visit(Unroll &unroll);
  void visit(Probe &probe);
  void visit(BlockExpr &block);
  void visit(Subprog &subprog);
  void visit(Comptime &comptime);

private:
  ASTContext &ctx_;
  PassTracker pass_tracker_;
  BPFtrace &bpftrace_;
  CDefinitions &c_definitions_;
  MapMetadata &map_metadata_;
  NamedParamDefaults &named_param_defaults_;
  TypeMetadata &type_metadata_;
  const MacroRegistry &macro_registry_;

  bool is_final_pass() const;
  bool is_first_pass() const;
  bool is_second_chance() const;

  std::optional<size_t> check(Sizeof &szof);
  std::optional<size_t> check(Offsetof &offof);

  [[nodiscard]] bool check_arg(Call &call,
                               size_t index,
                               const arg_type_spec &spec);
  [[nodiscard]] bool check_arg(Call &call,
                               size_t index,
                               const map_type_spec &spec);
  [[nodiscard]] bool check_arg(Call &call,
                               size_t index,
                               const map_key_spec &spec);
  [[nodiscard]] bool check_call(Call &call);
  [[nodiscard]] bool check_nargs(const Call &call, size_t expected_nargs);
  [[nodiscard]] bool check_varargs(const Call &call,
                                   size_t min_nargs,
                                   size_t max_nargs);

  bool check_arg(Call &call,
                 Type type,
                 size_t index,
                 bool want_literal = false);
  bool check_symbol(const Call &call, int arg_num);

  void check_stack_call(Call &call, bool kernel);

  Probe *get_probe(Node &node, std::string name = "");

  bool is_valid_assignment(const Expression &expr, bool map_without_type);
  SizedType *get_map_type(const Map &map);
  SizedType *get_map_key_type(const Map &map);
  void assign_map_type(Map &map,
                       const SizedType &type,
                       const Node *loc_node,
                       AssignMapStatement *assignment = nullptr);
  SizedType create_key_type(const SizedType &expr_type, Node &node);
  void reconcile_map_key(Map *map, Expression &key_expr);
  std::optional<SizedType> get_promoted_int(
      const SizedType &leftTy,
      const SizedType &rightTy,
      const std::optional<Expression> &leftExpr = std::nullopt,
      const std::optional<Expression> &rightExpr = std::nullopt);
  std::optional<SizedType> get_promoted_tuple(const SizedType &leftTy,
                                              const SizedType &rightTy);
  std::optional<SizedType> update_int_type(
      const SizedType &rightTy,
      Expression &rightExpr,
      const SizedType &leftTy,
      std::optional<std::reference_wrapper<Expression>> leftExpr = {});
  void resolve_struct_type(SizedType &type, Node &node);

  AddrSpace find_addrspace(ProbeType pt);

  void binop_ptr(Binop &op);
  void binop_int(Binop &op);
  void binop_array(Binop &op);

  void create_int_cast(Expression &exp, const SizedType &target_type);
  void create_string_cast(Expression &exp, const SizedType &target_type);
  void create_tuple_cast(Expression &exp,
                         const SizedType &curr_type,
                         const SizedType &target_type);

  bool has_error() const;
  bool in_loop()
  {
    return loop_depth_ > 0;
  };

  // At the moment we iterate over the stack from top to
  // bottom as variable shadowing is not supported.
  std::vector<Node *> scope_stack_;
  Node *top_level_node_ = nullptr;

  // Holds the function currently being visited by this
  // SemanticAnalyser.
  std::string func_;
  // Holds the function argument index currently being
  // visited by this SemanticAnalyser.
  int func_arg_idx_ = -1;

  variable *find_variable(const std::string &var_ident);
  void check_variable(Variable &var, bool check_assigned);
  Node *find_variable_scope(const std::string &var_ident);

  std::map<Node *, std::map<std::string, variable>> variables_;
  std::map<Node *, std::map<std::string, VarDeclStatement &>> variable_decls_;
  std::map<Node *, CollectNodes<Variable>> for_vars_referenced_;
  std::map<std::string, SizedType> map_val_;
  std::map<std::string, SizedType> map_key_;
  std::map<std::string, bpf_map_type> bpf_map_type_;
  std::map<std::string, SizedType> agg_map_val_;

  uint32_t loop_depth_ = 0;
  uint32_t meta_depth_ = 0; // sizeof, offsetof, etc.
  bool has_child_ = false;
};

} // namespace

static const std::map<std::string, call_spec> CALL_SPEC = {
  { "avg",
    { .min_args = 3,
      .max_args = 3,
      .arg_types = { map_type_spec{
                         .type = std::function<SizedType(const ast::Call &)>(
                             [](const ast::Call &call) -> SizedType {
                              return CreateAvg(
                                   call.vargs.at(2).type().IsSigned());
                             }) },
                     map_key_spec{ .map_index = 0 },
                     arg_type_spec{ .type = Type::integer } } } },
  { "bswap", { .min_args = 1, .max_args = 1 } },
  { "buf",
    { .min_args=1,
      .max_args=2,

      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "cat",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "cgroupid",
    { .min_args=1,
      .max_args=1,

      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "cgroup_path",
    { .min_args=1,
      .max_args=2,

      .arg_types={
        arg_type_spec{ .type=Type::integer },
        arg_type_spec{ .type=Type::string } } } },
  { "clear",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        map_type_spec{},
      }
      } },
  { "count",
    { .min_args=2,
      .max_args=2,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const Call&)>([](const ast::Call&) -> SizedType { return CreateCount(); })
        },
        map_key_spec{ .map_index=0 },
      }
       } },
  { "debugf",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "delete",
    { .min_args=2,
      .max_args=2,
      .arg_types={
        map_type_spec{},
        map_key_spec{ .map_index=0 },
      }
       } },
  { "errorf",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "exit",
    { .min_args=0,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::integer } } } },
  { "hist",
    { .min_args=3,
      .max_args=4,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([]([[maybe_unused]] const ast::Call &call) -> SizedType { return CreateHist(); })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer },
        arg_type_spec{ .type=Type::integer, .literal=true } } } },
  { "join",
    { .min_args=1,
      .max_args=2,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "kaddr",
    { .min_args=1,
      .max_args=1,

      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "kptr",
    { .min_args=1,
      .max_args=1,
       } },
  { "kstack",
    { .min_args=0,
      .max_args=2,
       } },
  { "ksym",
    { .min_args=1,
      .max_args=1,
       } },
  { "stack_len",
    { .min_args=1,
      .max_args=1,

    } },
  { "lhist",
    { .min_args=6,
      .max_args=6,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([]([[maybe_unused]] const ast::Call &call) -> SizedType { return CreateLhist(); })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::integer, .literal=true } } } },
  { "tseries",
    { .min_args=5,
      .max_args=6,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([]([[maybe_unused]] const ast::Call &call) -> SizedType { return CreateTSeries(); })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "macaddr",
    { .min_args=1,
      .max_args=1,
       } },
  { "max",
    { .min_args=3,
      .max_args=3,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([](const ast::Call &call) -> SizedType {
            return CreateMax(call.vargs.at(2).type().IsSigned());
          })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer } } } },
  { "min",
    { .min_args=3,
      .max_args=3,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([](const ast::Call &call) -> SizedType {
            return CreateMin(call.vargs.at(2).type().IsSigned());
          })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer } } } },
  { "nsecs",
    { .min_args=0,
      .max_args=1,

      .arg_types={
        arg_type_spec{ .type=Type::timestamp_mode } } } },
  { "ntop",
    { .min_args=1,
      .max_args=2,
       } },
  { "offsetof",
    { .min_args=2,
      .max_args=2,
       } },
  { "path",
    { .min_args=1,
      .max_args=2,

      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer, .literal=true } } } },
  { "percpu_kaddr",
    { .min_args=1,
      .max_args=2,

      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "print",
    { .min_args=1,
      .max_args=3,
      .arg_types={
        // This may be a pure map or not.
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::integer, .literal=true } } } },

  { "printf",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "pton",
    { .min_args=1,
      .max_args=1,
       } },
  { "reg",
    { .min_args=1,
      .max_args=1,

      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "sizeof",
    { .min_args=1,
      .max_args=1,
       } },
  { "skboutput",
    { .min_args=4,
      .max_args=4,

      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true }, // pcap file name
        arg_type_spec{ .type=Type::pointer },      // *skb
        arg_type_spec{ .type=Type::integer },      // cap length
        // cap offset, default is 0
        // some tracepoints like dev_queue_xmit will output ethernet header,
        // set offset to 14 bytes can exclude this header
        arg_type_spec{ .type=Type::integer } } } },
  { "stats",
    { .min_args=3,
      .max_args=3,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([](const ast::Call &call) -> SizedType {
            return CreateStats(call.vargs.at(2).type().IsSigned());
          })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer } } } },
  { "str",
    { .min_args=1,
      .max_args=2,

      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "strftime",
    { .min_args=2,
      .max_args=2,

      .arg_types={
          arg_type_spec{ .type=Type::string, .literal=true },
          arg_type_spec{ .type=Type::integer } } } },
  { "strncmp",
    { .min_args=3,
      .max_args=3,

      .arg_types={
          arg_type_spec{ .type=Type::string },
          arg_type_spec{ .type=Type::string },
          arg_type_spec{ .type=Type::integer, .literal=true } } } },
  { "sum",
    { .min_args=3,
      .max_args=3,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([](const ast::Call &call) -> SizedType {
            return CreateSum(call.vargs.at(2).type().IsSigned());
          })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer } } } },
  { "system",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "time",
    { .min_args=0,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "__builtin_uaddr",
    { .min_args=1,
      .max_args=1,

      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "unwatch",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::integer } } } },
  { "uptr",
    { .min_args=1,
      .max_args=1,
       } },
  { "ustack",
    { .min_args=0,
      .max_args=2,
       } },
  { "usym",
    { .min_args=1,
      .max_args=1,
       } },
  { "warnf",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "zero",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        map_type_spec{},
      } } },
  { "pid",
    { .min_args=0,
      .max_args=1 },
  },
  { "socket_cookie",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::pointer }, // struct sock *
      } } },
  { "fail",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true },
      } } },
};
// clang-format on

static const std::map<std::string, std::tuple<size_t, bool>> &getIntcasts()
{
  static const std::map<std::string, std::tuple<size_t, bool>> intcasts = {
    { "uint8", std::tuple<size_t, bool>{ 8, false } },
    { "int8", std::tuple<size_t, bool>{ 8, true } },
    { "uint16", std::tuple<size_t, bool>{ 16, false } },
    { "int16", std::tuple<size_t, bool>{ 16, true } },
    { "uint32", std::tuple<size_t, bool>{ 32, false } },
    { "int32", std::tuple<size_t, bool>{ 32, true } },
    { "uint64", std::tuple<size_t, bool>{ 64, false } },
    { "int64", std::tuple<size_t, bool>{ 64, true } },
  };
  return intcasts;
}

// These are types which aren't valid for scratch variables
// e.g. this is not valid `let $x: sum_t;`
static bool IsValidVarDeclType(const SizedType &ty)
{
  switch (ty.GetTy()) {
    case Type::avg_t:
    case Type::count_t:
    case Type::hist_t:
    case Type::lhist_t:
    case Type::tseries_t:
    case Type::max_t:
    case Type::min_t:
    case Type::stats_t:
    case Type::sum_t:
    case Type::stack_mode:
    case Type::voidtype:
      return false;
    case Type::integer:
    case Type::kstack_t:
    case Type::ustack_t:
    case Type::timestamp:
    case Type::ksym_t:
    case Type::usym_t:
    case Type::inet:
    case Type::username:
    case Type::string:
    case Type::buffer:
    case Type::pointer:
    case Type::array:
    case Type::mac_address:
    case Type::record:
    case Type::tuple:
    case Type::cgroup_path_t:
    case Type::none:
    case Type::timestamp_mode:
    case Type::boolean:
      return true;
  }
  return false; // unreachable
}

// These are special map aggregation types that cannot be assigned
// to scratch variables or from one map to another e.g. these are both invalid:
// `@a = hist(10); let $b = @a;`
// `@a = count(); @b = @a;`
// However, if the assigned map already contains integers, we implicitly cast
// the aggregation into an integer to retrieve its value, so this is valid:
// `@a = count(); @b = 0; @b = @a`
bool SemanticAnalyser::is_valid_assignment(const Expression &expr,
                                           bool map_without_type)
{
  // Prevent assigning aggregations to another map.
  if (expr.type().IsMultiKeyMapTy()) {
    return false;
  } else if (expr.type().NeedsPercpuMap() && !expr.type().IsCastableMapTy()) {
    return false;
  } else if (expr.type().IsCastableMapTy() && map_without_type) {
    return false;
  } else if (is_final_pass() && expr.type().IsNoneTy()) {
    return false;
  }
  return true;
}

void SemanticAnalyser::visit(String &string)
{
  // Skip check for printf()'s format string (1st argument) and create the
  // string with the original size. This is because format string is not part of
  // bpf byte code.
  if ((func_ == "printf" || func_ == "errorf" || func_ == "warnf") &&
      func_arg_idx_ == 0)
    return;

  const auto str_len = bpftrace_.config_->max_strlen;
  if (!is_compile_time_func(func_) && string.value.size() > str_len - 1) {
    string.addError() << "String is too long (over " << str_len
                      << " bytes): " << string.value;
  }
  // @a = buf("hi", 2). String allocated on bpf stack. See codegen
  string.string_type.SetAS(AddrSpace::kernel);
}

void SemanticAnalyser::visit(Identifier &identifier)
{
  if (c_definitions_.enums.contains(identifier.ident)) {
    const auto &enum_name = std::get<1>(c_definitions_.enums[identifier.ident]);
    identifier.ident_type = CreateEnum(64, enum_name);
  } else if (bpftrace_.structs.Has(identifier.ident)) {
    identifier.ident_type = CreateRecord(
        identifier.ident, bpftrace_.structs.Lookup(identifier.ident));
  } else if (func_ == "sizeof" && getIntcasts().contains(identifier.ident)) {
    identifier.ident_type = CreateInt(
        std::get<0>(getIntcasts().at(identifier.ident)));
  } else if (func_ == "nsecs") {
    identifier.ident_type = CreateTimestampMode();
    if (identifier.ident == "monotonic") {
      identifier.ident_type.ts_mode = TimestampMode::monotonic;
    } else if (identifier.ident == "boot") {
      identifier.ident_type.ts_mode = TimestampMode::boot;
    } else if (identifier.ident == "tai") {
      identifier.ident_type.ts_mode = TimestampMode::tai;
    } else if (identifier.ident == "sw_tai") {
      identifier.ident_type.ts_mode = TimestampMode::sw_tai;
    } else {
      identifier.addError() << "Invalid timestamp mode: " << identifier.ident;
    }
  } else if (func_ == "pid" || func_ == "tid") {
    if (identifier.ident != "curr_ns" && identifier.ident != "init") {
      identifier.addError()
          << "Invalid PID namespace mode: " << identifier.ident
          << " (expects: curr_ns or init)";
    }
  } else if (func_ == "signal") {
    if (identifier.ident != "current_pid" &&
        identifier.ident != "current_tid") {
      identifier.addError() << "Invalid signal target: " << identifier.ident
                            << " (expects: current_pid or current_tid)";
    }
  } else {
    // Final attempt: try to parse as a stack mode.
    ConfigParser<StackMode> parser;
    StackMode mode;
    auto ok = parser.parse(func_, &mode, identifier.ident);
    if (ok) {
      identifier.ident_type = CreateStack(true, StackType{ .mode = mode });
    } else {
      identifier.addError() << "Unknown identifier: '" + identifier.ident + "'";
    }
  }
}

AddrSpace SemanticAnalyser::find_addrspace(ProbeType pt)
{
  switch (pt) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::tracepoint:
    case ProbeType::iter:
    case ProbeType::rawtracepoint:
      return AddrSpace::kernel;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
      return AddrSpace::user;
    // case : i:ms:1 (struct x*)ctx)->x
    // Cannot decide the addrspace. Provide backward compatibility,
    // if addrspace cannot be detected.
    case ProbeType::invalid:
    case ProbeType::special:
    case ProbeType::test:
    case ProbeType::benchmark:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::software:
    case ProbeType::hardware:
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
      // Will trigger a warning in selectProbeReadHelper.
      return AddrSpace::none;
  }
  return {}; // unreached
}

void SemanticAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "ctx") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType pt = probetype(probe->attach_points[0]->provider);
    bpf_prog_type bt = progtype(pt);
    std::string func = probe->attach_points[0]->func;

    for (auto *attach_point : probe->attach_points) {
      ProbeType pt = probetype(attach_point->provider);
      bpf_prog_type bt2 = progtype(pt);
      if (bt != bt2)
        builtin.addError()
            << "ctx cannot be used in different BPF program types: "
            << progtypeName(bt) << " and " << progtypeName(bt2);
    }
    switch (bt) {
      case BPF_PROG_TYPE_KPROBE: {
        auto record = bpftrace_.structs.Lookup("struct pt_regs");
        if (!record.expired()) {
          builtin.builtin_type = CreatePointer(
              CreateRecord("struct pt_regs", record), AddrSpace::kernel);
          builtin.builtin_type.MarkCtxAccess();
        } else {
          builtin.builtin_type = CreatePointer(CreateNone());
        }
        break;
      }
      case BPF_PROG_TYPE_TRACEPOINT:
        builtin.addError() << "Use args instead of ctx in tracepoint";
        break;
      case BPF_PROG_TYPE_PERF_EVENT:
        builtin.builtin_type = CreatePointer(
            CreateRecord("struct bpf_perf_event_data",
                         bpftrace_.structs.Lookup(
                             "struct bpf_perf_event_data")),
            AddrSpace::kernel);
        builtin.builtin_type.MarkCtxAccess();
        break;
      case BPF_PROG_TYPE_TRACING:
        if (pt == ProbeType::iter) {
          std::string type = "struct bpf_iter__" + func;
          builtin.builtin_type = CreatePointer(
              CreateRecord(type, bpftrace_.structs.Lookup(type)),
              AddrSpace::kernel);
          builtin.builtin_type.MarkCtxAccess();
        } else {
          builtin.addError() << "invalid program type";
        }
        break;
      default:
        builtin.addError() << "invalid program type";
        break;
    }
  } else if (builtin.ident == "pid" || builtin.ident == "tid") {
    builtin.builtin_type = CreateUInt32();
  } else if (builtin.ident == "nsecs" || builtin.ident == "__builtin_elapsed" ||
             builtin.ident == "__builtin_cgroup" ||
             builtin.ident == "__builtin_uid" ||
             builtin.ident == "__builtin_gid" ||
             builtin.ident == "__builtin_cpu" ||
             builtin.ident == "__builtin_rand" ||
             builtin.ident == "__builtin_jiffies" ||
             builtin.ident == "__builtin_ncpus") {
    builtin.builtin_type = CreateUInt64();
  } else if (builtin.ident == "__builtin_curtask") {
    // Retype curtask to its original type: struct task_struct.
    builtin.builtin_type = CreatePointer(
        CreateRecord("struct task_struct",
                     bpftrace_.structs.Lookup("struct task_struct")),
        AddrSpace::kernel);
  } else if (builtin.ident == "__builtin_retval") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType type = probe->get_probetype();

    if (type == ProbeType::kretprobe || type == ProbeType::uretprobe) {
      builtin.builtin_type = CreateUInt64();
    } else if (type == ProbeType::fentry || type == ProbeType::fexit) {
      const auto *arg = bpftrace_.structs.GetProbeArg(*probe,
                                                      RETVAL_FIELD_NAME);
      if (arg) {
        builtin.builtin_type = arg->type;
      } else
        builtin.addError() << "Can't find a field " << RETVAL_FIELD_NAME;
    } else {
      builtin.addError()
          << "The retval builtin can only be used with 'kretprobe' and "
          << "'uretprobe' and 'fentry' probes"
          << (type == ProbeType::tracepoint ? " (try to use args.ret instead)"
                                            : "");
    }
    // For kretprobe, fentry, fexit -> AddrSpace::kernel
    // For uretprobe -> AddrSpace::user
    builtin.builtin_type.SetAS(find_addrspace(type));
  } else if (builtin.ident == "kstack") {
    builtin.builtin_type = CreateStack(
        true, StackType{ .mode = bpftrace_.config_->stack_mode });
  } else if (builtin.ident == "ustack") {
    builtin.builtin_type = CreateStack(
        false, StackType{ .mode = bpftrace_.config_->stack_mode });
  } else if (builtin.ident == "__builtin_comm") {
    constexpr int COMM_SIZE = 16;
    builtin.builtin_type = CreateString(COMM_SIZE);
    // comm allocated in the bpf stack. See codegen
    // Case: @=comm and strncmp(@, "name")
    builtin.builtin_type.SetAS(AddrSpace::kernel);
  } else if (builtin.ident == "__builtin_func") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    for (auto *attach_point : probe->attach_points) {
      ProbeType type = probetype(attach_point->provider);
      if (type == ProbeType::kprobe || type == ProbeType::kretprobe)
        builtin.builtin_type = CreateKSym();
      else if (type == ProbeType::uprobe || type == ProbeType::uretprobe)
        builtin.builtin_type = CreateUSym();
      else if (type == ProbeType::fentry || type == ProbeType::fexit) {
        if (!bpftrace_.feature_->has_helper_get_func_ip()) {
          builtin.addError()
              << "BPF_FUNC_get_func_ip not available for your kernel version";
        }
        builtin.builtin_type = CreateKSym();
      } else
        builtin.addError() << "The func builtin can not be used with '"
                           << attach_point->provider << "' probes";

      if ((type == ProbeType::kretprobe || type == ProbeType::uretprobe) &&
          !bpftrace_.feature_->has_helper_get_func_ip()) {
        builtin.addError()
            << "The 'func' builtin is not available for " << type
            << "s on kernels without the get_func_ip BPF feature. Consider "
               "using the 'probe' builtin instead.";
      }
    }
  } else if (builtin.is_argx()) {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType pt = probetype(probe->attach_points[0]->provider);
    AddrSpace addrspace = find_addrspace(pt);
    int arg_num = atoi(builtin.ident.substr(3).c_str());
    for (auto *attach_point : probe->attach_points) {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::kprobe && type != ProbeType::uprobe &&
          type != ProbeType::usdt && type != ProbeType::rawtracepoint)
        builtin.addError() << "The " << builtin.ident
                           << " builtin can only be used with "
                           << "'kprobes', 'uprobes' and 'usdt' probes";
      // argx in USDT probes doesn't need to check against arch::max_arg()
      if (type != ProbeType::usdt &&
          static_cast<size_t>(arg_num) >= arch::Host::arguments().size())
        builtin.addError() << arch::Host::Machine << " doesn't support "
                           << builtin.ident;
    }
    builtin.builtin_type = CreateUInt64();
    builtin.builtin_type.SetAS(addrspace);
  } else if (builtin.ident == "__builtin_username") {
    builtin.builtin_type = CreateUsername();
  } else if (builtin.ident == "__builtin_usermode") {
    if (arch::Host::Machine != arch::Machine::X86_64) {
      builtin.addError() << "'usermode' builtin is only supported on x86_64";
      return;
    }
    builtin.builtin_type = CreateUInt8();
  } else if (builtin.ident == "__builtin_cpid") {
    if (!has_child_) {
      builtin.addError() << "cpid cannot be used without child command";
    }
    builtin.builtin_type = CreateUInt32();
  } else if (builtin.ident == "args") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    for (auto *attach_point : probe->attach_points) {
      ProbeType type = probetype(attach_point->provider);

      if (type == ProbeType::tracepoint) {
        std::string tracepoint_struct = get_tracepoint_struct_name(
            *attach_point);
        builtin.builtin_type = CreateRecord(
            tracepoint_struct, bpftrace_.structs.Lookup(tracepoint_struct));
        builtin.builtin_type.SetAS(attach_point->target == "syscalls"
                                       ? AddrSpace::user
                                       : AddrSpace::kernel);
        builtin.builtin_type.MarkCtxAccess();
        break;
      }
    }

    ProbeType type = probe->get_probetype();

    if (type == ProbeType::fentry || type == ProbeType::fexit ||
        type == ProbeType::uprobe || type == ProbeType::rawtracepoint) {
      for (auto *attach_point : probe->attach_points) {
        if (attach_point->target == "bpf") {
          builtin.addError() << "The args builtin cannot be used for "
                                "'fentry/fexit:bpf' probes";
          return;
        }
      }
      auto type_name = probe->args_typename();
      builtin.builtin_type = CreateRecord(type_name,
                                          bpftrace_.structs.Lookup(type_name));
      if (builtin.builtin_type.GetFieldCount() == 0)
        builtin.addError() << "Cannot read function parameters";

      builtin.builtin_type.MarkCtxAccess();
      builtin.builtin_type.is_funcarg = true;
      builtin.builtin_type.SetAS(type == ProbeType::uprobe ? AddrSpace::user
                                                           : AddrSpace::kernel);
      // We'll build uprobe args struct on stack
      if (type == ProbeType::uprobe)
        builtin.builtin_type.is_internal = true;
    } else if (type != ProbeType::tracepoint) // no special action for
                                              // tracepoint
    {
      builtin.addError() << "The args builtin can only be used with "
                            "tracepoint/fentry/uprobe probes ("
                         << type << " used here)";
    }
  } else {
    builtin.addError() << "Unknown builtin variable: '" << builtin.ident << "'";
  }
}

void SemanticAnalyser::visit(Call &call)
{
  // Check for unsafe-ness first. It is likely the most pertinent issue
  // (and should be at the top) for any function call.
  if (bpftrace_.safe_mode_ && is_unsafe_func(call.func)) {
    call.addError() << call.func
                    << "() is an unsafe function being used in safe mode";
  }

  struct func_setter {
    func_setter(SemanticAnalyser &analyser, const std::string &s)
        : analyser_(analyser), old_func_(analyser_.func_)
    {
      analyser_.func_ = s;
    }

    ~func_setter()
    {
      analyser_.func_ = old_func_;
      analyser_.func_arg_idx_ = -1;
    }

  private:
    SemanticAnalyser &analyser_;
    std::string old_func_;
  };

  func_setter scope_bound_func_setter{ *this, call.func };

  for (size_t i = 0; i < call.vargs.size(); ++i) {
    func_arg_idx_ = i;
    visit(call.vargs.at(i));
  }

  if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
    for (auto *ap : probe->attach_points) {
      if (!ap->check_available(call.func)) {
        call.addError() << call.func << " can not be used with \""
                        << ap->provider << "\" probes";
      }
    }
  }

  if (!check_call(call)) {
    return;
  }

  if (call.func == "len" || call.func == "delete" || call.func == "has_key") {
    // N.B. this should always be true at this point
    if (auto *map = call.vargs.at(0).as<Map>()) {
      if (map_metadata_.bad_scalar_call.contains(map)) {
        map->addError()
            << "call to " << call.func
            << "() expects a map with explicit keys (non-scalar map)";
        return;
      } else if (map_metadata_.bad_indexed_call.contains(map)) {
        map->addError()
            << "call to " << call.func
            << "() expects a map without explicit keys (scalar map)";
        return;
      }
    }
  }

  if (call.func == "hist") {
    if (call.vargs.size() == 3) {
      call.vargs.emplace_back(ctx_.make_node<Integer>(call.loc, 0)); // default
                                                                     // bits is
                                                                     // 0
    } else {
      const auto *bits = call.vargs.at(3).as<Integer>();
      if (!bits) {
        // Bug here as the validity of the integer literal is already checked by
        // check_arg above.
        LOG(BUG) << call.func << ": invalid bits value, need integer literal";
      } else if (bits->value > 5) {
        call.addError() << call.func << ": bits " << bits->value
                        << " must be 0..5";
      }
    }

    call.return_type = CreateHist();
  } else if (call.func == "lhist") {
    if (is_final_pass()) {
      Expression &min_arg = call.vargs.at(3);
      Expression &max_arg = call.vargs.at(4);
      Expression &step_arg = call.vargs.at(5);
      auto *min = min_arg.as<Integer>();
      auto *max = max_arg.as<Integer>();
      auto *step = step_arg.as<Integer>();

      if (!min) {
        call.addError() << call.func
                        << ": invalid min value (must be non-negative literal)";
        return;
      }
      if (!max) {
        call.addError() << call.func
                        << ": invalid max value (must be non-negative literal)";
        return;
      }
      if (!step) {
        call.addError() << call.func << ": invalid step value";
        return;
      }

      if (step->value <= 0) {
        call.addError() << "lhist() step must be >= 1 (" << step->value
                        << " provided)";
      } else {
        int buckets = (max->value - min->value) / step->value;
        if (buckets > 1000) {
          call.addError()
              << "lhist() too many buckets, must be <= 1000 (would need "
              << buckets << ")";
        }
      }
      if (min->value > max->value) {
        call.addError() << "lhist() min must be less than max (provided min "
                        << min->value << " and max " << max->value << ")";
      }
      if ((max->value - min->value) < step->value) {
        call.addError()
            << "lhist() step is too large for the given range (provided step "
            << step->value << " for range " << (max->value - min->value) << ")";
      }
    }
  } else if (call.func == "tseries") {
    const static std::set<std::string> ALLOWED_AGG_FUNCS = {
      "avg",
      "sum",
      "max",
      "min",
    };
    if (is_final_pass()) {
      Expression &interval_ns_arg = call.vargs.at(3);
      Expression &num_intervals_arg = call.vargs.at(4);

      auto *interval_ns = interval_ns_arg.as<Integer>();
      auto *num_intervals = num_intervals_arg.as<Integer>();

      if (!interval_ns) {
        call.addError()
            << call.func
            << ": invalid interval_ns value (must be non-negative literal)";
        return;
      }
      if (!num_intervals) {
        call.addError()
            << call.func
            << ": invalid num_intervals value (must be non-negative literal)";
        return;
      }

      if (interval_ns->value <= 0) {
        call.addError() << "tseries() interval_ns must be >= 1 ("
                        << interval_ns->value << " provided)";
        return;
      }

      if (num_intervals->value <= 0) {
        call.addError() << "tseries() num_intervals must be >= 1 ("
                        << num_intervals->value << " provided)";
        return;
      } else if (num_intervals->value > 1000000) {
        call.addError() << "tseries() num_intervals must be < 1000000 ("
                        << num_intervals->value << " provided)";
      }

      if (call.vargs.size() == 6) {
        auto &aggregator = *call.vargs.at(5).as<String>();
        if (!ALLOWED_AGG_FUNCS.contains(aggregator.value)) {
          auto &err = call.addError();
          err << "tseries() expects one of the following aggregation "
                 "functions: ";
          size_t i = 0;
          for (const std::string &agg : ALLOWED_AGG_FUNCS) {
            err << agg;
            if (i++ != ALLOWED_AGG_FUNCS.size() - 1) {
              err << ", ";
            }
          }
          err << " (\"" << aggregator.value << "\" provided)";
        }
      }
    }

    call.return_type = CreateVoid();
  } else if (call.func == "count" || call.func == "sum" || call.func == "min" ||
             call.func == "max" || call.func == "avg" || call.func == "stats") {
    call.return_type = CreateVoid();
  } else if (call.func == "delete") {
    call.return_type = CreateUInt8();
  } else if (call.func == "str") {
    auto &arg = call.vargs.at(0);
    const auto &t = arg.type();
    if (!t.IsStringTy() && !t.IsIntegerTy() && !t.IsPtrTy()) {
      call.addError()
          << call.func
          << "() expects a string, integer or a pointer type as first "
          << "argument (" << t << " provided)";
    }
    auto strlen = bpftrace_.config_->max_strlen;
    if (call.vargs.size() == 2) {
      if (auto *integer = call.vargs.at(1).as<Integer>()) {
        if (integer->value + 1 > strlen) {
          call.addWarning() << "length param (" << integer->value
                            << ") is too long and will be shortened to "
                            << strlen << " bytes (see BPFTRACE_MAX_STRLEN)";
        } else {
          strlen = integer->value + 1; // Storage for NUL byte.
        }
      }

      if (auto *integer = dynamic_cast<NegativeInteger *>(
              call.vargs.at(1).as<NegativeInteger>())) {
        call.addError() << call.func << "cannot use negative length ("
                        << integer->value << ")";
      } else {
        // In codegen we compare against the BPFTRACE_MAX_STRLEN
        // which is set as a 64 bit int
        create_int_cast(call.vargs.at(1), CreateUInt64());
      }
    }
    call.return_type = CreateString(strlen);
    call.return_type.SetAS(AddrSpace::kernel);
  } else if (call.func == "buf") {
    const uint64_t max_strlen = bpftrace_.config_->max_strlen;
    if (max_strlen >
        std::numeric_limits<decltype(AsyncEvent::Buf::length)>::max()) {
      call.addError() << "BPFTRACE_MAX_STRLEN too large to use on buffer ("
                      << max_strlen << " > "
                      << std::numeric_limits<uint32_t>::max() << ")";
    }

    auto &arg = call.vargs.at(0);
    if (is_final_pass() && !(arg.type().IsIntTy() || arg.type().IsStringTy() ||
                             arg.type().IsPtrTy() || arg.type().IsArrayTy())) {
      call.addError()
          << call.func
          << "() expects an integer, string, or array argument but saw "
          << typestr(arg.type().GetTy());
    }

    // Subtract out metadata headroom
    uint32_t max_buffer_size = max_strlen - sizeof(AsyncEvent::Buf);
    uint32_t buffer_size = max_buffer_size;

    if (call.vargs.size() == 1) {
      if (arg.type().IsArrayTy())
        buffer_size = arg.type().GetNumElements() *
                      arg.type().GetElementTy()->GetSize();
      else if (is_final_pass())
        call.addError() << call.func
                        << "() expects a length argument for non-array type "
                        << typestr(arg.type().GetTy());
    } else {
      if (auto *integer = call.vargs.at(1).as<Integer>()) {
        buffer_size = integer->value;
      } else if (auto *integer = call.vargs.at(1).as<NegativeInteger>()) {
        call.addError() << call.func << "cannot use negative length ("
                        << integer->value << ")";
      }
    }

    if (buffer_size > max_buffer_size) {
      if (is_final_pass())
        call.addWarning() << call.func
                          << "() length is too long and will be shortened to "
                          << std::to_string(max_strlen)
                          << " bytes (see BPFTRACE_MAX_STRLEN)";

      buffer_size = max_buffer_size;
    }

    call.return_type = CreateBuffer(buffer_size);
    // Consider case : $a = buf("hi", 2); $b = buf("bye", 3);  $a == $b
    // The result of buf is copied to bpf stack. Hence kernel probe read
    call.return_type.SetAS(AddrSpace::kernel);
  } else if (call.func == "ksym" || call.func == "usym") {
    // allow symbol lookups on casts (eg, function pointers)
    auto &arg = call.vargs.at(0);
    const auto &type = arg.type();
    if (!type.IsIntegerTy() && !type.IsPtrTy()) {
      call.addError() << call.func
                      << "() expects an integer or pointer argument";
    } else if (type.IsIntegerTy() && type.GetSize() != 8) {
      create_int_cast(call.vargs.at(0), CreateInt64());
    }

    if (call.func == "ksym")
      call.return_type = CreateKSym();
    else if (call.func == "usym")
      call.return_type = CreateUSym();
  } else if (call.func == "ntop") {
    int index = 0;
    if (call.vargs.size() == 2) {
      check_arg(call, Type::integer, 0);
      index = 1;
    }

    auto &arg = call.vargs.at(index);
    if (!arg.type().IsIntTy() && !arg.type().IsStringTy() &&
        !arg.type().IsArrayTy())
      call.addError() << call.func
                      << "() expects an integer or array argument, got "
                      << arg.type().GetTy();

    // Kind of:
    //
    // struct {
    //   int af_type;
    //   union {
    //     char[4] inet4;
    //     char[16] inet6;
    //   }
    // }
    int buffer_size = 24;
    auto type = arg.type();

    if ((arg.type().IsArrayTy() || arg.type().IsStringTy()) &&
        type.GetSize() != 4 && type.GetSize() != 16)
      call.addError() << call.func
                      << "() argument must be 4 or 16 bytes in size";

    call.return_type = CreateInet(buffer_size);
  } else if (call.func == "pton") {
    int af_type = 0, addr_size = 0;
    std::string addr;
    if (auto *str = call.vargs.at(0).as<String>()) {
      addr = str->value;
      // use '.' and ':' to determine the address family
      if (addr.find(".") != std::string::npos) {
        af_type = AF_INET;
        addr_size = 4;
      } else if (addr.find(":") != std::string::npos) {
        af_type = AF_INET6;
        addr_size = 16;
      } else {
        call.addError()
            << call.func
            << "() expects an string argument of an IPv4/IPv6 address, got "
            << addr;
        return;
      }
    } else {
      call.addError() << call.func << "() expects an string literal, got "
                      << call.vargs.at(0).type();
      return;
    }

    std::vector<char> dst(addr_size);
    auto ret = inet_pton(af_type, addr.c_str(), dst.data());
    if (ret != 1) {
      call.addError() << call.func
                      << "() expects a valid IPv4/IPv6 address, got " << addr;
      return;
    }

    call.return_type = CreateArray(addr_size, CreateUInt8());
    call.return_type.SetAS(AddrSpace::kernel);
    call.return_type.is_internal = true;
  } else if (call.func == "join") {
    call.return_type = CreateNone();

    if (!is_final_pass())
      return;

    auto &arg = call.vargs.at(0);
    if (!(arg.type().IsIntTy() || arg.type().IsPtrTy())) {
      call.addError() << "() only supports int or pointer arguments" << " ("
                      << arg.type().GetTy() << " provided)";
    }
  } else if (call.func == "reg") {
    auto reg_name = call.vargs.at(0).as<String>()->value;
    auto offset = arch::Host::register_to_pt_regs_offset(reg_name);
    if (!offset) {
      call.addError() << "'" << reg_name
                      << "' is not a valid register on this architecture"
                      << " (" << arch::Host::Machine << ")";
    }
    call.return_type = CreateUInt64();
    if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
      ProbeType pt = probe->get_probetype();
      // In case of different attach_points, Set the addrspace to none.
      call.return_type.SetAS(find_addrspace(pt));
    } else {
      // Assume kernel space for data in subprogs
      call.return_type.SetAS(AddrSpace::kernel);
    }
  } else if (call.func == "kaddr") {
    call.return_type = CreateUInt64();
    call.return_type.SetAS(AddrSpace::kernel);
  } else if (call.func == "percpu_kaddr") {
    const auto &symbol = call.vargs.at(0).as<String>()->value;
    if (bpftrace_.btf_->get_var_type(symbol).IsNoneTy()) {
      call.addError() << "Could not resolve variable \"" << symbol
                      << "\" from BTF";
    }
    if (call.vargs.size() == 2 && call.vargs.at(1).type() != CreateUInt32()) {
      create_int_cast(call.vargs.at(1), CreateUInt32());
    }
    call.return_type = CreateUInt64();
    call.return_type.SetAS(AddrSpace::kernel);
  } else if (call.func == "__builtin_uaddr") {
    auto *probe = get_probe(call, call.func);
    if (probe == nullptr)
      return;

    if (!check_symbol(call, 0))
      return;

    std::vector<int> sizes;
    auto name = call.vargs.at(0).as<String>()->value;
    for (auto *ap : probe->attach_points) {
      struct symbol sym = {};
      int err = bpftrace_.resolve_uname(name, &sym, ap->target);
      if (err < 0 || sym.address == 0) {
        call.addError() << "Could not resolve symbol: " << ap->target << ":"
                        << name;
      }
      sizes.push_back(sym.size);
    }

    for (size_t i = 1; i < sizes.size(); i++) {
      if (sizes.at(0) != sizes.at(i)) {
        call.addError() << "Symbol size mismatch between probes. Symbol \""
                        << name << "\" has size " << sizes.at(0)
                        << " for probe \"" << probe->attach_points.at(0)->name()
                        << "\" but size " << sizes.at(i) << " for probe \""
                        << probe->attach_points.at(i)->name() << "\"";
      }
    }
    size_t pointee_size = 0;
    switch (sizes.at(0)) {
      case 1:
      case 2:
      case 4:
        pointee_size = sizes.at(0) * 8;
        break;
      default:
        pointee_size = 64;
    }
    call.return_type = CreatePointer(CreateInt(pointee_size), AddrSpace::user);
  } else if (call.func == "cgroupid") {
    call.return_type = CreateUInt64();
  } else if (call.func == "printf" || call.func == "errorf" ||
             call.func == "warnf" || call.func == "system" ||
             call.func == "cat" || call.func == "debugf") {
    if (is_final_pass()) {
      const auto &fmt = call.vargs.at(0).as<String>()->value;
      std::vector<SizedType> args;
      for (size_t i = 1; i < call.vargs.size(); i++) {
        args.push_back(call.vargs[i].type());
      }
      FormatString fs(fmt);
      auto ok = fs.check(args);
      if (!ok) {
        call.addError() << ok.takeError();
      }
      // The `debugf` call is a builtin, and is subject to more much rigorous
      // checks. We've already validate the basic counts, etc. but we need to
      // apply these additional constraints which includes a limited surface.
      if (call.func == "debugf") {
        call.addWarning()
            << "The debugf() builtin is not recommended for production use. "
               "For more information see bpf_trace_printk in bpf-helpers(7).";
        // bpf_trace_printk cannot use more than three arguments, see
        // bpf-helpers(7).
        constexpr int PRINTK_MAX_ARGS = 3;
        if (args.size() > PRINTK_MAX_ARGS) {
          call.addError() << "cannot use more than " << PRINTK_MAX_ARGS
                          << " conversion specifiers";
        }
        for (size_t i = 0; i < args.size(); i++) {
          // bpf_trace_printk_format_types is a subset of printf_format_types
          // that contains valid types for bpf_trace_printk() see iovisor/bcc
          // BTypeVisitor::checkFormatSpecifiers.
          static const std::unordered_map<std::string, Type>
              bpf_trace_printk_format_types = { { "d", Type::integer },
                                                { "u", Type::integer },
                                                { "x", Type::integer },
                                                { "p", Type::integer },
                                                { "s", Type::string } };
          auto it = bpf_trace_printk_format_types.find(fs.specs[i].specifier);
          if (it == bpf_trace_printk_format_types.end()) {
            call.vargs.at(0).node().addError()
                << "Invalid format specifier for `debugf`: "
                << fs.specs[i].specifier;
            continue;
          }
          if (args[i].GetTy() != it->second) {
            call.vargs.at(i + 1).node().addError()
                << "Type does not match format specifier: "
                << fs.specs[i].specifier;
            continue;
          }
        }
      }
    }
  } else if (call.func == "exit") {
    // Leave as `none`.
  } else if (call.func == "print") {
    if (auto *map = call.vargs.at(0).as<Map>()) {
      if (is_final_pass()) {
        // N.B. that print is parameteric in the type, so this is not checked
        // by `check_arg` as there is no spec for the first argument.
        if (map->type().IsNoneTy()) {
          map->addError() << "Undefined map: " + map->ident;
        } else {
          if (in_loop()) {
            call.addWarning() << "Due to it's asynchronous nature using "
                                 "'print()' in a loop can "
                                 "lead to unexpected behavior. The map will "
                                 "likely be updated "
                                 "before the runtime can 'print' it.";
          }
          if (map->value_type.IsStatsTy() && call.vargs.size() > 1) {
            call.addWarning()
                << "print()'s top and div arguments are ignored when used on "
                   "stats() maps.";
          }
        }
      }
    }
    // Note that IsPrintableTy() is somewhat disingenuous here. Printing a
    // non-map value requires being able to serialize the entire value, so
    // map-backed types like count(), min(), max(), etc. cannot be printed
    // through the non-map printing mechanism.
    //
    // We rely on the fact that semantic analysis enforces types like count(),
    // min(), max(), etc. to be assigned directly to a map.
    else if (call.vargs.at(0).type().IsMultiKeyMapTy()) {
      call.addError()
          << "Map type " << call.vargs.at(0).type()
          << " cannot print the value of individual keys. You must print "
             "the whole map.";
    } else if (call.vargs.at(0).type().IsPrintableTy()) {
      if (call.vargs.size() != 1)
        call.addError() << "Non-map print() only takes 1 argument, "
                        << call.vargs.size() << " found";
    } else {
      if (is_final_pass())
        call.addError() << call.vargs.at(0).type() << " type passed to "
                        << call.func << "() is not printable";
    }
  } else if (call.func == "cgroup_path") {
    call.return_type = CreateCgroupPath();
  } else if (call.func == "clear") {
    // Leave as `none`.
  } else if (call.func == "zero") {
    // Leave as `none`.
  } else if (call.func == "stack_len") {
    if (!call.vargs.at(0).type().IsStack()) {
      call.addError() << "len() expects a map or stack to be provided";
    }
    call.return_type = CreateInt64();
  } else if (call.func == "time") {
    // Leave as `none`.
  } else if (call.func == "strftime") {
    call.return_type = CreateTimestamp();
    if (is_final_pass()) {
      auto &arg = call.vargs.at(1);
      call.return_type.ts_mode = arg.type().ts_mode;
      if (call.return_type.ts_mode == TimestampMode::monotonic) {
        call.addError() << "strftime() can not take a monotonic timestamp";
      }
    }
  } else if (call.func == "kstack") {
    check_stack_call(call, true);
  } else if (call.func == "ustack") {
    check_stack_call(call, false);
  } else if (call.func == "path") {
    auto *probe = get_probe(call, call.func);
    if (probe == nullptr)
      return;

    if (!bpftrace_.feature_->has_d_path()) {
      call.addError()
          << "BPF_FUNC_d_path not available for your kernel version";
    }

    // Argument for path can be both record and pointer.
    // It's pointer when it's passed directly from the probe
    // argument, like: path(args.path))
    // It's record when it's referenced as object pointer
    // member, like: path(args.filp->f_path))
    auto &arg = call.vargs.at(0);
    if (arg.type().GetTy() != Type::record &&
        arg.type().GetTy() != Type::pointer) {
      call.addError() << "path() only supports pointer or record argument ("
                      << arg.type().GetTy() << " provided)";
    }

    auto call_type_size = bpftrace_.config_->max_strlen;
    if (call.vargs.size() == 2) {
      if (auto *size = call.vargs.at(1).as<Integer>()) {
        call_type_size = size->value;
      } else {
        call.addError() << call.func
                        << ": invalid size value, need non-negative literal";
      }
    }

    call.return_type = SizedType(Type::string, call_type_size);

    for (auto *attach_point : probe->attach_points) {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::fentry && type != ProbeType::fexit &&
          type != ProbeType::iter)
        call.addError() << "The path function can only be used with "
                        << "'fentry', 'fexit', 'iter' probes";
    }
  } else if (call.func == "strncmp") {
    if (!call.vargs.at(2).is<Integer>()) {
      call.addError() << "Builtin strncmp requires a non-negative literal";
    }
    call.return_type = CreateUInt64();
  } else if (call.func == "kptr" || call.func == "uptr") {
    // kptr should accept both integer or pointer. Consider case: kptr($1)
    auto &arg = call.vargs.at(0);
    if (!arg.type().IsIntTy() && !arg.type().IsPtrTy()) {
      call.addError() << call.func << "() only supports "
                      << "integer or pointer arguments (" << arg.type().GetTy()
                      << " provided)";
      return;
    }

    auto as = (call.func == "kptr" ? AddrSpace::kernel : AddrSpace::user);
    call.return_type = call.vargs.front().type();
    call.return_type.SetAS(as);
  } else if (call.func == "macaddr") {
    auto &arg = call.vargs.at(0);
    if (!arg.type().IsIntTy() && !arg.type().IsArrayTy() &&
        !arg.type().IsByteArray() && !arg.type().IsPtrTy())
      call.addError() << call.func
                      << "() only supports array or pointer arguments" << " ("
                      << arg.type().GetTy() << " provided)";

    if (arg.is<String>())
      call.addError() << call.func
                      << "() does not support literal string arguments";

    // N.B. When converting from BTF, we can treat string types as 7 bytes in
    // order to signal to userspace that they are well-formed. However, we can
    // convert from anything as long as there are at least 6 bytes to read.
    const auto &type = arg.type();
    if ((type.IsArrayTy() || type.IsByteArray()) && type.GetSize() < 6) {
      call.addError() << call.func
                      << "() argument must be at least 6 bytes in size";
    }

    call.return_type = CreateMacAddress();
  } else if (call.func == "unwatch") {
    // Leave as `none`.
  } else if (call.func == "bswap") {
    auto &arg = call.vargs.at(0);
    if (!arg.type().IsIntTy()) {
      call.addError() << call.func << "() only supports integer arguments ("
                      << arg.type().GetTy() << " provided)";
      return;
    }
    call.return_type = CreateUInt(arg.type().GetIntBitWidth());
  } else if (call.func == "skboutput") {
    call.return_type = CreateUInt32();
  } else if (call.func == "nsecs") {
    call.return_type = CreateUInt64();
    call.return_type.ts_mode = TimestampMode::boot;
    if (call.vargs.size() == 1) {
      call.return_type.ts_mode = call.vargs.at(0).type().ts_mode;
    }

    if (call.return_type.ts_mode == TimestampMode::tai &&
        !bpftrace_.feature_->has_helper_ktime_get_tai_ns()) {
      call.addError()
          << "Kernel does not support tai timestamp, please try sw_tai";
    }
    if (call.return_type.ts_mode == TimestampMode::sw_tai &&
        !bpftrace_.delta_taitime_.has_value()) {
      call.addError() << "Failed to initialize sw_tai in "
                         "userspace. This is very unexpected.";
    }
  } else if (call.func == "pid" || call.func == "tid") {
    call.return_type = CreateUInt32();
    if (call.vargs.size() == 1) {
      auto &arg = call.vargs.at(0);
      if (!(arg.as<Identifier>())) {
        call.addError() << call.func
                        << "() only supports curr_ns and init as the argument ("
                        << arg.type().GetTy() << " provided)";
      }
    }
  } else if (call.func == "socket_cookie") {
    auto logError = [&]<typename T>(T name) {
      call.addError() << call.func
                      << "() only supports 'struct sock *' as the argument ("
                      << name << " provided)";
    };

    const auto &type = call.vargs.at(0).type();
    if (!type.IsPtrTy() || !type.GetPointeeTy() ||
        !type.GetPointeeTy()->IsRecordTy()) {
      logError(type.GetTy());
      return;
    }
    if (!type.GetPointeeTy()->IsSameType(CreateRecord("struct sock"))) {
      logError("'" + type.GetPointeeTy()->GetName() + " *'");
      return;
    }
    call.return_type = CreateUInt64();
  } else if (call.func == "fail") {
    // This is basically a static_assert failure. It will halt the compilation.
    // We expect to hit this path only when using the `typeof` folds.
    bool fail_valid = true;
    std::vector<output::Primitive> args;
    for (size_t i = 0; i < call.vargs.size(); ++i) {
      if (!call.vargs[i].is_literal()) {
        fail_valid = false;
        call.addError() << "fail() arguments need to be literals";
      } else {
        if (i != 0) {
          if (auto *val = call.vargs[i].as<String>()) {
            args.emplace_back(val->value);
          } else if (auto *val = call.vargs[i].as<Integer>()) {
            args.emplace_back(val->value);
          } else if (auto *val = call.vargs[i].as<NegativeInteger>()) {
            args.emplace_back(val->value);
          } else if (auto *val = call.vargs[i].as<Boolean>()) {
            args.emplace_back(val->value);
          }
        } else {
          if (!call.vargs[0].is<String>()) {
            call.addError()
                << "first argument to fail() must be a string literal";
          }
        }
      }
    }

    if (fail_valid) {
      FormatString fs(call.vargs[0].as<String>()->value);
      call.addError() << fs.format(args);
    }
  } else {
    // Check here if this corresponds to an external function. We convert the
    // external type metadata into the internal `SizedType` representation and
    // check that they are exactly equal.
    auto maybe_func = type_metadata_.global.lookup<btf::Function>(call.func);
    if (!maybe_func) {
      call.addError() << "Unknown function: '" << call.func << "'";
      return;
    }

    const auto &func = *maybe_func;

    if (func.linkage() != btf::Function::Linkage::Global &&
        func.linkage() != btf::Function::Linkage::Extern) {
      call.addError() << "Unsupported function linkage: '" << call.func << "'";
      return;
    }

    auto proto = func.type();
    if (!proto) {
      call.addError() << "Unable to find function proto: " << proto.takeError();
      return;
    }
    // Extract our return type.
    auto return_type = proto->return_type();
    if (!return_type) {
      call.addError() << "Unable to read return type: "
                      << return_type.takeError();
      return;
    }
    auto compat_return_type = getCompatType(*return_type);
    if (!compat_return_type) {
      call.addError() << "Unable to convert return type: "
                      << compat_return_type.takeError();
      return;
    }
    call.return_type = *compat_return_type;
    // Convert all arguments.
    auto argument_types = proto->argument_types();
    if (!argument_types) {
      call.addError() << "Unable to read argument types: "
                      << argument_types.takeError();
      return;
    }
    // Check the argument count.
    if (argument_types->size() != call.vargs.size()) {
      call.addError() << "Function `" << call.func << "` requires "
                      << argument_types->size() << " arguments, got only "
                      << call.vargs.size();
      return;
    }
    std::vector<std::pair<std::string, SizedType>> args;
    for (size_t i = 0; i < argument_types->size(); i++) {
      const auto &[name, type] = argument_types->at(i);
      auto compat_arg_type = getCompatType(type);
      if (!compat_arg_type) {
        // If the required type is a **pointer**, and the provided type is
        // a **pointer**, then we let it slide. Just assume the user knows
        // what they are doing. The verifier will catch them out otherwise.
        if (type.is<btf::Pointer>() && call.vargs[i].type().IsPtrTy()) {
          args.emplace_back(name, call.vargs[i].type());
          continue;
        }
        call.addError() << "Unable to convert argument type, "
                        << "function requires '" << type << "', " << "found '"
                        << typestr(call.vargs[i].type())
                        << "': " << compat_arg_type.takeError();
        continue;
      }
      args.emplace_back(name, std::move(*compat_arg_type));
    }
    if (args.size() != argument_types->size()) {
      return; // Already emitted errors.
    }
    // Check all the individual arguments.
    bool ok = true;
    for (size_t i = 0; i < args.size(); i++) {
      const auto &[name, type] = args[i];
      if (type != call.vargs[i].type()) {
        if (!name.empty()) {
          call.vargs[i].node().addError()
              << "Expected " << typestr(type) << " for argument `" << name
              << "` got " << typestr(call.vargs[i].type());
        } else {
          call.vargs[i].node().addError()
              << "Expected " << typestr(type) << " got "
              << typestr(call.vargs[i].type());
        }
        ok = false;
      }
    }
    // Build our full proto as an error message.
    std::stringstream fullmsg;
    fullmsg << "Function `" << call.func << "` requires arguments (";
    bool first = true;
    for (const auto &[name, type] : args) {
      if (!first) {
        fullmsg << ", ";
      }
      fullmsg << typestr(type);
      first = false;
    }
    fullmsg << ")";
    if (!ok) {
      call.addError() << fullmsg.str();
      return;
    }
  }
}

std::optional<size_t> SemanticAnalyser::check(Sizeof &szof)
{
  meta_depth_++;
  Visitor<SemanticAnalyser>::visit(szof);
  meta_depth_--;

  if (std::holds_alternative<SizedType>(szof.record)) {
    auto &ty = std::get<SizedType>(szof.record);
    resolve_struct_type(ty, szof);
    if (!ty.IsNoneTy()) {
      return ty.GetSize();
    }
  } else {
    const auto &ty = std::get<Expression>(szof.record).type();
    if (!ty.IsNoneTy()) {
      return ty.GetSize();
    }
  }

  return std::nullopt;
}

void SemanticAnalyser::visit(Sizeof &szof)
{
  const auto v = check(szof);
  if (!v && is_final_pass()) {
    szof.addError() << "sizeof not resolved, is type complete?";
  }
}

std::optional<size_t> SemanticAnalyser::check(Offsetof &offof)
{
  meta_depth_++;
  Visitor<SemanticAnalyser>::visit(offof);
  meta_depth_--;

  auto check_type = [&](SizedType record) -> std::optional<size_t> {
    size_t offset = 0;
    // Check if all sub-fields are present.
    for (const auto &field : offof.field) {
      if (!record.IsRecordTy()) {
        offof.addError() << "'" << record << "' " << "is not a record type.";
        return std::nullopt;
      } else if (!bpftrace_.structs.Has(record.GetName())) {
        offof.addError() << "'" << record.GetName() << "' does not exist.";
        return std::nullopt;
      } else if (!record.HasField(field)) {
        offof.addError() << "'" << record.GetName() << "' "
                         << "has no field named " << "'" << field << "'";
        return std::nullopt;
      } else {
        // Get next sub-field
        const auto &f = record.GetField(field);
        offset += f.offset;
        record = f.type;
      }
    }
    return offset;
  };

  std::optional<size_t> offset;
  if (std::holds_alternative<SizedType>(offof.record)) {
    auto &ty = std::get<SizedType>(offof.record);
    resolve_struct_type(ty, offof);
    offset = check_type(ty);
  } else {
    const auto &ty = std::get<Expression>(offof.record).type();
    offset = check_type(ty);
  }
  if (offset) {
    return offset.value();
  }

  return std::nullopt;
}

void SemanticAnalyser::visit(Offsetof &offof)
{
  const auto v = check(offof);
  if (!v && is_final_pass()) {
    offof.addError() << "offsetof not resolved, is type complete?";
  }
}

void SemanticAnalyser::visit(Typeof &typeof)
{
  meta_depth_++;
  Visitor<SemanticAnalyser>::visit(typeof);
  meta_depth_--;

  if (std::holds_alternative<SizedType>(typeof.record)) {
    resolve_struct_type(std::get<SizedType>(typeof.record), typeof);
  }
}

void SemanticAnalyser::visit(Typeinfo &typeinfo)
{
  meta_depth_++;
  Visitor<SemanticAnalyser>::visit(typeinfo);
  meta_depth_--;
}

void SemanticAnalyser::check_stack_call(Call &call, bool kernel)
{
  call.return_type = CreateStack(kernel);
  StackType stack_type;
  stack_type.mode = bpftrace_.config_->stack_mode;

  switch (call.vargs.size()) {
    case 0:
      break;
    case 1: {
      if (auto *ident = call.vargs.at(0).as<Identifier>()) {
        ConfigParser<StackMode> parser;
        auto ok = parser.parse(call.func, &stack_type.mode, ident->ident);
        if (!ok) {
          ident->addError() << "Error parsing stack mode: " << ok.takeError();
        }
      } else if (check_arg(call, Type::integer, 0, true)) {
        if (auto *limit = call.vargs.at(0).as<Integer>()) {
          stack_type.limit = limit->value;
        } else {
          call.addError() << call.func << ": invalid limit value";
        }
      }
      break;
    }
    case 2: {
      if (auto *ident = call.vargs.at(0).as<Identifier>()) {
        ConfigParser<StackMode> parser;
        auto ok = parser.parse(call.func, &stack_type.mode, ident->ident);
        if (!ok) {
          ident->addError() << "Error parsing stack mode: " << ok.takeError();
        }
      } else {
        // If two arguments are provided, then the first must be a stack mode.
        call.addError() << "Expected stack mode as first argument";
      }
      if (check_arg(call, Type::integer, 1, true)) {
        if (auto *limit = call.vargs.at(1).as<Integer>()) {
          stack_type.limit = limit->value;
        } else {
          call.addError() << call.func << ": invalid limit value";
        }
      }
      break;
    }
    default:
      call.addError() << "Invalid number of arguments";
      break;
  }
  constexpr int MAX_STACK_SIZE = 1024;
  if (stack_type.limit > MAX_STACK_SIZE) {
    call.addError() << call.func << "([int limit]): limit shouldn't exceed "
                    << MAX_STACK_SIZE << ", " << stack_type.limit << " given";
  }
  call.return_type = CreateStack(kernel, stack_type);
}

Probe *SemanticAnalyser::get_probe(Node &node, std::string name)
{
  auto *probe = dynamic_cast<Probe *>(top_level_node_);
  if (probe == nullptr) {
    // Attempting to use probe-specific feature in non-probe context
    if (name.empty()) {
      node.addError() << "Feature not supported outside probe";
    } else {
      node.addError() << "Builtin " << name << " not supported outside probe";
    }
  }

  return probe;
}

void SemanticAnalyser::visit(MapDeclStatement &decl)
{
  const auto bpf_type = get_bpf_map_type(decl.bpf_type);
  if (!bpf_type) {
    auto &err = decl.addError();
    err << "Invalid bpf map type: " << decl.bpf_type;
    auto &hint = err.addHint();
    add_bpf_map_types_hint(hint);
  } else {
    bpf_map_type_.insert({ decl.ident, *bpf_type });
  }

  if (is_final_pass()) {
    auto map_key_search_val = map_key_.find(decl.ident);
    if (map_key_search_val == map_key_.end()) {
      decl.addWarning() << "Unused map: " << decl.ident;
    }
  }
}

void SemanticAnalyser::visit(Map &map)
{
  if (map_metadata_.bad_indexed_access.contains(&map)) {
    map.addError()
        << map.ident
        << " used as a map without an explicit key (scalar map), previously "
           "used with an explicit key (non-scalar map)";
    return;
  }

  auto val = map_val_.find(map.ident);
  if (val != map_val_.end()) {
    map.value_type = val->second;
  }
  auto key = map_key_.find(map.ident);
  if (key != map_key_.end()) {
    map.key_type = key->second;
  }

  // Note that the naked `Map` node actually gets no type, the type
  // is applied to the node at the `MapAccess` level.
  if (is_final_pass()) {
    auto found_kind = bpf_map_type_.find(map.ident);
    if (found_kind != bpf_map_type_.end()) {
      if (!bpf_map_types_compatible(map.value_type, found_kind->second)) {
        auto map_type = get_bpf_map_type(map.value_type);
        map.addError() << "Incompatible map types. Type from declaration: "
                       << get_bpf_map_type_str(found_kind->second)
                       << ". Type from value/key type: "
                       << get_bpf_map_type_str(map_type);
      }
    }
  }
}
void SemanticAnalyser::visit(MapAddr &map_addr)
{
  if (!map_val_.contains(map_addr.map->ident)) {
    if (!is_first_pass()) {
      map_addr.addError() << "Undefined map: " << map_addr.map->ident;
    }
    pass_tracker_.inc_num_unresolved();
  } else {
    visit(map_addr.map);
    map_addr.map_addr_type = CreatePointer(map_addr.map->type(),
                                           map_addr.map->type().GetAS());
  }
}

void SemanticAnalyser::check_variable(Variable &var, bool check_assigned)
{
  if (auto *found = find_variable(var.ident)) {
    var.var_type = found->type;
    if (!found->was_assigned && check_assigned) {
      var.addWarning() << "Variable used before it was assigned: " << var.ident;
    }
    return;
  }

  var.addError() << "Undefined or undeclared variable: " << var.ident;
}

void SemanticAnalyser::visit(Variable &var)
{
  // Warnings are suppressed when we are evaluating the variable in an
  // expression that is not used, e.g. part of a sizeof, offsetof or a typeof.
  check_variable(var, meta_depth_ == 0);
}

void SemanticAnalyser::visit(VariableAddr &var_addr)
{
  check_variable(*var_addr.var,
                 false /* Don't warn if variable hasn't been assigned yet */);
  if (auto *found = find_variable(var_addr.var->ident)) {
    if (!found->type.IsNoneTy()) {
      var_addr.var_addr_type = CreatePointer(found->type, found->type.GetAS());
    }
    // We can't know if the pointer to a scratch variable was passed
    // to an external function for assignment so just mark it as assigned.
    found->was_assigned = true;
  }
  if (is_final_pass() && var_addr.var_addr_type.IsNoneTy()) {
    var_addr.addError() << "No type available for variable "
                        << var_addr.var->ident;
  }
}

void SemanticAnalyser::visit(ArrayAccess &arr)
{
  visit(arr.expr);
  visit(arr.indexpr);

  const SizedType &type = arr.expr.type();

  if (is_final_pass()) {
    if (!type.IsArrayTy() && !type.IsPtrTy() && !type.IsStringTy()) {
      arr.addError() << "The array index operator [] can only be "
                        "used on arrays and pointers, found "
                     << type.GetTy() << ".";
      return;
    }

    if (type.IsPtrTy() && type.GetPointeeTy()->GetSize() == 0) {
      arr.addError() << "The array index operator [] cannot be used "
                        "on a pointer to an unsized type (void *).";
    }

    if (auto *integer = arr.indexpr.as<Integer>()) {
      auto num = [&]() -> size_t {
        if (type.IsArrayTy()) {
          return type.GetNumElements();
        } else if (type.IsStringTy()) {
          return type.GetSize();
        } else {
          return 0;
        }
      }();
      if (num != 0 && static_cast<size_t>(integer->value) >= num) {
        arr.addError() << "the index " << integer->value
                       << " is out of bounds for array of size " << num;
      }
    } else if (!arr.indexpr.type().IsIntTy() || arr.indexpr.type().IsSigned()) {
      arr.addError() << "The array index operator [] only "
                        "accepts positive (unsigned) integer indices. Got: "
                     << arr.indexpr.type();
    }
  }

  if (type.IsArrayTy())
    arr.element_type = *type.GetElementTy();
  else if (type.IsPtrTy())
    arr.element_type = *type.GetPointeeTy();
  else if (type.IsStringTy())
    arr.element_type = CreateInt8();
  arr.element_type.SetAS(type.GetAS());

  // BPF verifier cannot track BTF information for double pointers so we
  // cannot propagate is_internal for arrays of pointers and we need to reset
  // it on the array type as well. Indexing a pointer as an array also can't
  // be verified, so the same applies there.
  if (arr.element_type.IsPtrTy() || type.IsPtrTy()) {
    arr.element_type.is_internal = false;
  } else {
    arr.element_type.is_internal = type.is_internal;
  }
}

void SemanticAnalyser::visit(TupleAccess &acc)
{
  visit(acc.expr);
  const SizedType &type = acc.expr.type();

  if (!type.IsTupleTy()) {
    if (is_final_pass()) {
      acc.addError() << "Can not access index '" << acc.index
                     << "' on expression of type '" << type << "'";
    }
    return;
  }

  bool valid_idx = acc.index < type.GetFields().size();

  // We may not have inferred the full type of the tuple yet in early passes
  // so wait until the final pass.
  if (!valid_idx && is_final_pass()) {
    acc.addError() << "Invalid tuple index: " << acc.index << ". Found "
                   << type.GetFields().size() << " elements in tuple.";
  }

  if (valid_idx) {
    acc.element_type = type.GetField(acc.index).type;
  }
}

void SemanticAnalyser::binop_int(Binop &binop)
{
  SizedType leftTy = binop.left.type();
  SizedType rightTy = binop.right.type();

  if (leftTy.IsEqual(rightTy)) {
    return;
  }

  if (leftTy.IsBoolTy()) {
    auto *typeof = ctx_.make_node<Typeof>(Location(binop.right.loc()), leftTy);
    binop.right = ctx_.make_node<Cast>(
        Location(binop.right.loc()),
        typeof,
        clone(ctx_, binop.right.loc(), binop.right));
    visit(binop.right);
    return;
  } else if (rightTy.IsBoolTy()) {
    auto *typeof = ctx_.make_node<Typeof>(Location(binop.left.loc()), rightTy);
    binop.left = ctx_.make_node<Cast>(
        Location(binop.left.loc()),
        typeof,
        clone(ctx_, binop.left.loc(), binop.left));
    visit(binop.left);
    return;
  }

  bool show_warning = false;
  bool mismatched_sign = rightTy.IsSigned() != leftTy.IsSigned();
  // N.B. all castable map values are 64 bits
  if (leftTy.IsCastableMapTy()) {
    if (rightTy.IsCastableMapTy()) {
      show_warning = mismatched_sign;
    } else {
      if (!update_int_type(rightTy,
                           binop.right,
                           CreateInteger(64, leftTy.IsSigned()))) {
        show_warning = true;
      }
    }
  } else if (rightTy.IsCastableMapTy()) {
    if (!update_int_type(leftTy,
                         binop.left,
                         CreateInteger(64, rightTy.IsSigned()))) {
      show_warning = true;
    }
  } else if (!update_int_type(rightTy, binop.right, leftTy, binop.left)) {
    show_warning = true;
  }

  if (show_warning) {
    switch (binop.op) {
      case Operator::EQ:
      case Operator::NE:
      case Operator::LE:
      case Operator::GE:
      case Operator::LT:
      case Operator::GT:
        binop.addWarning() << "comparison of integers of different signs: '"
                           << leftTy << "' and '" << rightTy << "'"
                           << " can lead to undefined behavior";
        break;
      case Operator::PLUS:
      case Operator::MINUS:
      case Operator::MUL:
      case Operator::DIV:
      case Operator::MOD:
        binop.addWarning() << "arithmetic on integers of different signs: '"
                           << leftTy << "' and '" << rightTy << "'"
                           << " can lead to undefined behavior";
        break;
      default:
        break;
    }
  }

  // Next, warn on any operations that require signed division.
  //
  // SDIV is not implemented for bpf. See Documentation/bpf/bpf_design_QA
  // in kernel sources
  if (binop.op == Operator::DIV || binop.op == Operator::MOD) {
    // If they're still signed, we have to warn
    if (leftTy.IsSigned() || rightTy.IsSigned()) {
      binop.addWarning() << "signed operands for '" << opstr(binop)
                         << "' can lead to undefined behavior "
                         << "(cast to unsigned to silence warning)";
    } else {
      binop.result_type = CreateUInt64();
    }
  } else if ((binop.op == Operator::MUL || binop.op == Operator::PLUS) &&
             !leftTy.IsSigned() && !rightTy.IsSigned()) {
    binop.result_type = CreateUInt64();
  }
}

void SemanticAnalyser::create_int_cast(Expression &exp,
                                       const SizedType &target_type)
{
  // We don't need a cast if it's a literal
  if (target_type.IsIntegerTy()) {
    if (auto *integer = exp.as<Integer>()) {
      exp = ctx_.make_node<Integer>(
          Location(exp.loc()), integer->value, target_type, integer->original);
      return;
    } else if (auto *negative_integer = exp.as<NegativeInteger>()) {
      exp = ctx_.make_node<NegativeInteger>(Location(exp.loc()),
                                            negative_integer->value,
                                            target_type);
      return;
    }
  }

  auto *typeof_r = ctx_.make_node<Typeof>(Location(exp.loc()), target_type);
  exp = ctx_.make_node<Cast>(Location(exp.loc()),
                             typeof_r,
                             clone(ctx_, exp.loc(), exp));
  visit(exp);
}

void SemanticAnalyser::create_string_cast(Expression &exp,
                                          const SizedType &target_type)
{
  if (exp.type().GetSize() == target_type.GetSize()) {
    return;
  }

  auto *typeof_r = ctx_.make_node<Typeof>(Location(exp.loc()), target_type);
  exp = ctx_.make_node<Cast>(Location(exp.loc()),
                             typeof_r,
                             clone(ctx_, exp.loc(), exp));
  visit(exp);
}

void SemanticAnalyser::create_tuple_cast(Expression &exp,
                                         const SizedType &curr_type,
                                         const SizedType &target_type)
{
  if (auto *block_expr = exp.as<BlockExpr>()) {
    create_tuple_cast(block_expr->expr, curr_type, target_type);
    return;
  }

  if (!exp.is<Variable>() && !exp.is<TupleAccess>() && !exp.is<MapAccess>() &&
      !exp.is<Tuple>()) {
    LOG(BUG) << "Unexpected expression kind: create_tuple_cast";
  }

  ExpressionList expr_list = {};

  for (size_t i = 0; i < target_type.GetFields().size(); ++i) {
    auto &c_ty = curr_type.GetField(i).type;
    auto &t_ty = target_type.GetField(i).type;
    Expression elem;
    if (auto *tuple_literal = exp.as<Tuple>()) {
      elem = clone(ctx_,
                   tuple_literal->elems.at(i).loc(),
                   tuple_literal->elems.at(i));
    } else {
      elem = ctx_.make_node<TupleAccess>(Location(exp.loc()),
                                         clone(ctx_, exp.loc(), exp),
                                         i);
      elem.as<TupleAccess>()->element_type = c_ty;
    }
    if (t_ty.IsIntTy() && c_ty != t_ty) {
      create_int_cast(elem, t_ty);
    } else if (t_ty.IsStringTy()) {
      create_string_cast(elem, t_ty);
    } else if (t_ty.IsTupleTy()) {
      create_tuple_cast(elem, c_ty, t_ty);
    }
    expr_list.emplace_back(std::move(elem));
  }

  exp = ctx_.make_node<Tuple>(Location(exp.loc()), std::move(expr_list));
  exp.as<Tuple>()->tuple_type = target_type;
  visit(exp);
}

void SemanticAnalyser::binop_array(Binop &binop)
{
  const auto &lht = binop.left.type();
  const auto &rht = binop.right.type();
  if (binop.op != Operator::EQ && binop.op != Operator::NE) {
    binop.addError() << "The " << opstr(binop)
                     << " operator cannot be used on arrays.";
  }

  if (lht.GetNumElements() != rht.GetNumElements()) {
    binop.addError()
        << "Only arrays of same size support comparison operators.";
  }

  if (!lht.GetElementTy()->IsIntegerTy() || lht != rht) {
    binop.addError()
        << "Only arrays of same sized integer support comparison operators.";
  }
}

void SemanticAnalyser::binop_ptr(Binop &binop)
{
  const auto &lht = binop.left.type();
  const auto &rht = binop.right.type();

  bool left_is_ptr = lht.IsPtrTy();
  const auto &ptr = left_is_ptr ? lht : rht;
  const auto &other = left_is_ptr ? rht : lht;

  bool compare = false;
  bool logical = false;

  // Do what C does
  switch (binop.op) {
    case Operator::EQ:
    case Operator::NE:
    case Operator::LE:
    case Operator::GE:
    case Operator::LT:
    case Operator::GT:
      compare = true;
      break;
    case Operator::LAND:
    case Operator::LOR:
      logical = true;
      break;
    default:;
  }

  auto invalid_op = [&binop, &lht, &rht]() {
    binop.addError() << "The " << opstr(binop)
                     << " operator can not be used on expressions of types "
                     << lht << ", " << rht;
  };

  // Binop on two pointers
  if (other.IsPtrTy()) {
    if (compare) {
      if (is_final_pass()) {
        const auto *le = lht.GetPointeeTy();
        const auto *re = rht.GetPointeeTy();
        if (*le != *re) {
          auto &warn = binop.addWarning();
          warn << "comparison of distinct pointer types: " << *le << ", "
               << *re;
          warn.addContext(binop.left.loc()) << "left (" << *le << ")";
          warn.addContext(binop.right.loc()) << "right (" << *re << ")";
        }
      }
    } else if (!logical) {
      invalid_op();
    }
  }
  // Binop on a pointer and (int or bool)
  else if (other.IsIntTy() || other.IsBoolTy()) {
    // sum is associative but minus only works with pointer on the left hand
    // side
    if (binop.op == Operator::MINUS && !left_is_ptr)
      invalid_op();
    else if (binop.op == Operator::PLUS || binop.op == Operator::MINUS)
      binop.result_type = CreatePointer(*ptr.GetPointeeTy(), ptr.GetAS());
    else if (!compare && !logical)
      invalid_op();

    if (compare && other.IsIntTy() && other.GetSize() != 8) {
      if (other == rht) {
        create_int_cast(binop.right, CreateUInt64());
      } else {
        create_int_cast(binop.left, CreateUInt64());
      }
    }
  }
  // Might need an additional pass to resolve the type
  else if (other.IsNoneTy()) {
    if (is_final_pass()) {
      invalid_op();
    }
  }
  // Binop on a pointer and something else
  else {
    invalid_op();
  }
}

void SemanticAnalyser::visit(Binop &binop)
{
  visit(binop.left);
  visit(binop.right);

  const auto &lht = binop.left.type();
  const auto &rht = binop.right.type();
  bool lsign = binop.left.type().IsSigned();
  bool rsign = binop.right.type().IsSigned();
  bool is_int_binop = (lht.IsCastableMapTy() || lht.IsIntTy() ||
                       lht.IsBoolTy()) &&
                      (rht.IsCastableMapTy() || rht.IsIntTy() ||
                       rht.IsBoolTy());

  bool is_signed = lsign || rsign;
  bool is_comparison = is_comparison_op(binop.op);
  switch (binop.op) {
    case Operator::LEFT:
    case Operator::RIGHT:
      is_signed = lsign;
      break;
    default:
      break;
  }

  if (is_comparison) {
    binop.result_type = CreateBool();
  }

  if (lht.IsBoolTy() && rht.IsBoolTy()) {
    binop.result_type = CreateBool();
    return;
  }

  if (lht.IsPtrTy() || rht.IsPtrTy()) {
    binop_ptr(binop);
    return;
  }

  if (!is_comparison) {
    // Default type - will be overriden below as necessary
    binop.result_type = CreateInteger(64, is_signed);
  }

  auto addr_lhs = binop.left.type().GetAS();
  auto addr_rhs = binop.right.type().GetAS();

  // if lhs or rhs has different addrspace (not none), then set the
  // addrspace to none. This preserves the behaviour for x86.
  if (addr_lhs != addr_rhs && addr_lhs != AddrSpace::none &&
      addr_rhs != AddrSpace::none) {
    if (is_final_pass())
      binop.addWarning() << "Addrspace mismatch";
    binop.result_type.SetAS(AddrSpace::none);
  }
  // Associativity from left to right for binary operator
  else if (addr_lhs != AddrSpace::none) {
    binop.result_type.SetAS(addr_lhs);
  } else {
    // In case rhs is none, then this triggers warning in
    // selectProbeReadHelper.
    binop.result_type.SetAS(addr_rhs);
  }

  if (!is_final_pass()) {
    return;
  }

  if (is_int_binop) {
    binop_int(binop);
  } else if (lht.IsArrayTy() && rht.IsArrayTy()) {
    binop_array(binop);
  } else if (lht.IsPtrTy() || rht.IsPtrTy()) {
    // This case is caught earlier, just here for readability of the if/else
    // flow
  }
  // Compare type here, not the sized type as we it needs to work on strings
  // of different lengths
  else if (!lht.IsSameType(rht)) {
    auto &err = binop.addError();
    err << "Type mismatch for '" << opstr(binop) << "': comparing " << lht
        << " with " << rht;
    err.addContext(binop.left.loc()) << "left (" << lht << ")";
    err.addContext(binop.right.loc()) << "right (" << rht << ")";
  }
  // Also allow combination like reg("sp") + 8
  else if (binop.op != Operator::EQ && binop.op != Operator::NE) {
    binop.addError() << "The " << opstr(binop)
                     << " operator can not be used on expressions of types "
                     << lht << ", " << rht;
  }
}

void SemanticAnalyser::visit(Unop &unop)
{
  if (unop.op == Operator::PRE_INCREMENT ||
      unop.op == Operator::PRE_DECREMENT ||
      unop.op == Operator::POST_INCREMENT ||
      unop.op == Operator::POST_DECREMENT) {
    // Handle ++ and -- before visiting unop.expr, because these
    // operators should be able to work with undefined maps.
    if (auto *acc = unop.expr.as<MapAccess>()) {
      // Doing increments or decrements on the map type implements that
      // it is done on an integer. Maps are always coerced into larger
      // integers, so this should not conflict with different assignments.
      assign_map_type(*acc->map, CreateInt64(), acc->map);
    } else if (!unop.expr.is<Variable>()) {
      unop.addError() << "The " << opstr(unop)
                      << " operator must be applied to a map or variable";
    }
  }

  visit(unop.expr);

  auto valid_ptr_op = false;
  switch (unop.op) {
    case Operator::PRE_INCREMENT:
    case Operator::PRE_DECREMENT:
    case Operator::POST_INCREMENT:
    case Operator::POST_DECREMENT:
    case Operator::MUL:
      valid_ptr_op = true;
      break;
    default:;
  }

  const SizedType &type = unop.expr.type();
  if (is_final_pass()) {
    bool invalid = false;
    // Unops are only allowed on ints (e.g. ~$x), dereference only on pointers
    // and context (we allow args->field for backwards compatibility)
    if (type.IsBoolTy()) {
      invalid = unop.op != Operator::LNOT;
    } else if (!type.IsIntegerTy() &&
               !((type.IsPtrTy() || type.IsCtxAccess()) && valid_ptr_op)) {
      invalid = true;
    }
    if (invalid) {
      unop.addError() << "The " << opstr(unop)
                      << " operator can not be used on expressions of type '"
                      << type << "'";
    }
  }

  if (unop.op == Operator::MUL) {
    if (type.IsPtrTy()) {
      unop.result_type = SizedType(*type.GetPointeeTy());
      if (type.IsCtxAccess())
        unop.result_type.MarkCtxAccess();
      unop.result_type.is_internal = type.is_internal;
      unop.result_type.SetAS(type.GetAS());
    } else if (type.IsRecordTy()) {
      // We allow dereferencing "args" with no effect (for backwards compat)
      if (type.IsCtxAccess())
        unop.result_type = type;
      else {
        unop.addError() << "Can not dereference struct/union of type '"
                        << type.GetName() << "'. It is not a pointer.";
      }
    } else if (type.IsIntTy()) {
      unop.result_type = CreateUInt64();
    }
  } else if (unop.op == Operator::LNOT) {
    unop.result_type = CreateBool();
  } else if (type.IsPtrTy() && valid_ptr_op) {
    unop.result_type = unop.expr.type();
  } else {
    unop.result_type = CreateInteger(64, type.IsSigned());
  }

  if (unop.expr.is<Variable>() && unop.expr.type().IsIntegerTy()) {
    auto *variable = unop.expr.as<Variable>();
    if (auto *scope = find_variable_scope(variable->ident)) {
      auto &foundVar = variables_[scope][variable->ident];
      if (foundVar.can_resize) {
        // We don't know how many times this operation will be called
        // so just make it the largest possible int
        foundVar.type.SetSize(8);
      }
    }
  }
}

void SemanticAnalyser::visit(IfExpr &if_expr)
{
  // In order to evaluate literals and resolved type operators, we need to fold
  // the condition. This is handled in the `Expression` visitor. Branches that
  // are always `false` are exempted from semantic checks. If after folding the
  // condition still has unresolved `comptime` operators, then we are not able
  // to visit yet. These branches are also not allowed to contain information
  // necessary to resolve types, that is a cycle in the dependency graph, the
  // `if` condition must be resolvable first. If the condition *is* resolvable
  // and is a constant, then we prune the dead code paths and will never use
  // them for semantic analysis.
  if (auto *comptime = if_expr.cond.as<Comptime>()) {
    visit(comptime->expr);
    pass_tracker_.add_unresolved_branch(if_expr);
    return; // Skip visiting this `if` for now.
  }

  visit(if_expr.cond);
  visit(if_expr.left);
  visit(if_expr.right);

  const Type &cond = if_expr.cond.type().GetTy();
  const auto &lhs = if_expr.left.type();
  const auto &rhs = if_expr.right.type();

  if (!lhs.IsSameType(rhs)) {
    if (is_final_pass()) {
      if_expr.addError() << "Branches must return the same type: " << "have '"
                         << lhs << "' and '" << rhs << "'";
    }
    // This assignment is just temporary to prevent errors
    // before the final pass
    if_expr.result_type = lhs;
    return;
  }

  if (lhs.IsStack() && lhs.stack_type != rhs.stack_type) {
    // TODO: fix this for different stack types
    if_expr.addError() << "Branches must have the same stack type on the right "
                          "and left sides.";
    return;
  }

  if (is_final_pass() && cond != Type::integer && cond != Type::pointer &&
      cond != Type::boolean) {
    if_expr.addError() << "Invalid condition: " << cond;
    return;
  }

  bool type_mismatch_error = false;
  if (lhs.IsIntegerTy()) {
    auto updatedTy = update_int_type(rhs, if_expr.right, lhs, if_expr.left);
    if (!updatedTy) {
      type_mismatch_error = true;
    } else {
      if_expr.result_type = *updatedTy;
    }
  } else if (lhs.IsTupleTy()) {
    auto updatedTy = get_promoted_tuple(lhs, rhs);
    if (!updatedTy) {
      type_mismatch_error = true;
    } else {
      if (*updatedTy != lhs) {
        create_tuple_cast(if_expr.left, lhs, *updatedTy);
      }
      if (*updatedTy != rhs) {
        create_tuple_cast(if_expr.right, rhs, *updatedTy);
      }
      if_expr.result_type = *updatedTy;
    }
  } else {
    auto lsize = lhs.GetSize();
    auto rsize = rhs.GetSize();
    if_expr.result_type = lsize > rsize ? lhs : rhs;
  }

  if (is_final_pass() && type_mismatch_error) {
    if_expr.addError()
        << "Branches must return the same type or compatible types: "
        << "have '" << lhs << "' and '" << rhs << "'";
  }
}

void SemanticAnalyser::visit(Unroll &unroll)
{
  visit(unroll.expr);

  auto *integer = unroll.expr.as<Integer>();
  if (!integer) {
    unroll.addError() << "invalid unroll value";
    return;
  }

  if (integer->value > static_cast<uint64_t>(100)) {
    unroll.addError() << "unroll maximum value is 100";
  } else if (integer->value < static_cast<uint64_t>(1)) {
    unroll.addError() << "unroll minimum value is 1";
  }

  visit(unroll.block);
}

void SemanticAnalyser::visit(Jump &jump)
{
  if (jump.ident == JumpType::RETURN) {
    visit(jump.return_value);
    if (auto *subprog = dynamic_cast<Subprog *>(top_level_node_)) {
      const auto &ty = subprog->return_type->type();
      if (is_final_pass() && !ty.IsNoneTy() &&
          (ty.IsVoidTy() != !jump.return_value.has_value() ||
           (jump.return_value.has_value() &&
            jump.return_value->type() != ty))) {
        if (jump.return_value.has_value() &&
            jump.return_value->type().IsSameType(ty)) {
          // TODO: fix this for other types
          if (ty.IsIntegerTy()) {
            auto updatedTy = update_int_type(jump.return_value->type(),
                                             *jump.return_value,
                                             ty);
            if (updatedTy && updatedTy->IsEqual(ty)) {
              return;
            }
          }
        }
        jump.addError() << "Function " << subprog->name << " is of type " << ty
                        << ", cannot return "
                        << (jump.return_value.has_value()
                                ? jump.return_value->type()
                                : CreateVoid());
      }
    }
  }
}

void SemanticAnalyser::visit(While &while_block)
{
  visit(while_block.cond);

  loop_depth_++;
  visit(while_block.block);
  loop_depth_--;
}

void SemanticAnalyser::visit(For &f)
{
  if (f.iterable.is<Range>() && !bpftrace_.feature_->has_helper_loop()) {
    f.addError() << "Missing required kernel feature: loop";
  }
  if (auto *map = f.iterable.as<Map>()) {
    if (!is_first_pass() && !map_val_.contains(map->ident)) {
      map->addError() << "Undefined map: " << map->ident;
    }
    if (map_metadata_.bad_iterator.contains(map)) {
      map->addError() << map->ident
                      << " has no explicit keys (scalar map), and "
                         "cannot be used for iteration";
    }
  }

  // For-loops are implemented using the bpf_for_each_map_elem or bpf_loop
  // helper functions, which requires them to be rewritten into a callback
  // style.
  //
  // Pseudo code for the transformation we apply:
  //
  // Before:
  //     PROBE {
  //       @map[0] = 1;
  //       for ($kv : @map) {
  //         [LOOP BODY]
  //       }
  //     }
  //
  // After:
  //     PROBE {
  //       @map[0] = 1;
  //       bpf_for_each_map_elem(@map, &map_for_each_cb, 0, 0);
  //     }
  //     long map_for_each_cb(bpf_map *map,
  //                          const void *key,
  //                          void *value,
  //                          void *ctx) {
  //       $kv = ((uint64)key, (uint64)value);
  //       [LOOP BODY]
  //     }
  //
  //
  // To allow variables to be shared between the loop callback and the main
  // program, some extra steps are taken:
  //
  // 1. Determine which variables need to be shared with the loop callback
  // 2. Pack pointers to them into a context struct
  // 3. Pass pointer to the context struct to the callback function
  // 4. In the callback, override the shared variables so that they read and
  //    write through the context pointers instead of directly from their
  //    original addresses
  //
  // Example transformation with context:
  //
  // Before:
  //     PROBE {
  //       $str = "hello";
  //       $not_shared = 2;
  //       $len = 0;
  //       @map[11, 12] = "c";
  //       for ($kv : @map) {
  //         print($str);
  //         $len++;
  //       }
  //       print($len);
  //       print($not_shared);
  //     }
  //
  // After:
  //     struct ctx_t {
  //       string *str;
  //       uint64 *len;
  //     };
  //     PROBE {
  //       $str = "hello";
  //       $not_shared = 2;
  //       $len = 0;
  //       @map[11, 12] = "c";
  //
  //       ctx_t ctx { .str = &$str, .len = &$len };
  //       bpf_for_each_map_elem(@map, &map_for_each_cb, &ctx, 0);
  //
  //       print($len);
  //       print($not_shared);
  //     }
  //     long map_for_each_cb(bpf_map *map,
  //                          const void *key,
  //                          void *value,
  //                          void *ctx) {
  //       $kv = (((uint64, uint64))key, (string)value);
  //       $str = ((ctx_t*)ctx)->str;
  //       $len = ((ctx_t*)ctx)->len;
  //
  //       print($str);
  //       $len++;
  //     }

  // Validate decl.
  const auto &decl_name = f.decl->ident;
  if (find_variable(decl_name)) {
    f.decl->addError() << "Loop declaration shadows existing variable: " +
                              decl_name;
  }

  visit(f.iterable);

  // Validate the iterable.
  if (auto *map = f.iterable.as<Map>()) {
    if (!map->type().IsMapIterableTy()) {
      map->addError() << "Loop expression does not support type: "
                      << map->type();
    }
  } else if (auto *range = f.iterable.as<Range>()) {
    if (is_final_pass()) {
      if (!range->start.type().IsIntTy()) {
        range->addError()
            << "Loop range requires an integer for the start value";
      }
      if (!range->end.type().IsIntTy()) {
        range->addError() << "Loop range requires an integer for the end value";
      }
    }
  }

  if (!ctx_.diagnostics().ok()) {
    return;
  }

  // Collect a list of unique variables which are referenced in the loop's
  // body and declared before the loop. These will be passed into the loop
  // callback function as the context parameter.
  std::unordered_set<std::string> found_vars;
  // Only do this on the first pass because variables declared later
  // in a script will get added to the outer scope, which these do not
  // reference e.g.
  // begin { @a[1] = 1; for ($kv : @a) { $x = 2; } let $x; }
  if (is_first_pass()) {
    // We save these for potential use at the end of this function in
    // subsequent passes in case the map we're iterating over isn't ready
    // yet and still needs additional passes to resolve its key/value types
    // e.g. begin { $x = 1; for ($kv : @a) { print(($x)); } @a[1] = 1; }
    //
    // This is especially tricky because we need to visit all statements
    // inside the for loop to get the types of the referenced variables but
    // only after we have the map's key/value type so we can also check
    // the usages of the created $kv tuple variable.
    auto [iter, _] = for_vars_referenced_.try_emplace(&f);
    auto &collector = iter->second;
    collector.visit(f.block, [this, &found_vars](const auto &var) {
      if (found_vars.contains(var.ident))
        return false;

      if (find_variable(var.ident)) {
        found_vars.insert(var.ident);
        return true;
      }
      return false;
    });
  }

  // Create type for the loop's decl.
  if (auto *map = f.iterable.as<Map>()) {
    // Iterating over a map provides a tuple: (map_key, map_val)
    auto *mapkey = get_map_key_type(*map);
    auto *mapval = get_map_type(*map);

    if (!mapkey || !mapval)
      return;

    f.decl->var_type = CreateTuple(Struct::CreateTuple({ *mapkey, *mapval }));
  } else if (auto *range = f.iterable.as<Range>()) {
    if (range->start.type().IsIntTy() && range->end.type().IsIntTy()) {
      if (range->start.type().GetSize() > range->end.type().GetSize()) {
        create_int_cast(range->end, range->start.type());
      } else if (range->start.type().GetSize() < range->end.type().GetSize()) {
        create_int_cast(range->start, range->end.type());
      }
    }
    f.decl->var_type = range->start.type();
  }

  scope_stack_.push_back(&f);

  variables_[scope_stack_.back()][decl_name] = { .type = f.decl->type(),
                                                 .can_resize = true,
                                                 .was_assigned = true };

  loop_depth_++;
  visit(f.block);
  loop_depth_--;

  scope_stack_.pop_back();

  // Currently, we do not pass BPF context to the callback so disable builtins
  // which require ctx access.
  CollectNodes<Builtin> builtins;
  builtins.visit(f.block);
  for (const Builtin &builtin : builtins.nodes()) {
    if (builtin.builtin_type.IsCtxAccess() || builtin.is_argx() ||
        builtin.ident == "__builtin_retval") {
      builtin.addError() << "'" << builtin.ident
                         << "' builtin is not allowed in a for-loop";
    }
  }

  // Finally, create the context tuple now that all variables inside the loop
  // have been visited.
  std::vector<SizedType> ctx_types;
  std::vector<std::string_view> ctx_idents;
  auto [iter, _] = for_vars_referenced_.try_emplace(&f);
  auto &collector = iter->second;
  for (const Variable &var : collector.nodes()) {
    ctx_types.push_back(CreatePointer(var.var_type, AddrSpace::kernel));
    ctx_idents.push_back(var.ident);
  }
  f.ctx_type = CreateRecord(Struct::CreateRecord(ctx_types, ctx_idents));
}

void SemanticAnalyser::visit(FieldAccess &acc)
{
  visit(acc.expr);

  // FieldAccesses will automatically resolve through any number of pointer
  // dereferences. For now, we inject the `Unop` operator directly, as codegen
  // stores the underlying structs as pointers anyways. In the future, we will
  // likely want to do this in a different way if we are tracking l-values.
  while (acc.expr.type().IsPtrTy()) {
    auto *unop = ctx_.make_node<Unop>(acc.expr.node().loc,
                                      acc.expr,
                                      Operator::MUL);
    acc.expr.value = unop;
    visit(acc.expr);
  }

  const SizedType &type = acc.expr.type();

  if (type.IsPtrTy()) {
    acc.addError() << "Can not access field '" << acc.field << "' on type '"
                   << type << "'. Try dereferencing it first, or using '->'";
    return;
  }

  if (!type.IsRecordTy()) {
    if (is_final_pass()) {
      acc.addError() << "Can not access field '" << acc.field
                     << "' on expression of type '" << type << "'";
    }
    return;
  }

  if (type.is_funcarg) {
    auto *probe = get_probe(acc);
    if (probe == nullptr)
      return;
    const auto *arg = bpftrace_.structs.GetProbeArg(*probe, acc.field);
    if (arg) {
      acc.field_type = arg->type;
      acc.field_type.SetAS(acc.expr.type().GetAS());

      if (is_final_pass() && acc.field_type.IsNoneTy()) {
        acc.addError() << acc.field << " has unsupported type";
      }
    } else {
      acc.addError() << "Can't find function parameter " << acc.field;
    }
    return;
  }

  if (!bpftrace_.structs.Has(type.GetName())) {
    acc.addError() << "Unknown struct/union: '" << type.GetName() << "'";
    return;
  }

  std::string cast_type = type.GetName();
  const auto &record = type.GetStruct();

  if (!record->HasField(acc.field)) {
    acc.addError() << "Struct/union of type '" << cast_type
                   << "' does not contain " << "a field named '" << acc.field
                   << "'";
  } else {
    const auto &field = record->GetField(acc.field);

    if (field.type.IsPtrTy()) {
      const auto &tags = field.type.GetBtfTypeTags();
      // Currently only "rcu" is safe. "percpu", for example, requires
      // special unwrapping with `bpf_per_cpu_ptr` which is not yet
      // supported.
      static const std::string_view allowed_tag = "rcu";
      for (const auto &tag : tags) {
        if (tag != allowed_tag) {
          acc.addError() << "Attempting to access pointer field '" << acc.field
                         << "' with unsupported tag attribute: " << tag;
        }
      }
    }

    acc.field_type = field.type;
    if (acc.expr.type().IsCtxAccess() &&
        (acc.field_type.IsArrayTy() || acc.field_type.IsRecordTy())) {
      // e.g., ((struct bpf_perf_event_data*)ctx)->regs.ax
      acc.field_type.MarkCtxAccess();
    }
    acc.field_type.is_internal = type.is_internal;
    acc.field_type.SetAS(acc.expr.type().GetAS());

    // The kernel uses the first 8 bytes to store `struct pt_regs`. Any
    // access to the first 8 bytes results in verifier error.
    if (is_tracepoint_struct(type.GetName()) && field.offset < 8)
      acc.addError()
          << "BPF does not support accessing common tracepoint fields";
  }
}

void SemanticAnalyser::visit(MapAccess &acc)
{
  if (map_metadata_.bad_scalar_access.contains(acc.map)) {
    acc.addError() << acc.map->ident
                   << " used as a map with an explicit key (non-scalar map), "
                      "previously used without an explicit key (scalar map)";
    return;
  }

  visit(acc.map);
  visit(acc.key);
  reconcile_map_key(acc.map, acc.key);

  auto search_val = map_val_.find(acc.map->ident);
  if (search_val != map_val_.end()) {
    if (acc.map->type().IsCastableMapTy() &&
        !bpftrace_.feature_->has_helper_map_lookup_percpu_elem()) {
      acc.addError()
          << "Missing required kernel feature: map_lookup_percpu_elem";
    }
    acc.map->value_type = search_val->second;
  } else {
    // If there is no record of any assignment after the first pass
    // then it's safe to say this map is undefined.
    bool read_only = named_param_defaults_.defaults.contains(acc.map->ident);
    if (!is_first_pass() && !read_only) {
      acc.addError() << "Undefined map: " << acc.map->ident;
    }
    pass_tracker_.inc_num_unresolved();
  }
}

void SemanticAnalyser::reconcile_map_key(Map *map, Expression &key_expr)
{
  SizedType new_key_type = create_key_type(key_expr.type(), key_expr.node());

  if (const auto &key = map_key_.find(map->ident); key != map_key_.end()) {
    SizedType &storedTy = key->second;
    bool type_mismatch_error = false;
    if (!storedTy.IsSameType(new_key_type)) {
      type_mismatch_error = true;
    } else {
      if (storedTy.IsStringTy()) {
        if (storedTy.GetSize() > new_key_type.GetSize()) {
          create_string_cast(key_expr, storedTy);
        } else {
          storedTy.SetSize(new_key_type.GetSize());
        }
      } else if (storedTy.IsTupleTy()) {
        auto updatedTy = get_promoted_tuple(storedTy, new_key_type);
        if (!updatedTy) {
          type_mismatch_error = true;
        } else {
          if (*updatedTy != new_key_type) {
            create_tuple_cast(key_expr, new_key_type, *updatedTy);
          }
          storedTy = *updatedTy;
        }
      } else if (storedTy.IsIntegerTy()) {
        auto updatedTy = update_int_type(new_key_type, key_expr, storedTy);
        if (!updatedTy) {
          type_mismatch_error = true;
        } else {
          storedTy = *updatedTy;
        }
      }
    }
    if (type_mismatch_error) {
      key_expr.node().addError()
          << "Argument mismatch for " << map->ident << ": "
          << "trying to access with arguments: '" << new_key_type
          << "' when map expects arguments: '" << storedTy << "'";
    }
  } else {
    if (!new_key_type.IsNoneTy()) {
      map_key_.insert({ map->ident, new_key_type });
      map->key_type = new_key_type;
    }
  }
}

// We can't hint for unsigned types. It is a syntax error,
// because the word "unsigned" is not allowed in a type name.
static std::unordered_map<std::string_view, std::string_view>
    KNOWN_TYPE_ALIASES{
      { "char", "int8" },   /* { "unsigned char", "uint8" }, */
      { "short", "int16" }, /* { "unsigned short", "uint16" }, */
      { "int", "int32" },   /* { "unsigned int", "uint32" }, */
      { "long", "int64" },  /* { "unsigned long", "uint64" }, */
    };

void SemanticAnalyser::visit(Cast &cast)
{
  visit(cast.expr);
  visit(cast.typeof);

  const auto &resolved_ty = cast.type();
  if (resolved_ty.IsNoneTy()) {
    pass_tracker_.inc_num_unresolved();
    if (is_final_pass()) {
      cast.addError() << "Incomplete cast, unknown type";
    }
    return; // Revisit next cycle.
  }

  auto rhs = cast.expr.type();
  if (rhs.IsRecordTy()) {
    cast.addError() << "Cannot cast from struct type \"" << cast.expr.type()
                    << "\"";
  } else if (rhs.IsNoneTy()) {
    if (is_final_pass()) {
      cast.addError() << "Cannot cast from \"" << cast.expr.type() << "\" type";
    } else {
      return; // Revisit later.
    }
  }

  // Resolved the type because we may mutate it below, for various reasons.
  cast.typeof->record = resolved_ty;
  auto &ty = std::get<SizedType>(cast.typeof->record);

  if (ty.IsStringTy() && rhs.IsStringTy()) {
    if (ty.GetSize() < rhs.GetSize()) {
      cast.addError() << "Cannot cast from \"" << rhs << "\" to \"" << ty
                      << "\"";
    }
    return;
  }

  if (!ty.IsIntTy() && !ty.IsPtrTy() && !ty.IsBoolTy() &&
      (!ty.IsPtrTy() || ty.GetElementTy()->IsIntTy() ||
       ty.GetElementTy()->IsRecordTy()) &&
      // we support casting integers to int arrays
      !(ty.IsArrayTy() && ty.GetElementTy()->IsBoolTy()) &&
      !(ty.IsArrayTy() && ty.GetElementTy()->IsIntTy())) {
    auto &err = cast.addError();
    err << "Cannot cast to \"" << ty << "\"";
    if (ty.IsRecordTy() || ty.IsEnumTy()) {
      if (auto it = KNOWN_TYPE_ALIASES.find(ty.GetName());
          it != KNOWN_TYPE_ALIASES.end()) {
        err.addHint() << "Did you mean \"" << it->second << "\"?";
      }
    }
  }

  if (ty.IsArrayTy()) {
    if (ty.GetNumElements() == 0) {
      if (ty.GetElementTy()->GetSize() == 0)
        cast.addError() << "Could not determine size of the array";
      else {
        if (rhs.GetSize() % ty.GetElementTy()->GetSize() != 0) {
          cast.addError() << "Cannot determine array size: the element size is "
                             "incompatible with the cast integer size";
        }

        // cast to unsized array (e.g. int8[]), determine size from RHS
        auto num_elems = rhs.GetSize() / ty.GetElementTy()->GetSize();
        ty = CreateArray(num_elems, *ty.GetElementTy());
      }
    }

    if (rhs.IsIntTy() || rhs.IsBoolTy())
      ty.is_internal = true;
  }

  if (ty.IsEnumTy()) {
    if (!c_definitions_.enum_defs.contains(ty.GetName())) {
      cast.addError() << "Unknown enum: " << ty.GetName();
    } else {
      if (auto *integer = cast.expr.as<Integer>()) {
        if (!c_definitions_.enum_defs[ty.GetName()].contains(integer->value)) {
          cast.addError() << "Enum: " << ty.GetName()
                          << " doesn't contain a variant value of "
                          << integer->value;
        }
      }
    }
  }

  if (ty.IsBoolTy() && !rhs.IsIntTy() && !rhs.IsStringTy() && !rhs.IsPtrTy() &&
      !rhs.IsCastableMapTy()) {
    if (is_final_pass()) {
      cast.addError() << "Cannot cast from \"" << rhs << "\" to \"" << ty
                      << "\"";
    }
  }

  if ((ty.IsIntTy() && !rhs.IsIntTy() && !rhs.IsPtrTy() && !rhs.IsBoolTy() &&
       !rhs.IsCtxAccess() && !rhs.IsArrayTy() && !rhs.IsCastableMapTy()) ||
      (ty.IsArrayTy() && (!rhs.IsBoolTy() || ty.GetSize() != rhs.GetSize()) &&
       !rhs.IsIntTy()) ||
      (rhs.IsArrayTy() && (!ty.IsIntTy() || ty.GetSize() != rhs.GetSize()))) {
    cast.addError() << "Cannot cast from \"" << rhs << "\" to \"" << ty << "\"";
  }

  if (ty.IsArrayTy() && rhs.IsIntTy() &&
      (ty.GetElementTy()->IsIntegerTy() || ty.GetElementTy()->IsBoolTy())) {
    if ((ty.GetSize() <= 8) && (ty.GetSize() > rhs.GetSize())) {
      create_int_cast(cast.expr,
                      CreateInteger(ty.GetSize() * 8,
                                    ty.GetElementTy()->IsSigned()));
    } else if (ty.GetSize() != rhs.GetSize()) {
      cast.addError() << "Cannot cast from \"" << rhs << "\" to \"" << ty
                      << "\"";
    }
  }

  if (cast.expr.type().IsCtxAccess() && !ty.IsIntTy()) {
    ty.MarkCtxAccess();
  }
  ty.SetAS(cast.expr.type().GetAS());
  // case : begin { @foo = (struct Foo)0; }
  // case : profile:hz:99 $task = (struct task_struct *)curtask.
  if (ty.GetAS() == AddrSpace::none) {
    if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
      ProbeType type = probe->get_probetype();
      ty.SetAS(find_addrspace(type));
    } else {
      // Assume kernel space for data in subprogs.
      ty.SetAS(AddrSpace::kernel);
    }
  }
}

void SemanticAnalyser::visit(Tuple &tuple)
{
  std::vector<SizedType> elements;
  for (auto &elem : tuple.elems) {
    visit(elem);

    // If elem type is none that means that the tuple is not yet resolved.
    if (elem.type().IsNoneTy()) {
      pass_tracker_.inc_num_unresolved();
      return;
    } else if (elem.type().IsMultiKeyMapTy()) {
      elem.node().addError()
          << "Map type " << elem.type() << " cannot exist inside a tuple.";
    }
    elements.emplace_back(elem.type());
  }

  tuple.tuple_type = CreateTuple(Struct::CreateTuple(elements));
}

void SemanticAnalyser::visit(Expression &expr)
{
  // Visit and fold all other values.
  Visitor<SemanticAnalyser>::visit(expr);
  fold(ctx_, expr);

  // Inline specific constant expressions.
  if (auto *szof = expr.as<Sizeof>()) {
    const auto v = check(*szof);
    if (v) {
      expr.value = ctx_.make_node<Integer>(Location(szof->loc), *v);
    }
  } else if (auto *offof = expr.as<Offsetof>()) {
    const auto v = check(*offof);
    if (v) {
      expr.value = ctx_.make_node<Integer>(Location(offof->loc), *v);
    }
  } else if (auto *type_id = expr.as<Typeinfo>()) {
    const auto &ty = type_id->typeof->type();
    if (!ty.IsNoneTy()) {
      // We currently lack a globally-unique enumeration of types. For
      // simplicity, just use the type string with a placeholder identifier.
      auto *id = ctx_.make_node<Integer>(type_id->loc, 0);
      auto *base_ty = ctx_.make_node<String>(type_id->loc,
                                             to_string(ty.GetTy()));
      auto *full_ty = ctx_.make_node<String>(type_id->loc, typestr(ty));
      expr.value = ctx_.make_node<Tuple>(
          type_id->loc, ExpressionList{ id, base_ty, full_ty });
    }
  } else if (auto *binop = expr.as<Binop>()) {
    if (binop->left.type().IsTupleTy() &&
        binop->left.type().IsSameType(binop->right.type()) &&
        (binop->op == Operator::EQ || binop->op == Operator::NE)) {
      const auto &lht = binop->left.type();
      const auto &rht = binop->right.type();
      auto updatedTy = get_promoted_tuple(lht, rht);
      if (!updatedTy) {
        binop->addError() << "Type mismatch for '" << opstr(*binop)
                          << "': comparing " << lht << " with " << rht;
      } else {
        if (*updatedTy != lht) {
          create_tuple_cast(binop->left, lht, *updatedTy);
        }
        if (*updatedTy != rht) {
          create_tuple_cast(binop->right, rht, *updatedTy);
        }
        auto *size = ctx_.make_node<Integer>(binop->loc,
                                             updatedTy->GetSize(),
                                             CreateUInt64());
        auto *call = ctx_.make_node<Call>(
            binop->loc,
            "memcmp",
            ExpressionList{ binop->left, binop->right, size });
        auto *typeof = ctx_.make_node<Typeof>(binop->loc, CreateBool());
        auto *cast = ctx_.make_node<Cast>(binop->loc, typeof, call);
        if (binop->op == Operator::NE) {
          expr.value = cast;
        } else {
          expr.value = ctx_.make_node<Unop>(binop->loc, cast, Operator::LNOT);
        }
        expand_macro(ctx_, expr, macro_registry_);
      }
    }
  }
}

void SemanticAnalyser::visit(ExprStatement &expr)
{
  visit(expr.expr);

  if (is_final_pass() &&
      !(expr.expr.type().IsNoneTy() || expr.expr.type().IsVoidTy())) {
    expr.addWarning() << "Return value discarded.";
  }
}

static const std::unordered_map<Type, std::string_view> AGGREGATE_HINTS{
  { Type::count_t, "count()" },
  { Type::sum_t, "sum(retval)" },
  { Type::min_t, "min(retval)" },
  { Type::max_t, "max(retval)" },
  { Type::avg_t, "avg(retval)" },
  { Type::hist_t, "hist(retval)" },
  { Type::lhist_t, "lhist(rand %10, 0, 10, 1)" },
  { Type::tseries_t, "tseries(rand %10, 10s, 1)" },
  { Type::stats_t, "stats(arg2)" },
};

void SemanticAnalyser::visit(AssignMapStatement &assignment)
{
  visit(assignment.map_access);
  visit(assignment.expr);

  reconcile_map_key(assignment.map_access->map, assignment.map_access->key);
  const auto *map_type_before = get_map_type(*assignment.map_access->map);

  // Add an implicit cast when copying the value of an aggregate map to an
  // existing map of int. Enables the following: `@x = 1; @y = count(); @x =
  // @y`
  const bool map_contains_int = map_type_before && map_type_before->IsIntTy();
  if (map_contains_int && assignment.expr.type().IsCastableMapTy()) {
    auto *typeof = ctx_.make_node<Typeof>(assignment.loc, *map_type_before);
    assignment.expr = ctx_.make_node<Cast>(assignment.loc,
                                           typeof,
                                           assignment.expr);
  }

  if (!is_valid_assignment(assignment.expr, map_type_before == nullptr)) {
    auto &err = assignment.addError();
    const auto &type = assignment.expr.type();
    auto hint = AGGREGATE_HINTS.find(type.GetTy());
    if (hint == AGGREGATE_HINTS.end()) {
      err << "Not a valid assignment: " << type.GetTy();
    } else {
      err << "Map value '" << type
          << "' cannot be assigned from one map to another. "
             "The function that returns this type must be called directly "
             "e.g. "
             "`"
          << assignment.map_access->map->ident << " = " << hint->second
          << ";`.";

      if (const auto *acc = assignment.expr.as<MapAccess>()) {
        if (type.IsCastableMapTy()) {
          err.addHint() << "Add a cast to integer if you want the value of the "
                           "aggregate, "
                        << "e.g. `" << assignment.map_access->map->ident
                        << " = (int64)" << acc->map->ident << ";`.";
        }
      }
    }
  }

  assign_map_type(*assignment.map_access->map,
                  assignment.expr.type(),
                  &assignment,
                  &assignment);

  const auto &map_ident = assignment.map_access->map->ident;
  const auto &type = assignment.expr.type();

  if (type.IsRecordTy() && map_val_[map_ident].IsRecordTy()) {
    std::string ty = assignment.expr.type().GetName();
    std::string stored_ty = map_val_[map_ident].GetName();
    if (!stored_ty.empty() && stored_ty != ty) {
      assignment.addError() << "Type mismatch for " << map_ident << ": "
                            << "trying to assign value of type '" << ty
                            << "' when map already contains a value of type '"
                            << stored_ty << "'";
    } else {
      map_val_[map_ident] = assignment.expr.type();
      map_val_[map_ident].is_internal = true;
    }
  } else if (type.IsStringTy()) {
    auto map_size = map_val_[map_ident].GetSize();
    auto expr_size = assignment.expr.type().GetSize();
    if (map_size < expr_size) {
      assignment.addWarning() << "String size mismatch: " << map_size << " < "
                              << expr_size << ". The value may be truncated.";
    }
  } else if (type.IsBufferTy()) {
    auto map_size = map_val_[map_ident].GetSize();
    auto expr_size = assignment.expr.type().GetSize();
    if (map_size != expr_size) {
      std::stringstream buf;
      buf << "Buffer size mismatch: " << map_size << " != " << expr_size << ".";
      if (map_size < expr_size) {
        buf << " The value may be truncated.";
        assignment.addWarning() << buf.str();
      } else {
        // bpf_map_update_elem() expects map_size-length value
        assignment.addError() << buf.str();
      }
    }
  } else if (type.IsCtxAccess()) {
    // bpf_map_update_elem() only accepts a pointer to a element in the stack
    assignment.addError() << "context cannot be assigned to a map";
  } else if (type.IsArrayTy()) {
    const auto &map_type = map_val_[map_ident];
    const auto &expr_type = assignment.expr.type();
    if (map_type == expr_type) {
      map_val_[map_ident].is_internal = true;
    } else {
      assignment.addError()
          << "Array type mismatch: " << map_type << " != " << expr_type << ".";
    }
  } else if (type.IsNoneTy()) {
    pass_tracker_.inc_num_unresolved();
  }
}

void SemanticAnalyser::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);

  // Only visit the declaration if it is a `let` declaration,
  // otherwise skip as it is not a variable access.
  if (std::holds_alternative<VarDeclStatement *>(assignment.var_decl)) {
    visit(assignment.var_decl);
  }

  if (assignment.expr.type().IsCastableMapTy()) {
    auto *typeof = ctx_.make_node<Typeof>(assignment.loc, CreateInt64());
    assignment.expr = ctx_.make_node<Cast>(assignment.loc,
                                           typeof,
                                           assignment.expr);
  }

  if (!is_valid_assignment(assignment.expr, false)) {
    if (is_final_pass()) {
      assignment.addError() << "Value '" << assignment.expr.type()
                            << "' cannot be assigned to a scratch variable.";
    }
    return;
  }

  Node *var_scope = nullptr;
  const auto &var_ident = assignment.var()->ident;
  auto assignTy = assignment.expr.type();

  if (auto *scope = find_variable_scope(var_ident)) {
    auto &foundVar = variables_[scope][var_ident];
    auto &storedTy = foundVar.type;
    bool type_mismatch_error = false;
    if (storedTy.IsNoneTy()) {
      storedTy = assignTy;
    } else if (!storedTy.IsSameType(assignTy) &&
               (!storedTy.IsIntegerTy() || !assignTy.IsIntegerTy())) {
      if (!assignTy.IsNoneTy() || is_final_pass()) {
        type_mismatch_error = true;
      } else {
        pass_tracker_.inc_num_unresolved();
      }
    } else if (assignTy.IsStringTy()) {
      if (assignTy.GetSize() > storedTy.GetSize()) {
        if (foundVar.can_resize) {
          storedTy.SetSize(assignTy.GetSize());
        } else {
          type_mismatch_error = true;
        }
      } else {
        create_string_cast(assignment.expr, storedTy);
      }
    } else if (storedTy.IsIntegerTy()) {
      auto updatedTy = update_int_type(assignTy, assignment.expr, storedTy);
      if (!updatedTy ||
          (!updatedTy->IsEqual(storedTy) && !foundVar.can_resize)) {
        type_mismatch_error = true;
      } else {
        storedTy = *updatedTy;
        assignTy = *updatedTy;
      }
    } else if (assignTy.IsBufferTy()) {
      auto var_size = storedTy.GetSize();
      auto expr_size = assignTy.GetSize();
      if (var_size != expr_size) {
        assignment.addWarning()
            << "Buffer size mismatch: " << var_size << " != " << expr_size
            << (var_size < expr_size ? ". The value may be truncated."
                                     : ". The value may contain garbage.");
      }
    } else if (assignTy.IsTupleTy()) {
      auto updatedTy = get_promoted_tuple(storedTy, assignTy);
      if (!updatedTy || (*updatedTy != storedTy && !foundVar.can_resize)) {
        type_mismatch_error = true;
      } else {
        if (*updatedTy != assignTy) {
          create_tuple_cast(assignment.expr, assignTy, *updatedTy);
        }
        storedTy = *updatedTy;
        assignTy = *updatedTy;
      }
    }
    if (type_mismatch_error && is_final_pass()) {
      const auto *err_segment =
          foundVar.was_assigned
              ? "when variable already contains a value of type"
              : "when variable already has a type";
      assignment.addError() << "Type mismatch for " << var_ident << ": "
                            << "trying to assign value of type '" << assignTy
                            << "' " << err_segment << " '" << storedTy << "'";
    } else {
      if (!foundVar.was_assigned) {
        // The assign type is possibly more complete than the stored type,
        // which could come from a variable declaration. The assign type may
        // resolve builtins like `curtask` which also specifies the address
        // space.
        if (assignTy.GetSize() < storedTy.GetSize()) {
          assignTy.SetSize(storedTy.GetSize());
        }
        foundVar.type = assignTy;
        foundVar.was_assigned = true;
      }
      var_scope = scope;
    }
  }

  if (var_scope == nullptr) {
    variables_[scope_stack_.back()].insert(
        { var_ident,
          { .type = assignTy, .can_resize = true, .was_assigned = true } });
    var_scope = scope_stack_.back();
  }

  const auto &storedTy = variables_[var_scope][var_ident].type;
  assignment.var()->var_type = storedTy;

  if (is_final_pass()) {
    if (storedTy.IsNoneTy())
      assignment.addError()
          << "Invalid expression for assignment: " << storedTy;
  }
}

void SemanticAnalyser::visit(VarDeclStatement &decl)
{
  visit(decl.typeof);
  const std::string &var_ident = decl.var->ident;

  if (decl.typeof) {
    const auto &ty = decl.typeof->type();
    if (!ty.IsNoneTy()) {
      if (!IsValidVarDeclType(ty)) {
        decl.addError() << "Invalid variable declaration type: " << ty;
      } else {
        decl.var->var_type = ty;
      }
    } else if (is_final_pass()) {
      // We couldn't resolve that specific type by now.
      decl.addError() << "Type cannot be resolved: still none";
    }
  }

  // Only checking on the first pass for cases like this:
  // `begin { if (1) { let $x; } else { let $x; } let $x; }`
  // Notice how the last `let $x` is defined in the outer scope;
  // this means on subsequent passes the first two `let $x` statements
  // would be considered variable shadowing, when in fact, because of order,
  // there is no ambiguity in terms of future assignment and use.
  if (is_first_pass()) {
    for (auto *scope : scope_stack_) {
      // This should be the first time we're seeing this variable
      if (auto decl_search = variable_decls_[scope].find(var_ident);
          decl_search != variable_decls_[scope].end()) {
        if (&decl_search->second != &decl) {
          decl.addError()
              << "Variable " << var_ident
              << " was already declared. Variable shadowing is not allowed.";
          decl_search->second.addWarning()
              << "This is the initial declaration.";
        }
      }
    }
  }

  if (is_first_pass() || is_final_pass()) {
    if (auto *scope = find_variable_scope(var_ident)) {
      auto &foundVar = variables_[scope][var_ident];
      // Checking the first pass only for cases like this:
      // `begin { if (1) { let $x; } $x = 2; }`
      // Again, this is legal and there is no ambiguity but `$x = 2` gets
      // placed in the outer scope so subsequent passes would consider
      // this a use before declaration error (below)
      if (!variable_decls_[scope].contains(var_ident) && is_first_pass()) {
        decl.addError()
            << "Variable declarations need to occur before variable usage or "
               "assignment. Variable: "
            << var_ident;
      } else if (is_final_pass()) {
        if (!decl.typeof || (decl.typeof->type().IsNoneTy() ||
                             decl.typeof->type().GetSize() == 0)) {
          // Update the declaration type if it was either not set e.g. `let $a;`
          // or the type is ambiguous or resizable e.g. `let $a: string;`
          decl.var->var_type = foundVar.type;
        } else {
          foundVar.type = decl.var->var_type;
        }
      }

      if (is_final_pass() && !foundVar.was_assigned) {
        decl.addWarning() << "Variable " << var_ident << " never assigned to.";
      }

      return;
    }
  }

  bool can_resize = decl.var->var_type.GetSize() == 0;

  variables_[scope_stack_.back()].insert({ var_ident,
                                           { .type = decl.var->var_type,
                                             .can_resize = can_resize,
                                             .was_assigned = false } });
  variable_decls_[scope_stack_.back()].insert({ var_ident, decl });
}

void SemanticAnalyser::visit(BlockExpr &block)
{
  scope_stack_.push_back(&block);
  visit(block.stmts);
  visit(block.expr);
  scope_stack_.pop_back();
}

void SemanticAnalyser::visit(Probe &probe)
{
  top_level_node_ = &probe;
  visit(probe.attach_points);
  visit(probe.block);
}

void SemanticAnalyser::visit(Subprog &subprog)
{
  // Note that we visit the subprogram and process arguments *after*
  // constructing the stack with the variable states. This is because the
  // arguments, etc. may have types defined in terms of the arguments
  // themselves. We already handle detecting circular dependencies.
  scope_stack_.push_back(&subprog);
  top_level_node_ = &subprog;
  for (SubprogArg *arg : subprog.args) {
    const auto &ty = arg->typeof->type();
    auto &var = variables_[scope_stack_.back()]
                    .emplace(arg->var->ident,
                             variable{ .type = ty,
                                       .can_resize = true,
                                       .was_assigned = true })
                    .first->second;
    var.type = ty; // Override in case it has changed.
  }

  // Validate that arguments are set.
  visit(subprog.args);
  for (SubprogArg *arg : subprog.args) {
    if (arg->typeof->type().IsNoneTy()) {
      pass_tracker_.inc_num_unresolved();
      if (is_final_pass()) {
        arg->addError() << "Unable to resolve argument type.";
      }
    }
  }

  // Visit all statements.
  visit(subprog.block);

  // Validate that the return type is valid.
  visit(subprog.return_type);
  if (subprog.return_type->type().IsNoneTy()) {
    pass_tracker_.inc_num_unresolved();
    if (is_final_pass()) {
      subprog.return_type->addError()
          << "Unable to resolve suitable return type.";
    }
  }
  scope_stack_.pop_back();
}

void SemanticAnalyser::visit(Comptime &comptime)
{
  // If something has not been resolved here, then we fail. Calls, variables,
  // maps and other stateful things should be trapped by the fold pass itself,
  // but there may just be statements that are not yet supported there, e.g.
  // `comptime { unroll(5) { } }`. We can refine these and support more
  // compile-time evaluation as needed. Note that we shouldn't hit this for
  // `if` cases (that may depend on some type information), as these are
  // handled above.
  comptime.addError() << "Unable to resolve comptime expression.";
}

int SemanticAnalyser::analyse()
{
  std::string errors;

  auto last_num_unresolved = std::numeric_limits<int>::max();
  auto last_unresolved_branches = pass_tracker_.get_unresolved_branches();

  // Multiple passes to handle variables being used before they are defined
  while (ctx_.diagnostics().ok()) {
    pass_tracker_.reset_num_unresolved();
    visit(ctx_.root);
    if (is_final_pass()) {
      return pass_tracker_.get_num_passes();
    }

    auto num_unresolved = pass_tracker_.get_num_unresolved();
    auto unresolved_branches = pass_tracker_.get_unresolved_branches();

    if (unresolved_branches != last_unresolved_branches) {
      // While we have unresolved branches that are changing, we need to reset
      // our unresolved number since it may increase.
      last_unresolved_branches = std::move(unresolved_branches);
      last_num_unresolved = std::numeric_limits<int>::max();
      if (pass_tracker_.is_second_chance()) {
        pass_tracker_.clear_second_chance();
      }
    } else if (num_unresolved > 0 && num_unresolved < last_num_unresolved) {
      // If we're making progress, keep making passes.
      last_num_unresolved = num_unresolved;
      if (pass_tracker_.is_second_chance()) {
        pass_tracker_.clear_second_chance();
      }
    } else {
      if (pass_tracker_.is_second_chance()) {
        pass_tracker_.mark_final_pass();
      } else {
        pass_tracker_.mark_second_chance();
      }
    }

    pass_tracker_.inc_num_passes();
  }

  return 1;
}

inline bool SemanticAnalyser::is_final_pass() const
{
  return pass_tracker_.is_final_pass();
}

bool SemanticAnalyser::is_first_pass() const
{
  return pass_tracker_.get_num_passes() == 1;
}

bool SemanticAnalyser::check_arg(Call &call,
                                 size_t index,
                                 const arg_type_spec &spec)
{
  if (spec.skip_check) {
    return true;
  }
  return check_arg(call, spec.type, index, spec.literal);
}

bool SemanticAnalyser::check_arg(Call &call,
                                 size_t index,
                                 const map_type_spec &spec)
{
  if (auto *map = call.vargs.at(index).as<Map>()) {
    if (spec.type) {
      SizedType type = spec.type(call);
      assign_map_type(*map, type, &call);
      if (type.IsMinTy() || type.IsMaxTy() || type.IsAvgTy() ||
          type.IsSumTy() || type.IsStatsTy()) {
        // N.B. this keeps track of the integers passed to these map
        // aggregation calls to ensure they are compatible
        // (similar to the logic in update_int_type)
        const auto &assignTy = call.vargs.at(2).type();
        auto found = agg_map_val_.find(map->ident);
        if (found != agg_map_val_.end()) {
          auto &storedTy = found->second;
          if (assignTy.IsSigned() != storedTy.IsSigned()) {
            auto updatedTy = get_promoted_int(
                storedTy, assignTy, std::nullopt, call.vargs.at(2));
            if (!updatedTy) {
              call.addError() << "Type mismatch for " << map->ident << ": "
                              << "trying to assign value of type '" << assignTy
                              << "' when map already contains a value of type '"
                              << storedTy << "'";
            } else {
              storedTy.SetSize(updatedTy->GetSize());
              storedTy.SetSign(true);
            }
          } else {
            storedTy.SetSize(std::max(assignTy.GetSize(), storedTy.GetSize()));
          }
        } else {
          agg_map_val_[map->ident] = assignTy;
        }
      }
    }
    if (is_final_pass() && map->type().IsNoneTy()) {
      map->addError() << "Undefined map: " + map->ident;
    }
    return true;
  }
  call.vargs.at(index).node().addError()
      << call.func << "() expects a map argument";
  return false;
}

bool SemanticAnalyser::check_arg(Call &call,
                                 size_t index,
                                 const map_key_spec &spec)
{
  if (auto *map = call.vargs.at(spec.map_index).as<Map>()) {
    // This reconciles the argument if the other one is a map, but otherwise
    // we don't specifically emit an error. `map_type_spec` above does that.
    reconcile_map_key(map, call.vargs.at(index));
    return true;
  } else {
    return false;
  }
}

bool SemanticAnalyser::check_call(Call &call)
{
  auto spec = CALL_SPEC.find(call.func);
  if (spec == CALL_SPEC.end()) {
    return true;
  }

  auto ret = true;
  if (spec->second.min_args != spec->second.max_args) {
    ret = check_varargs(call, spec->second.min_args, spec->second.max_args);
  } else {
    ret = check_nargs(call, spec->second.min_args);
  }

  if (!ret) {
    return ret;
  }

  for (size_t i = 0; i < spec->second.arg_types.size() && i < call.vargs.size();
       ++i) {
    std::visit([&](auto &v) { ret = ret && check_arg(call, i, v); },
               spec->second.arg_types.at(i));
  }

  return ret;
}

// Checks the number of arguments passed to a function is correct.
bool SemanticAnalyser::check_nargs(const Call &call, size_t expected_nargs)
{
  std::stringstream err;
  auto nargs = call.vargs.size();
  assert(nargs >= call.injected_args);
  assert(expected_nargs >= call.injected_args);
  nargs -= call.injected_args;
  expected_nargs -= call.injected_args;

  if (nargs != expected_nargs) {
    if (expected_nargs == 0)
      err << call.func << "() requires no arguments";
    else if (expected_nargs == 1)
      err << call.func << "() requires one argument";
    else
      err << call.func << "() requires " << expected_nargs << " arguments";

    err << " (" << nargs << " provided)";
    call.addError() << err.str();
    return false;
  }
  return true;
}

// Checks the number of arguments passed to a function is within a specified
// range.
bool SemanticAnalyser::check_varargs(const Call &call,
                                     size_t min_nargs,
                                     size_t max_nargs)
{
  std::stringstream err;
  auto nargs = call.vargs.size();
  assert(nargs >= call.injected_args);
  assert(min_nargs >= call.injected_args);
  assert(max_nargs >= call.injected_args);
  nargs -= call.injected_args;
  min_nargs -= call.injected_args;
  max_nargs -= call.injected_args;

  if (nargs < min_nargs) {
    if (min_nargs == 1)
      err << call.func << "() requires at least one argument";
    else
      err << call.func << "() requires at least " << min_nargs << " arguments";

    err << " (" << nargs << " provided)";
    call.addError() << err.str();
    return false;
  } else if (nargs > max_nargs) {
    if (max_nargs == 0)
      err << call.func << "() requires no arguments";
    else if (max_nargs == 1)
      err << call.func << "() takes up to one argument";
    else
      err << call.func << "() takes up to " << max_nargs << " arguments";

    err << " (" << nargs << " provided)";
    call.addError() << err.str();
    return false;
  }

  return true;
}

// Checks an argument passed to a function is of the correct type.
//
// This function does not check that the function has the correct number of
// arguments. Either check_nargs() or check_varargs() should be called first
// to validate this.
bool SemanticAnalyser::check_arg(Call &call,
                                 Type type,
                                 size_t index,
                                 bool want_literal)
{
  const auto &arg = call.vargs.at(index);

  if (want_literal && (!arg.is_literal() || arg.type().GetTy() != type)) {
    call.addError() << call.func << "() expects a " << type << " literal ("
                    << arg.type().GetTy() << " provided)";
    if (type == Type::string) {
      // If the call requires a string literal and a positional parameter is
      // given, tell user to use str()
      auto *pos_param = arg.as<PositionalParameter>();
      if (pos_param)
        pos_param->addError() << "Use str($" << pos_param->n << ") to treat $"
                              << pos_param->n << " as a string";
    }
    return false;
  } else if (is_final_pass() && arg.type().GetTy() != type) {
    call.addError() << call.func << "() only supports " << type
                    << " arguments (" << arg.type().GetTy() << " provided)";
    return false;
  }
  return true;
}

bool SemanticAnalyser::check_symbol(const Call &call,
                                    int arg_num __attribute__((unused)))
{
  auto *arg = call.vargs.at(0).as<String>();
  if (!arg) {
    call.addError() << call.func
                    << "() expects a string literal as the first argument";
    return false;
  }

  std::string re = "^[a-zA-Z0-9./_-]+$";
  bool is_valid = std::regex_match(arg->value, std::regex(re));
  if (!is_valid) {
    call.addError() << call.func
                    << "() expects a string that is a valid symbol (" << re
                    << ") as input (\"" << arg << "\" provided)";
    return false;
  }

  return true;
}

SizedType *SemanticAnalyser::get_map_type(const Map &map)
{
  const std::string &map_ident = map.ident;
  auto search = map_val_.find(map_ident);
  if (search == map_val_.end())
    return nullptr;
  return &search->second;
}

SizedType *SemanticAnalyser::get_map_key_type(const Map &map)
{
  if (auto it = map_key_.find(map.ident); it != map_key_.end()) {
    return &it->second;
  }
  return nullptr;
}

// Semantic analysis for assigning a value of the provided type to the given
// map. The type within the passes `Map` node will be updated to reflect the
// new type, if available.
void SemanticAnalyser::assign_map_type(Map &map,
                                       const SizedType &type,
                                       const Node *loc_node,
                                       AssignMapStatement *assignment)
{
  const std::string &map_ident = map.ident;

  if (type.IsRecordTy() && is_tracepoint_struct(type.GetName())) {
    loc_node->addError() << "Storing tracepoint args in maps is not supported";
  }

  auto *maptype = get_map_type(map);
  if (maptype) {
    auto storedTy = *maptype;
    bool type_mismatch_error = false;
    if (storedTy.IsNoneTy()) {
      pass_tracker_.inc_num_unresolved();
      if (is_final_pass())
        map.addError() << "Undefined map: " + map_ident;
      else
        storedTy = type;
    } else if (storedTy.IsPtrTy() && type.IsIntegerTy()) {
      // OK
    } else if (storedTy.GetTy() != type.GetTy()) {
      type_mismatch_error = true;
    } else if (storedTy.IsIntegerTy()) {
      if (!assignment) {
        storedTy = type;
      } else {
        auto updatedTy = update_int_type(type, assignment->expr, storedTy);
        if (!updatedTy) {
          type_mismatch_error = true;
        } else {
          storedTy = *updatedTy;
        }
      }
    } else if (storedTy.IsStringTy()) {
      if (storedTy.GetSize() > type.GetSize()) {
        create_string_cast(assignment->expr, storedTy);
      } else {
        storedTy.SetSize(type.GetSize());
      }
    } else if (storedTy.IsTupleTy()) {
      if (!storedTy.IsSameType(type)) {
        type_mismatch_error = true;
      } else {
        auto updatedTy = get_promoted_tuple(storedTy, type);
        if (!updatedTy) {
          type_mismatch_error = true;
        } else {
          if (*updatedTy != type) {
            create_tuple_cast(assignment->expr, type, *updatedTy);
          }
          storedTy = *updatedTy;
        }
      }
    } else if (type.IsMinTy() || type.IsMaxTy() || type.IsAvgTy() ||
               type.IsSumTy() || type.IsStatsTy()) {
      if (storedTy.IsSigned() != type.IsSigned()) {
        storedTy.SetSign(true);
      }
    }
    if (type_mismatch_error) {
      loc_node->addError() << "Type mismatch for " << map_ident << ": "
                           << "trying to assign value of type '" << type
                           << "' when map already contains a value of type '"
                           << storedTy << "'";
    } else {
      map.value_type = storedTy;
      *maptype = storedTy;
    }
  } else {
    // This map hasn't been seen before.
    map_val_.insert({ map_ident, type });
    map.value_type = map_val_[map_ident];
  }
}

SizedType SemanticAnalyser::create_key_type(const SizedType &expr_type,
                                            Node &node)
{
  SizedType new_key_type = expr_type;
  if (expr_type.IsTupleTy()) {
    std::vector<SizedType> elements;
    for (const auto &field : expr_type.GetFields()) {
      SizedType keytype = create_key_type(field.type, node);
      elements.push_back(std::move(keytype));
    }
    new_key_type = CreateTuple(Struct::CreateTuple(elements));
  }

  if (new_key_type.IsPtrTy() && new_key_type.IsCtxAccess()) {
    // map functions only accepts a pointer to a element in the stack
    node.addError() << "context cannot be part of a map key";
  }

  if (new_key_type.IsHistTy() || new_key_type.IsLhistTy() ||
      new_key_type.IsStatsTy() || new_key_type.IsTSeriesTy()) {
    node.addError() << new_key_type << " cannot be part of a map key";
  }

  if (is_final_pass() && new_key_type.IsNoneTy()) {
    node.addError() << "Invalid map key type: " << new_key_type;
  }

  return new_key_type;
}

std::optional<SizedType> SemanticAnalyser::get_promoted_int(
    const SizedType &leftTy,
    const SizedType &rightTy,
    const std::optional<Expression> &leftExpr,
    const std::optional<Expression> &rightExpr)
{
  if (leftTy.IsEqual(rightTy)) {
    return leftTy;
  }

  bool leftSigned = leftTy.IsSigned();
  bool rightSigned = rightTy.IsSigned();
  auto leftSize = leftTy.GetSize();
  auto rightSize = rightTy.GetSize();

  if (leftSigned != rightSigned) {
    if (leftSigned) {
      if (leftSize > rightSize) {
        return leftTy;
      }
      if (rightExpr && (*rightExpr).is<Integer>()) {
        auto signed_ty = ast::get_signed_integer_type(
            (*rightExpr).as<Integer>()->value);
        if (!signed_ty) {
          // The value is too large and can't fit into
          // any supported signed int types
          return std::nullopt;
        }
        if (signed_ty->GetSize() <= leftSize) {
          return leftTy;
        }
      }
    } else if (rightSigned) {
      if (rightSize > leftSize) {
        return rightTy;
      }
      if (leftExpr && (*leftExpr).is<Integer>()) {
        auto signed_ty = ast::get_signed_integer_type(
            (*leftExpr).as<Integer>()->value);
        if (!signed_ty) {
          // The value is too large and can't fit into
          // any supported signed int types
          return std::nullopt;
        }
        if (signed_ty->GetSize() <= rightSize) {
          return rightTy;
        }
      }
    }

    size_t new_size = std::max(leftSize, rightSize) * 2;
    if (new_size > 8) {
      return std::nullopt;
    } else {
      return CreateInteger(new_size * 8, true);
    }
  }

  // Same sign - return the larger of the two
  size_t new_size = std::max(leftSize, rightSize);
  return CreateInteger(new_size * 8, leftSigned);
}

std::optional<SizedType> SemanticAnalyser::get_promoted_tuple(
    const SizedType &leftTy,
    const SizedType &rightTy)
{
  assert(leftTy.IsTupleTy() && leftTy.IsSameType(rightTy));

  std::vector<SizedType> new_elems;
  for (ssize_t i = 0; i < rightTy.GetFieldCount(); i++) {
    auto storedElemTy = leftTy.GetField(i).type;
    auto assignElemTy = rightTy.GetField(i).type;
    if (storedElemTy.IsIntegerTy()) {
      auto updatedTy = get_promoted_int(storedElemTy, assignElemTy);
      if (!updatedTy) {
        return std::nullopt;
      }

      new_elems.emplace_back(*updatedTy);
      continue;
    } else if (storedElemTy.IsTupleTy()) {
      auto new_elem = get_promoted_tuple(storedElemTy, assignElemTy);
      if (!new_elem) {
        return std::nullopt;
      } else {
        new_elems.emplace_back(*new_elem);
        continue;
      }
    } else if (storedElemTy.IsStringTy()) {
      storedElemTy.SetSize(
          std::max(storedElemTy.GetSize(), assignElemTy.GetSize()));
      new_elems.emplace_back(storedElemTy);
      continue;
    } else if (storedElemTy.IsArrayTy()) {
      if ((storedElemTy.GetSize() != assignElemTy.GetSize()) ||
          (*storedElemTy.GetElementTy() != *assignElemTy.GetElementTy())) {
        return std::nullopt;
      }
    }

    new_elems.emplace_back(storedElemTy);
  }
  return CreateTuple(Struct::CreateTuple(new_elems));
}

// The leftExpr is optional because in cases of variable assignment,
// and map key/value adjustment we can't modify/cast the left
// but in cases of binops or if expressions we can modify/cast both
// the left and the right expressions
std::optional<SizedType> SemanticAnalyser::update_int_type(
    const SizedType &rightTy,
    Expression &rightExpr,
    const SizedType &leftTy,
    std::optional<std::reference_wrapper<Expression>> leftExpr)
{
  assert(leftTy.IsIntegerTy() && rightTy.IsIntegerTy());

  auto updatedTy =
      leftExpr ? get_promoted_int(leftTy, rightTy, leftExpr->get(), rightExpr)
               : get_promoted_int(leftTy, rightTy, std::nullopt, rightExpr);
  if (!updatedTy) {
    return std::nullopt;
  }

  if (*updatedTy != leftTy && leftExpr) {
    create_int_cast(leftExpr->get(), *updatedTy);
  }

  if (*updatedTy != rightTy) {
    create_int_cast(rightExpr, *updatedTy);
  }

  return *updatedTy;
}

void SemanticAnalyser::resolve_struct_type(SizedType &type, Node &node)
{
  const SizedType *inner_type = &type;
  int pointer_level = 0;
  while (inner_type->IsPtrTy()) {
    inner_type = inner_type->GetPointeeTy();
    pointer_level++;
  }
  if (inner_type->IsRecordTy() && !inner_type->GetStruct()) {
    auto struct_type = bpftrace_.structs.Lookup(inner_type->GetName()).lock();
    if (!struct_type) {
      node.addError() << "Cannot resolve unknown type \""
                      << inner_type->GetName() << "\"\n";
    } else {
      type = CreateRecord(inner_type->GetName(), struct_type);
      while (pointer_level > 0) {
        type = CreatePointer(type);
        pointer_level--;
      }
    }
  }
}

Pass CreateSemanticPass()
{
  auto fn = [](ASTContext &ast,
               BPFtrace &b,
               CDefinitions &c_definitions,
               MapMetadata &mm,
               NamedParamDefaults &named_param_defaults,
               TypeMetadata &types,
               MacroRegistry &macro_registry) {
    SemanticAnalyser semantics(ast,
                               b,
                               c_definitions,
                               mm,
                               named_param_defaults,
                               types,
                               macro_registry,
                               !b.cmd_.empty() || b.child_ != nullptr);
    semantics.analyse();
  };

  return Pass::create("Semantic", fn);
};

variable *SemanticAnalyser::find_variable(const std::string &var_ident)
{
  if (auto *scope = find_variable_scope(var_ident)) {
    return &variables_[scope][var_ident];
  }
  return nullptr;
}

Node *SemanticAnalyser::find_variable_scope(const std::string &var_ident)
{
  for (auto *scope : scope_stack_) {
    if (auto search_val = variables_[scope].find(var_ident);
        search_val != variables_[scope].end()) {
      return scope;
    }
  }
  return nullptr;
}

} // namespace bpftrace::ast
