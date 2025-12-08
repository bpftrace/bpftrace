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
#include "ast/passes/type_resolver.h"
#include "ast/passes/type_system.h"
#include "bpftrace.h"
#include "btf/compat.h"
#include "collect_nodes.h"
#include "config.h"
#include "log.h"
#include "probe_matcher.h"
#include "probe_types.h"
#include "types.h"
#include "util/paths.h"
#include "util/strings.h"
#include "util/system.h"
#include "util/type_name.h"
#include "util/wildcard.h"

namespace bpftrace::ast {

namespace {

struct variable {
  SizedType type;
  bool can_resize;
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

template <util::TypeName name>
class AssignMapDisallowed : public Visitor<AssignMapDisallowed<name>> {
public:
  explicit AssignMapDisallowed() = default;
  using Visitor<AssignMapDisallowed>::visit;
  void visit(AssignMapStatement &assignment)
  {
    assignment.addError() << "Map assignments not allowed inside of "
                          << name.str();
  }
};

class TypeResolver : public Visitor<TypeResolver> {
public:
  explicit TypeResolver(ASTContext &ctx,
                        BPFtrace &bpftrace,
                        CDefinitions &c_definitions,
                        MapMetadata &map_metadata,
                        NamedParamDefaults &named_param_defaults,
                        TypeMetadata &type_metadata,
                        MacroRegistry &macro_registry)
      : ctx_(ctx),
        bpftrace_(bpftrace),
        c_definitions_(c_definitions),
        map_metadata_(map_metadata),
        named_param_defaults_(named_param_defaults),
        type_metadata_(type_metadata),
        macro_registry_(macro_registry)
  {
  }

  int analyse();

  using Visitor<TypeResolver>::visit;
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
  void visit(Record &record);
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

  void check_map_value(Map &map, Call &call, SizedType type);

  bool check_symbol(const Call &call);
  void check_stack_call(Call &call, bool kernel);

  Probe *get_probe(Node &node, std::string name = "");

  bool is_valid_assignment(const Expression &expr,
                           bool map_without_type = false);
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
  std::optional<SizedType> get_promoted_record(const SizedType &storedTy,
                                               const SizedType &assignTy);
  std::optional<SizedType> update_int_type(
      const SizedType &rightTy,
      Expression &rightExpr,
      const SizedType &leftTy,
      const Expression *leftExpr = nullptr);
  void resolve_struct_type(SizedType &type, Node &node);

  AddrSpace find_addrspace(ProbeType pt);

  void binop_ptr(Binop &op);
  void binop_int(Binop &op);

  void create_int_cast(Expression &exp, const SizedType &target_type);
  void create_string_cast(Expression &exp, const SizedType &target_type);
  void create_tuple_cast(Expression &exp,
                         const SizedType &curr_type,
                         const SizedType &target_type);
  void create_record_cast(Expression &exp,
                          const SizedType &curr_type,
                          const SizedType &target_type);
  void apply_element_cast(Expression &elem,
                          const SizedType &curr_type,
                          const SizedType &target_type);

  bool has_error() const;

  // At the moment we iterate over the stack from top to
  // bottom as variable shadowing is not supported.
  std::vector<Node *> scope_stack_;
  Node *top_level_node_ = nullptr;

  // Holds the function currently being visited by this TypeResolver.
  std::string func_;
  // This is specifically for visiting Identifiers
  // in typeof, sizeof, cast, and offsetof expressions
  // as the ident is treated like a type name, e.g.
  // `print(sizeof(uint64_t));`
  bool is_type_name_ = false;

  variable *find_variable(const std::string &var_ident);
  Node *find_variable_scope(const std::string &var_ident, bool safe = false);

  std::map<Node *, std::map<std::string, variable>> variables_;
  std::map<Node *, std::map<std::string, VarDeclStatement &>> variable_decls_;
  std::map<Node *, CollectNodes<Variable>> for_vars_referenced_;
  std::map<std::string, SizedType> map_val_;
  std::map<std::string, SizedType> map_key_;
  std::map<std::string, SizedType> agg_map_val_;
};

} // namespace

static std::unordered_set<std::string> VOID_RETURNING_FUNCS = {
  "join", "printf", "errorf", "warnf", "system", "cat",     "debugf",
  "exit", "print",  "clear",  "zero",  "time",   "unwatch", "fail"
};

// These are special map aggregation types that cannot be assigned
// to scratch variables or from one map to another e.g. these are both invalid:
// `@a = hist(10); let $b = @a;`
// `@a = count(); @b = @a;`
// However, if the assigned map already contains integers, we implicitly cast
// the aggregation into an integer to retrieve its value, so this is valid:
// `@a = count(); @b = 0; @b = @a`
bool TypeResolver::is_valid_assignment(const Expression &expr,
                                       bool map_without_type)
{
  // Prevent assigning aggregations to another map.
  if (expr.type().IsMultiKeyMapTy()) {
    return false;
  } else if (expr.type().NeedsPercpuMap() && !expr.type().IsCastableMapTy()) {
    return false;
  } else if (expr.type().IsCastableMapTy() && map_without_type) {
    return false;
  } else if (is_final_pass() &&
             (expr.type().IsNoneTy() || expr.type().IsVoidTy())) {
    return false;
  }
  return true;
}

void TypeResolver::visit(String &string)
{
  // Some strings are not part of bpf bytecode, like printf args
  // so this address space will be ignored
  string.string_type.SetAS(AddrSpace::kernel);
}

void TypeResolver::visit(Identifier &identifier)
{
  if (c_definitions_.enums.contains(identifier.ident)) {
    const auto &enum_name = std::get<1>(c_definitions_.enums[identifier.ident]);
    identifier.ident_type = CreateEnum(64, enum_name);
  } else if (bpftrace_.structs.Has(identifier.ident)) {
    identifier.ident_type = CreateCStruct(
        identifier.ident, bpftrace_.structs.Lookup(identifier.ident));
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
  } else {
    ConfigParser<StackMode> parser;
    StackMode mode;
    auto ok = parser.parse(func_, &mode, identifier.ident);
    if (ok) {
      identifier.ident_type = CreateStack(true, StackType{ .mode = mode });
    } else if (is_type_name_) {
      identifier.ident_type = bpftrace_.btf_->get_stype(identifier.ident);
    }
  }
}

AddrSpace TypeResolver::find_addrspace(ProbeType pt)
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
      // Will trigger a warning in selectProbeReadHelper.
      return AddrSpace::none;
  }
  return {}; // unreached
}

void TypeResolver::visit(Builtin &builtin)
{
  if (builtin.ident == "ctx") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType pt = probetype(probe->attach_points[0]->provider);
    bpf_prog_type bt = progtype(pt);
    std::string func = probe->attach_points[0]->func;
    builtin.builtin_type = CreatePointer(CreateNone());
    switch (bt) {
      case BPF_PROG_TYPE_KPROBE: {
        auto record = bpftrace_.structs.Lookup("struct pt_regs");
        if (!record.expired()) {
          builtin.builtin_type = CreatePointer(
              CreateCStruct("struct pt_regs", record), AddrSpace::kernel);
          builtin.builtin_type.MarkCtxAccess();
        }
        break;
      }
      case BPF_PROG_TYPE_PERF_EVENT:
        builtin.builtin_type = CreatePointer(
            CreateCStruct("struct bpf_perf_event_data",
                          bpftrace_.structs.Lookup(
                              "struct bpf_perf_event_data")),
            AddrSpace::kernel);
        builtin.builtin_type.MarkCtxAccess();
        break;
      case BPF_PROG_TYPE_TRACING:
        if (pt == ProbeType::iter) {
          std::string type = "struct bpf_iter__" + func;
          builtin.builtin_type = CreatePointer(
              CreateCStruct(type, bpftrace_.structs.Lookup(type)),
              AddrSpace::kernel);
          builtin.builtin_type.MarkCtxAccess();
        }
        break;
      default:
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
  } else if (builtin.ident == "__builtin_retval") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType type = probe->get_probetype();
    if (type == ProbeType::fentry || type == ProbeType::fexit) {
      const auto *arg = bpftrace_.structs.GetProbeArg(*probe,
                                                      RETVAL_FIELD_NAME);
      if (arg) {
        builtin.builtin_type = arg->type;
      } else
        builtin.addError() << "Can't find a field " << RETVAL_FIELD_NAME;
    } else {
      builtin.builtin_type = CreateUInt64();
    }
    // For kretprobe, fentry, fexit -> AddrSpace::kernel
    // For uretprobe -> AddrSpace::user
    builtin.builtin_type.SetAS(find_addrspace(type));
  } else if (builtin.ident == "kstack") {
    if (bpftrace_.config_->stack_mode == StackMode::build_id) {
      builtin.addWarning() << "'build_id' stack mode can only be used for "
                              "ustack. Falling back to 'raw' mode.";
      builtin.builtin_type = CreateStack(true,
                                         StackType{ .mode = StackMode::raw });
    } else {
      builtin.builtin_type = CreateStack(
          true, StackType{ .mode = bpftrace_.config_->stack_mode });
    }
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
    ProbeType type = probe->get_probetype();
    if (type == ProbeType::uprobe || type == ProbeType::uretprobe) {
      builtin.builtin_type = CreateUSym();
    } else {
      builtin.builtin_type = CreateKSym();
    }
  } else if (builtin.is_argx()) {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    builtin.builtin_type = CreateUInt64();
    builtin.builtin_type.SetAS(
        find_addrspace(probetype(probe->attach_points[0]->provider)));
  } else if (builtin.ident == "__builtin_username") {
    builtin.builtin_type = CreateUsername();
  } else if (builtin.ident == "__builtin_usermode") {
    builtin.builtin_type = CreateUInt8();
  } else if (builtin.ident == "__builtin_cpid") {
    builtin.builtin_type = CreateUInt64();
  } else if (builtin.ident == "args") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;

    ProbeType type = probe->get_probetype();
    auto type_name = probe->args_typename();
    if (!type_name) {
      builtin.addError() << "Unable to resolve unique type name.";
      return;
    }

    if (type == ProbeType::fentry || type == ProbeType::fexit ||
        type == ProbeType::uprobe || type == ProbeType::rawtracepoint) {
      builtin.builtin_type = CreateCStruct(
          *type_name, bpftrace_.structs.Lookup(*type_name));
      if (builtin.builtin_type.GetFieldCount() == 0)
        builtin.addError() << "Cannot read function parameters";

      builtin.builtin_type.MarkCtxAccess();
      builtin.builtin_type.is_funcarg = true;
      builtin.builtin_type.SetAS(type == ProbeType::uprobe ? AddrSpace::user
                                                           : AddrSpace::kernel);
      // We'll build uprobe args struct on stack
      if (type == ProbeType::uprobe)
        builtin.builtin_type.is_internal = true;
    } else if (type == ProbeType::tracepoint) {
      builtin.builtin_type = CreateCStruct(
          *type_name, bpftrace_.structs.Lookup(*type_name));
      builtin.builtin_type.SetAS(probe->attach_points.front()->target ==
                                         "syscalls"
                                     ? AddrSpace::user
                                     : AddrSpace::kernel);
      builtin.builtin_type.MarkCtxAccess();
    }
  } else {
    LOG(BUG) << "Unknown builtin variable: '" << builtin.ident << "'";
  }
}

void TypeResolver::visit(Call &call)
{
  struct func_setter {
    func_setter(TypeResolver &analyser, const std::string &s)
        : analyser_(analyser), old_func_(analyser_.func_)
    {
      analyser_.func_ = s;
    }

    ~func_setter()
    {
      analyser_.func_ = old_func_;
    }

  private:
    TypeResolver &analyser_;
    std::string old_func_;
  };

  func_setter scope_bound_func_setter{ *this, call.func };

  for (auto &varg : call.vargs) {
    visit(varg);
  }

  if (getAssignRewriteFuncs().contains(call.func)) {
    if (auto *map = call.vargs.at(0).as<Map>()) {
      if (call.func == "sum" || call.func == "min" || call.func == "max" ||
          call.func == "avg" || call.func == "stats") {
        if (call.vargs.size() != 3) {
          // This is an error in a later pass.
          return;
        }
      }
      if (call.func == "avg") {
        check_map_value(*map,
                        call,
                        CreateAvg(call.vargs.at(2).type().IsSigned()));
      } else if (call.func == "count") {
        check_map_value(*map, call, CreateCount());
      } else if (call.func == "hist") {
        check_map_value(*map, call, CreateHist());
      } else if (call.func == "lhist") {
        check_map_value(*map, call, CreateLhist());
      } else if (call.func == "tseries") {
        check_map_value(*map, call, CreateTSeries());
      } else if (call.func == "max") {
        check_map_value(*map,
                        call,
                        CreateMax(call.vargs.at(2).type().IsSigned()));
      } else if (call.func == "min") {
        check_map_value(*map,
                        call,
                        CreateMin(call.vargs.at(2).type().IsSigned()));
      } else if (call.func == "stats") {
        check_map_value(*map,
                        call,
                        CreateStats(call.vargs.at(2).type().IsSigned()));
      } else if (call.func == "sum") {
        check_map_value(*map,
                        call,
                        CreateSum(call.vargs.at(2).type().IsSigned()));
      }
      // This reconciles the argument if the other one is a map, but otherwise
      // we don't specifically emit an error. `map_type_spec` above does that.
      reconcile_map_key(map, call.vargs.at(1));
    } else {
      call.vargs.at(0).node().addError()
          << call.func << "() expects a map argument";
    }
  }

  if (getRawMapArgFuncs().contains(call.func) && !call.vargs.empty()) {
    if (auto *map = call.vargs.at(0).as<Map>()) {
      if (!get_map_type(*map) && !is_first_pass()) {
        map->addError() << "Undefined map: " + map->ident;
      }
    } else if (call.func != "print") {
      call.vargs.at(0).node().addError()
          << call.func << "() expects a map argument";
    }
  }

  if (getAssignRewriteFuncs().contains(call.func) ||
      VOID_RETURNING_FUNCS.contains(call.func)) {
    call.return_type = CreateVoid();
  } else if (call.func == "str") {
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
    // Subtract out metadata headroom
    uint32_t max_buffer_size = max_strlen - sizeof(AsyncEvent::Buf);
    uint32_t buffer_size = max_buffer_size;

    if (call.vargs.size() == 1) {
      auto &arg = call.vargs.at(0);
      if (arg.type().IsArrayTy()) {
        buffer_size = arg.type().GetNumElements() *
                      arg.type().GetElementTy().GetSize();
      }
    } else if (call.vargs.size() == 2) {
      if (auto *integer = call.vargs.at(1).as<Integer>()) {
        buffer_size = integer->value;
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
    if (!call.vargs.empty()) {
      auto &arg = call.vargs.at(0);
      const auto &type = arg.type();
      if (type.IsIntegerTy() && type.GetSize() != 8) {
        create_int_cast(call.vargs.at(0), CreateInt64());
      }
    }

    if (call.func == "ksym")
      call.return_type = CreateKSym();
    else if (call.func == "usym")
      call.return_type = CreateUSym();
  } else if (call.func == "ntop") {
    int buffer_size = 24;
    call.return_type = CreateInet(buffer_size);
  } else if (call.func == "pton") {
    int af_type = 0, addr_size = 0;
    std::string addr;
    if (call.vargs.size() == 1) {
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
  } else if (call.func == "reg") {
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
    if (call.vargs.size() == 2 && call.vargs.at(1).type() != CreateUInt32()) {
      create_int_cast(call.vargs.at(1), CreateUInt32());
    }
    call.return_type = CreateUInt64();
    call.return_type.SetAS(AddrSpace::kernel);
  } else if (call.func == "__builtin_uaddr") {
    auto *probe = get_probe(call, call.func);
    if (probe == nullptr)
      return;

    struct symbol sym = {};

    if (!call.vargs.empty() && call.vargs.at(0).is<String>()) {
      if (check_symbol(call)) {
        auto name = call.vargs.at(0).as<String>()->value;
        const auto &target = probe->attach_points[0]->target;

        int err = bpftrace_.resolve_uname(name, &sym, target);
        if (err < 0 || sym.address == 0) {
          call.addError() << "Could not resolve symbol: " << target << ":"
                          << name;
        }
      }
    }

    size_t pointee_size = 0;
    switch (sym.size) {
      case 1:
      case 2:
      case 4:
        pointee_size = sym.size * 8;
        break;
      default:
        pointee_size = 64;
    }
    call.return_type = CreatePointer(CreateInt(pointee_size), AddrSpace::user);
  } else if (call.func == "cgroupid") {
    call.return_type = CreateUInt64();
  } else if (call.func == "cgroup_path") {
    call.return_type = CreateCgroupPath();
  } else if (call.func == "stack_len") {
    call.return_type = CreateInt64();
  } else if (call.func == "strftime") {
    call.return_type = CreateTimestamp();
  } else if (call.func == "kstack") {
    check_stack_call(call, true);
  } else if (call.func == "ustack") {
    check_stack_call(call, false);
  } else if (call.func == "path") {
    auto call_type_size = bpftrace_.config_->max_strlen;
    if (call.vargs.size() == 2) {
      if (auto *size = call.vargs.at(1).as<Integer>()) {
        call_type_size = size->value;
      }
    }
    call.return_type = SizedType(Type::string, call_type_size);
  } else if (call.func == "strncmp") {
    call.return_type = CreateUInt64();
  } else if (call.func == "kptr" || call.func == "uptr") {
    auto as = (call.func == "kptr" ? AddrSpace::kernel : AddrSpace::user);
    call.return_type = call.vargs.front().type();
    call.return_type.SetAS(as);
  } else if (call.func == "macaddr") {
    call.return_type = CreateMacAddress();
  } else if (call.func == "bswap") {
    auto int_bit_width = 1;
    if (!call.vargs.empty()) {
      auto &arg = call.vargs.at(0);
      if (!arg.type().IsIntTy()) {
        call.addError() << call.func << "() only supports integer arguments ("
                        << arg.type().GetTy() << " provided)";
        return;
      }
      int_bit_width = arg.type().GetIntBitWidth();
    }
    call.return_type = CreateUInt(int_bit_width);
  } else if (call.func == "skboutput") {
    call.return_type = CreateUInt32();
  } else if (call.func == "nsecs") {
    call.return_type = CreateUInt64();
    call.return_type.ts_mode = TimestampMode::boot;
    if (call.vargs.size() == 1) {
      call.return_type.ts_mode = call.vargs.at(0).type().ts_mode;
    }
  } else if (call.func == "pid" || call.func == "tid") {
    call.return_type = CreateUInt32();
  } else if (call.func == "socket_cookie") {
    call.return_type = CreateUInt64();
  } else {
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
  }
}

std::optional<size_t> TypeResolver::check(Sizeof &szof)
{
  is_type_name_ = true;
  Visitor<TypeResolver>::visit(szof);
  is_type_name_ = false;

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

void TypeResolver::visit(Sizeof &szof)
{
  AssignMapDisallowed<"sizeof">().visit(szof.record);

  const auto v = check(szof);
  if (!v && is_final_pass()) {
    szof.addError() << "sizeof not resolved, is type complete?";
  }
}

std::optional<size_t> TypeResolver::check(Offsetof &offof)
{
  is_type_name_ = true;
  Visitor<TypeResolver>::visit(offof);
  is_type_name_ = false;

  auto check_type = [&](SizedType cstruct) -> std::optional<size_t> {
    size_t offset = 0;
    // Check if all sub-fields are present.
    for (const auto &field : offof.field) {
      if (!cstruct.IsCStructTy()) {
        offof.addError() << "'" << cstruct << "' " << "is not a c_struct type.";
        return std::nullopt;
      } else if (!bpftrace_.structs.Has(cstruct.GetName())) {
        offof.addError() << "'" << cstruct.GetName() << "' does not exist.";
        return std::nullopt;
      } else if (!cstruct.HasField(field)) {
        offof.addError() << "'" << cstruct.GetName() << "' "
                         << "has no field named " << "'" << field << "'";
        return std::nullopt;
      } else {
        // Get next sub-field
        const auto &f = cstruct.GetField(field);
        offset += f.offset;
        cstruct = f.type;
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

void TypeResolver::visit(Offsetof &offof)
{
  AssignMapDisallowed<"offsetof">().visit(offof.record);

  const auto v = check(offof);
  if (!v && is_final_pass()) {
    offof.addError() << "offsetof not resolved, is type complete?";
  }
}

void TypeResolver::visit(Typeof &typeof)
{
  AssignMapDisallowed<"typeof or typeinfo">().visit(typeof.record);

  if (std::holds_alternative<SizedType>(typeof.record)) {
    resolve_struct_type(std::get<SizedType>(typeof.record), typeof);
  } else {
    const auto &expr = std::get<Expression>(typeof.record);
    if (auto *ident = expr.as<Identifier>()) {
      auto stype = bpftrace_.btf_->get_stype(ident->ident);
      if (!stype.IsNoneTy()) {
        typeof.record = stype;
      }
    }
  }

  is_type_name_ = true;
  Visitor<TypeResolver>::visit(typeof);
  is_type_name_ = false;
}

void TypeResolver::visit(Typeinfo &typeinfo)
{
  Visitor<TypeResolver>::visit(typeinfo);
}

bool TypeResolver::check_symbol(const Call &call)
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

void TypeResolver::check_stack_call(Call &call, bool kernel)
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
      } else if (auto *limit = call.vargs.at(0).as<Integer>()) {
        stack_type.limit = limit->value;
      } else {
        call.addError() << call.func << ": invalid limit value";
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
      if (auto *limit = call.vargs.at(1).as<Integer>()) {
        stack_type.limit = limit->value;
      } else {
        call.addError() << call.func << ": invalid limit value";
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
  if (stack_type.mode == StackMode::build_id && kernel) {
    call.addError() << "'build_id' stack mode can only be used for ustack";
  }
  call.return_type = CreateStack(kernel, stack_type);
}

Probe *TypeResolver::get_probe(Node &node, std::string name)
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

void TypeResolver::visit(Map &map)
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
}
void TypeResolver::visit(MapAddr &map_addr)
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

void TypeResolver::visit(Variable &var)
{
  if (auto *found = find_variable(var.ident)) {
    var.var_type = found->type;
  }
}

void TypeResolver::visit(VariableAddr &var_addr)
{
  if (auto *found = find_variable(var_addr.var->ident)) {
    var_addr.var->var_type = found->type;
    if (!found->type.IsNoneTy()) {
      var_addr.var_addr_type = CreatePointer(found->type, found->type.GetAS());
    }
  }
  if (is_final_pass() && var_addr.var_addr_type.IsNoneTy()) {
    var_addr.addError() << "No type available for variable "
                        << var_addr.var->ident;
  }
}

void TypeResolver::visit(ArrayAccess &arr)
{
  visit(arr.expr);
  visit(arr.indexpr);

  const SizedType &type = arr.expr.type();

  if (type.IsArrayTy())
    arr.element_type = type.GetElementTy();
  else if (type.IsPtrTy())
    arr.element_type = type.GetPointeeTy();
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

void TypeResolver::visit(TupleAccess &acc)
{
  visit(acc.expr);
  const SizedType &type = acc.expr.type();

  if (!type.IsTupleTy()) {
    return;
  }

  if (acc.index < type.GetFields().size()) {
    acc.element_type = type.GetField(acc.index).type;
  }
}

void TypeResolver::binop_int(Binop &binop)
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
  } else if (!update_int_type(rightTy, binop.right, leftTy, &binop.left)) {
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

void TypeResolver::create_int_cast(Expression &exp,
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

void TypeResolver::create_string_cast(Expression &exp,
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

void TypeResolver::apply_element_cast(Expression &elem,
                                      const SizedType &curr_type,
                                      const SizedType &target_type)
{
  if (target_type.IsIntTy() && curr_type != target_type) {
    create_int_cast(elem, target_type);
  } else if (target_type.IsStringTy()) {
    create_string_cast(elem, target_type);
  } else if (target_type.IsTupleTy()) {
    create_tuple_cast(elem, curr_type, target_type);
  } else if (target_type.IsRecordTy()) {
    create_record_cast(elem, curr_type, target_type);
  }
}

void TypeResolver::create_tuple_cast(Expression &exp,
                                     const SizedType &curr_type,
                                     const SizedType &target_type)
{
  if (auto *block_expr = exp.as<BlockExpr>()) {
    create_tuple_cast(block_expr->expr, curr_type, target_type);
    return;
  }

  if (!exp.is<Variable>() && !exp.is<TupleAccess>() && !exp.is<MapAccess>() &&
      !exp.is<Tuple>() && !exp.is<FieldAccess>() && !exp.is<Unop>()) {
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
    apply_element_cast(elem, c_ty, t_ty);
    expr_list.emplace_back(std::move(elem));
  }

  exp = ctx_.make_node<Tuple>(Location(exp.loc()), std::move(expr_list));
  exp.as<Tuple>()->tuple_type = target_type;
  visit(exp);
}

void TypeResolver::create_record_cast(Expression &exp,
                                      const SizedType &curr_type,
                                      const SizedType &target_type)
{
  if (auto *block_expr = exp.as<BlockExpr>()) {
    create_record_cast(block_expr->expr, curr_type, target_type);
    return;
  }

  if (!exp.is<Variable>() && !exp.is<FieldAccess>() && !exp.is<MapAccess>() &&
      !exp.is<Record>() && !exp.is<TupleAccess>() && !exp.is<Unop>()) {
    LOG(BUG) << "Unexpected expression kind: create_record_cast";
  }

  std::unordered_map<size_t, NamedArgument *> named_arg_map;

  for (size_t i = 0; i < curr_type.GetFields().size(); ++i) {
    const auto &target_field = target_type.GetField(i);
    const auto &c_ty = curr_type.GetField(target_field.name).type;
    const auto &t_ty = target_field.type;
    Expression elem;
    if (auto *record_literal = exp.as<Record>()) {
      auto field_idx = curr_type.GetFieldIdx(target_field.name);
      elem = clone(ctx_,
                   record_literal->elems.at(field_idx)->expr.loc(),
                   record_literal->elems.at(field_idx)->expr);
    } else {
      elem = ctx_.make_node<FieldAccess>(Location(exp.loc()),
                                         clone(ctx_, exp.loc(), exp),
                                         target_field.name);
      elem.as<FieldAccess>()->field_type = c_ty;
    }
    apply_element_cast(elem, c_ty, t_ty);
    auto *named_arg = ctx_.make_node<NamedArgument>(Location(exp.loc()),
                                                    target_field.name,
                                                    std::move(elem));
    named_arg_map[curr_type.GetFieldIdx(target_field.name)] = named_arg;
  }

  // Maintain the ordering for the current type
  NamedArgumentList named_args = {};
  for (size_t i = 0; i < curr_type.GetFields().size(); ++i) {
    named_args.emplace_back(named_arg_map[i]);
  }

  exp = ctx_.make_node<Record>(Location(exp.loc()), std::move(named_args));
  visit(exp);
}

void TypeResolver::binop_ptr(Binop &binop)
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
        const auto le = lht.GetPointeeTy();
        const auto re = rht.GetPointeeTy();
        if (le != re) {
          auto &warn = binop.addWarning();
          warn << "comparison of distinct pointer types: " << le << ", " << re;
          warn.addContext(binop.left.loc()) << "left (" << le << ")";
          warn.addContext(binop.right.loc()) << "right (" << re << ")";
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
      binop.result_type = CreatePointer(ptr.GetPointeeTy(), ptr.GetAS());
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

void TypeResolver::visit(Binop &binop)
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
  }
}

void TypeResolver::visit(Unop &unop)
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

  if (unop.op == Operator::MUL) {
    if (type.IsPtrTy()) {
      unop.result_type = type.GetPointeeTy();
      if (type.IsCtxAccess())
        unop.result_type.MarkCtxAccess();
      unop.result_type.is_internal = type.is_internal;
      unop.result_type.SetAS(type.GetAS());
    } else if (type.IsCStructTy()) {
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

void TypeResolver::visit(IfExpr &if_expr)
{
  // In order to evaluate literals and resolved type operators, we need to fold
  // the condition. This is handled in the `Expression` visitor. Branches that
  // are always `false` are exempted from semantic checks. If after folding the
  // condition still has unresolved `comptime` operators, then we are not able
  // to visit yet. These branches are also not allowed to contain information
  // necessary to resolve types, that is a cycle in the dependency graph, the
  // `if` condition must be resolvable first. If the condition *is* resolvable
  // and is a constant, then we prune the dead code paths and will never use
  // them.
  if (auto *comptime = if_expr.cond.as<Comptime>()) {
    visit(comptime->expr);
    if (is_final_pass()) {
      comptime->addError() << "Unable to resolve comptime expression";
    } else {
      pass_tracker_.add_unresolved_branch(if_expr);
    }
    return; // Skip visiting this `if` for now.
  }

  visit(if_expr.cond);
  visit(if_expr.left);
  visit(if_expr.right);

  const Type &cond = if_expr.cond.type().GetTy();
  const auto &lhs = if_expr.left.type();
  const auto &rhs = if_expr.right.type();

  if (!lhs.IsCompatible(rhs)) {
    if (is_final_pass()) {
      if_expr.addError() << "Branches must return the same type: " << "have '"
                         << lhs << "' and '" << rhs << "'";
    }
    // This assignment is just temporary to prevent errors
    // before the final pass
    if_expr.result_type = lhs;
    return;
  }

  if (is_final_pass() && cond != Type::integer && cond != Type::pointer &&
      cond != Type::boolean) {
    if_expr.addError() << "Invalid condition: " << cond;
    return;
  }

  bool type_mismatch_error = false;
  if (lhs.IsIntegerTy()) {
    auto updatedTy = update_int_type(rhs, if_expr.right, lhs, &if_expr.left);
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
  } else if (lhs.IsRecordTy()) {
    auto updatedTy = get_promoted_record(lhs, rhs);
    if (!updatedTy) {
      type_mismatch_error = true;
    } else {
      if (*updatedTy != lhs) {
        create_record_cast(if_expr.left, lhs, *updatedTy);
      }
      if (*updatedTy != rhs) {
        create_record_cast(if_expr.right, rhs, *updatedTy);
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

void TypeResolver::visit(Unroll &unroll)
{
  visit(unroll.expr);
  visit(unroll.block);
}

void TypeResolver::visit(Jump &jump)
{
  if (jump.ident == JumpType::RETURN) {
    visit(jump.return_value);
    if (dynamic_cast<Probe *>(top_level_node_)) {
      if (jump.return_value.has_value()) {
        const auto &ty = jump.return_value->type();
        if (ty.IsIntegerTy()) {
          // Probes always return 64 bit ints
          update_int_type(jump.return_value->type(),
                          *jump.return_value,
                          CreateInt64());
        }
      }
    } else if (auto *subprog = dynamic_cast<Subprog *>(top_level_node_)) {
      const auto &ty = subprog->return_type->type();
      if (is_final_pass() && !ty.IsNoneTy() &&
          (ty.IsVoidTy() != !jump.return_value.has_value() ||
           (jump.return_value.has_value() &&
            jump.return_value->type() != ty))) {
        if (jump.return_value.has_value() &&
            jump.return_value->type().IsCompatible(ty)) {
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

void TypeResolver::visit(While &while_block)
{
  visit(while_block.cond);
  visit(while_block.block);
}

void TypeResolver::visit(For &f)
{
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

  visit(f.iterable);

  // Validate the iterable.
  if (auto *map = f.iterable.as<Map>()) {
    if (!map->type().IsMapIterableTy()) {
      map->addError() << "Loop expression does not support type: "
                      << map->type();
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

  variables_[scope_stack_.back()][decl_name] = {
    .type = f.decl->type(),
    .can_resize = true,
  };

  visit(f.block);

  scope_stack_.pop_back();

  // Finally, create the context tuple now that all variables inside the loop
  // have been visited.
  std::vector<SizedType> ctx_types;
  std::vector<std::string_view> ctx_idents;
  auto [iter, _] = for_vars_referenced_.try_emplace(&f);
  auto &collector = iter->second;
  for (const Variable &var : collector.nodes()) {
    ctx_types.push_back(CreatePointer(var.var_type, AddrSpace::none));
    ctx_idents.push_back(var.ident);
  }
  f.ctx_type = CreateCStruct(Struct::CreateRecord(ctx_types, ctx_idents));
}

void TypeResolver::visit(FieldAccess &acc)
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

  if (!type.IsCStructTy() && !type.IsRecordTy()) {
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

  const auto &record = type.GetStruct();
  if (!record) {
    if (type.IsRecordTy()) {
      acc.addError() << "Record is not resolvable";
    } else {
      acc.addError() << "Struct/union is not resolvable";
    }
  } else if (!record->HasField(acc.field)) {
    if (type.IsRecordTy()) {
      acc.addError() << "Record does not contain a field named '" << acc.field
                     << "'";
    } else {
      acc.addError() << "Struct/union of type '" << type.GetName()
                     << "' does not contain a field named '" << acc.field
                     << "'";
    }
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
        (acc.field_type.IsArrayTy() || acc.field_type.IsCStructTy())) {
      // e.g., ((struct bpf_perf_event_data*)ctx)->regs.ax
      acc.field_type.MarkCtxAccess();
    }
    acc.field_type.is_internal = type.is_internal;
    acc.field_type.SetAS(acc.expr.type().GetAS());
  }
}

void TypeResolver::visit(MapAccess &acc)
{
  visit(acc.map);
  visit(acc.key);

  if (map_metadata_.bad_scalar_access.contains(acc.map)) {
    acc.addError() << acc.map->ident
                   << " used as a map with an explicit key (non-scalar map), "
                      "previously used without an explicit key (scalar map)";
    return;
  }

  reconcile_map_key(acc.map, acc.key);

  auto search_val = map_val_.find(acc.map->ident);
  if (search_val != map_val_.end()) {
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

void TypeResolver::reconcile_map_key(Map *map, Expression &key_expr)
{
  SizedType new_key_type = create_key_type(key_expr.type(), key_expr.node());

  if (const auto &key = map_key_.find(map->ident); key != map_key_.end()) {
    SizedType &storedTy = key->second;
    bool type_mismatch_error = false;
    if (!storedTy.IsCompatible(new_key_type)) {
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
      } else if (storedTy.IsRecordTy()) {
        auto updatedTy = get_promoted_record(storedTy, new_key_type);
        if (!updatedTy) {
          type_mismatch_error = true;
        } else {
          if (*updatedTy != new_key_type) {
            create_record_cast(key_expr, new_key_type, *updatedTy);
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
      if (is_final_pass()) {
        key_expr.node().addError()
            << "Argument mismatch for " << map->ident << ": "
            << "trying to access with arguments: '" << new_key_type
            << "' when map expects arguments: '" << storedTy << "'";
      }
    }
  } else {
    if (!new_key_type.IsNoneTy() && !new_key_type.IsVoidTy()) {
      map_key_.insert({ map->ident, new_key_type });
      map->key_type = new_key_type;
    }
  }
}

void TypeResolver::visit(Cast &cast)
{
  visit(cast.expr);
  visit(cast.typeof);

  const auto &resolved_ty = cast.type();
  if (resolved_ty.IsNoneTy()) {
    pass_tracker_.inc_num_unresolved();
    return; // Revisit later.
  }

  auto rhs = cast.expr.type();
  if (rhs.IsNoneTy()) {
    return; // Revisit later.
  }

  // Resolved the type because we may mutate it below, for various reasons.
  cast.typeof->record = resolved_ty;
  auto &ty = std::get<SizedType>(cast.typeof->record);

  if (ty.IsArrayTy()) {
    if (ty.GetNumElements() == 0) {
      if (ty.GetElementTy().GetSize() != 0) {
        if (rhs.GetSize() % ty.GetElementTy().GetSize() == 0) {
          // cast to unsized array (e.g. int8[]), determine size from RHS
          auto num_elems = rhs.GetSize() / ty.GetElementTy().GetSize();
          ty = CreateArray(num_elems, ty.GetElementTy());
        }
      }
    }

    if (rhs.IsIntTy() || rhs.IsBoolTy())
      ty.is_internal = true;

    if (rhs.IsIntTy()) {
      if ((ty.GetElementTy().IsIntegerTy() || ty.GetElementTy().IsBoolTy())) {
        if ((ty.GetSize() <= 8) && (ty.GetSize() > rhs.GetSize())) {
          create_int_cast(cast.expr,
                          CreateInteger(ty.GetSize() * 8,
                                        ty.GetElementTy().IsSigned()));
        }
      }
    }
  }

  if (ty.IsArrayTy() && rhs.IsIntTy() &&
      (ty.GetElementTy().IsIntegerTy() || ty.GetElementTy().IsBoolTy())) {
    if ((ty.GetSize() <= 8) && (ty.GetSize() > rhs.GetSize())) {
      create_int_cast(cast.expr,
                      CreateInteger(ty.GetSize() * 8,
                                    ty.GetElementTy().IsSigned()));
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

void TypeResolver::visit(Tuple &tuple)
{
  std::vector<SizedType> elements;
  for (auto &elem : tuple.elems) {
    visit(elem);

    // If elem type is none that means that the tuple is not yet resolved.
    if (elem.type().IsNoneTy()) {
      pass_tracker_.inc_num_unresolved();
      return;
    }
    elements.emplace_back(elem.type());
  }

  tuple.tuple_type = CreateTuple(Struct::CreateTuple(elements));
}

void TypeResolver::visit(Record &record)
{
  std::vector<SizedType> elements;
  std::vector<std::string_view> names;
  for (auto *named_arg : record.elems) {
    auto &elem = named_arg->expr;
    visit(elem);
    names.emplace_back(named_arg->name);

    // If elem type is none that means that the record is not yet resolved.
    if (elem.type().IsNoneTy()) {
      pass_tracker_.inc_num_unresolved();
      return;
    }
    elements.emplace_back(elem.type());
  }

  record.record_type = CreateRecord(Struct::CreateRecord(elements, names));
}

void TypeResolver::visit(Expression &expr)
{
  // Visit and fold all other values.
  Visitor<TypeResolver>::visit(expr);
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
      auto *base_type = ctx_.make_node<String>(type_id->loc,
                                               to_string(ty.GetTy()));
      auto *full_type = ctx_.make_node<String>(type_id->loc, typestr(ty));
      expr.value = make_record(ctx_,
                               type_id->loc,
                               { { "btf_id", id },
                                 { "base_type", base_type },
                                 { "full_type", full_type } });
    }
  } else if (auto *binop = expr.as<Binop>()) {
    if ((binop->left.type().IsTupleTy() || binop->left.type().IsRecordTy()) &&
        binop->left.type().IsCompatible(binop->right.type()) &&
        (binop->op == Operator::EQ || binop->op == Operator::NE)) {
      bool is_tuple = binop->left.type().IsTupleTy();
      const auto &lht = binop->left.type();
      const auto &rht = binop->right.type();
      auto updatedTy = is_tuple ? get_promoted_tuple(lht, rht)
                                : get_promoted_record(lht, rht);
      if (!updatedTy) {
        binop->addError() << "Type mismatch for '" << opstr(*binop)
                          << "': comparing " << lht << " with " << rht;
      } else {
        if (*updatedTy != lht) {
          if (is_tuple) {
            create_tuple_cast(binop->left, lht, *updatedTy);
          } else {
            create_record_cast(binop->left, lht, *updatedTy);
          }
        }
        if (*updatedTy != rht) {
          if (is_tuple) {
            create_tuple_cast(binop->right, rht, *updatedTy);
          } else {
            create_record_cast(binop->right, rht, *updatedTy);
          }
        }

        bool types_equal = binop->left.type() == binop->right.type();

        auto *size = ctx_.make_node<Integer>(binop->loc,
                                             updatedTy->GetSize(),
                                             CreateUInt64());
        // N.B. if the types aren't equal at this point it means that
        // we're dealing with record types that are same except for
        // their fields are in a different order so we need to use a
        // different memcmp that saves off both the left and right to
        // variables but sets the type of the right variable to the left
        // before assignment (e.g. `let $right: typeof($left) = right;`)
        // as this ensures the temporary `$right` variable has the same
        // field ordering as the `$left`.
        auto *call = ctx_.make_node<Call>(
            binop->loc,
            types_equal ? "memcmp" : "memcmp_record",
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

void TypeResolver::visit(ExprStatement &expr)
{
  visit(expr.expr);
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

void TypeResolver::visit(AssignMapStatement &assignment)
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

  if (type.IsCStructTy() && map_val_[map_ident].IsCStructTy()) {
    std::string ty = assignment.expr.type().GetName();
    std::string stored_ty = map_val_[map_ident].GetName();
    if (!stored_ty.empty() && stored_ty != ty) {
      assignment.addError()
          << "Type mismatch for " << map_ident << ": "
          << "trying to assign value of type '" << ty
          << "' when map already has a type '" << stored_ty << "'";
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

void TypeResolver::visit(AssignVarStatement &assignment)
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

  const auto &var_ident = assignment.var()->ident;

  if (!is_valid_assignment(assignment.expr)) {
    if (is_final_pass()) {
      assignment.addError() << "Value '" << assignment.expr.type()
                            << "' cannot be assigned to a scratch variable.";
    }
    return;
  }

  Node *var_scope = nullptr;
  auto assignTy = assignment.expr.type();

  if (auto *scope = find_variable_scope(var_ident)) {
    auto &foundVar = variables_[scope][var_ident];
    auto &storedTy = foundVar.type;
    bool type_mismatch_error = false;
    if (storedTy.IsNoneTy()) {
      storedTy = assignTy;
    } else if (!storedTy.IsCompatible(assignTy) &&
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
    } else if (assignTy.IsRecordTy()) {
      auto updatedTy = get_promoted_record(storedTy, assignTy);
      if (!updatedTy || (*updatedTy != storedTy && !foundVar.can_resize)) {
        type_mismatch_error = true;
      } else {
        if (*updatedTy != assignTy) {
          create_record_cast(assignment.expr, assignTy, *updatedTy);
        }
        storedTy = *updatedTy;
        assignTy = *updatedTy;
      }
    }
    if (type_mismatch_error) {
      if (is_final_pass()) {
        assignment.addError()
            << "Type mismatch for " << var_ident << ": "
            << "trying to assign value of type '" << assignTy
            << "' when variable already has a type '" << storedTy << "'";
      }
    } else {
      // The assign type is possibly more complete than the stored type,
      // which could come from a variable declaration. The assign type may
      // resolve builtins like `curtask` which also specifies the address
      // space.
      if (assignTy.GetSize() < storedTy.GetSize()) {
        assignTy.SetSize(storedTy.GetSize());
      }
      foundVar.type = assignTy;
      var_scope = scope;
    }
  }

  if (var_scope == nullptr) {
    variables_[scope_stack_.back()].insert({ var_ident,
                                             {
                                                 .type = assignTy,
                                                 .can_resize = true,
                                             } });
    var_scope = scope_stack_.back();
  }

  const auto &storedTy = variables_[var_scope][var_ident].type;
  assignment.var()->var_type = storedTy;
}

void TypeResolver::visit(VarDeclStatement &decl)
{
  visit(decl.typeof);
  const std::string &var_ident = decl.var->ident;

  if (decl.typeof) {
    decl.var->var_type = decl.typeof->type();
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

      return;
    }
  }

  bool can_resize = decl.var->var_type.GetSize() == 0;

  variables_[scope_stack_.back()].insert({ var_ident,
                                           {
                                               .type = decl.var->var_type,
                                               .can_resize = can_resize,
                                           } });
  variable_decls_[scope_stack_.back()].insert({ var_ident, decl });
}

void TypeResolver::visit(BlockExpr &block)
{
  scope_stack_.push_back(&block);
  visit(block.stmts);
  visit(block.expr);
  scope_stack_.pop_back();
}

void TypeResolver::visit(Probe &probe)
{
  top_level_node_ = &probe;
  visit(probe.attach_points);
  visit(probe.block);
}

void TypeResolver::visit(Subprog &subprog)
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
                             variable{
                                 .type = ty,
                                 .can_resize = true,
                             })
                    .first->second;
    var.type = ty; // Override in case it has changed.
  }

  // Validate that arguments are set.
  visit(subprog.args);
  for (SubprogArg *arg : subprog.args) {
    if (arg->typeof->type().IsNoneTy()) {
      pass_tracker_.inc_num_unresolved();
    }
  }

  // Visit all statements.
  visit(subprog.block);

  // Validate that the return type is valid.
  visit(subprog.return_type);
  if (subprog.return_type->type().IsNoneTy()) {
    pass_tracker_.inc_num_unresolved();
  }
  scope_stack_.pop_back();
}

void TypeResolver::visit(Comptime &comptime)
{
  visit(comptime.expr);
  // If something has not been resolved by the last pass, then we fail.
  if (is_final_pass()) {
    comptime.addError() << "Unable to resolve comptime expression.";
  } else {
    pass_tracker_.inc_num_unresolved();
  }
}

int TypeResolver::analyse()
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

inline bool TypeResolver::is_final_pass() const
{
  return pass_tracker_.is_final_pass();
}

bool TypeResolver::is_first_pass() const
{
  return pass_tracker_.get_num_passes() == 1;
}

void TypeResolver::check_map_value(Map &map, Call &call, SizedType type)
{
  assign_map_type(map, type, &call);
  if (type.IsMinTy() || type.IsMaxTy() || type.IsAvgTy() || type.IsSumTy() ||
      type.IsStatsTy()) {
    // N.B. this keeps track of the integers passed to these map
    // aggregation calls to ensure they are compatible
    // (similar to the logic in update_int_type)
    const auto &assignTy = call.vargs.at(2).type();
    auto found = agg_map_val_.find(map.ident);
    if (found != agg_map_val_.end()) {
      auto &storedTy = found->second;
      if (assignTy.IsSigned() != storedTy.IsSigned()) {
        auto updatedTy = get_promoted_int(
            storedTy, assignTy, std::nullopt, call.vargs.at(2));
        if (!updatedTy) {
          call.addError() << "Type mismatch for " << map.ident << ": "
                          << "trying to assign value of type '" << assignTy
                          << "' when map already has a type '" << storedTy
                          << "'";
        } else {
          storedTy.SetSize(updatedTy->GetSize());
          storedTy.SetSign(true);
        }
      } else {
        storedTy.SetSize(std::max(assignTy.GetSize(), storedTy.GetSize()));
      }
    } else {
      agg_map_val_[map.ident] = assignTy;
    }
  }
  if (is_final_pass() && map.type().IsNoneTy()) {
    map.addError() << "Undefined map: " + map.ident;
  }
}

SizedType *TypeResolver::get_map_type(const Map &map)
{
  const std::string &map_ident = map.ident;
  auto search = map_val_.find(map_ident);
  if (search == map_val_.end())
    return nullptr;
  return &search->second;
}

SizedType *TypeResolver::get_map_key_type(const Map &map)
{
  if (auto it = map_key_.find(map.ident); it != map_key_.end()) {
    return &it->second;
  }
  return nullptr;
}

// Semantic analysis for assigning a value of the provided type to the given
// map. The type within the passes `Map` node will be updated to reflect the
// new type, if available.
void TypeResolver::assign_map_type(Map &map,
                                   const SizedType &type,
                                   const Node *loc_node,
                                   AssignMapStatement *assignment)
{
  const std::string &map_ident = map.ident;

  if (type.IsCStructTy() && type.GetStruct() &&
      type.GetStruct()->is_tracepoint_args) {
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
      if (!storedTy.IsCompatible(type)) {
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
    } else if (storedTy.IsRecordTy()) {
      if (!storedTy.IsCompatible(type)) {
        type_mismatch_error = true;
      } else {
        auto updatedTy = get_promoted_record(storedTy, type);
        if (!updatedTy) {
          type_mismatch_error = true;
        } else {
          if (*updatedTy != type) {
            create_record_cast(assignment->expr, type, *updatedTy);
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
      if (is_final_pass()) {
        loc_node->addError()
            << "Type mismatch for " << map_ident << ": "
            << "trying to assign value of type '" << type
            << "' when map already has a type '" << storedTy << "'";
      }
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

SizedType TypeResolver::create_key_type(const SizedType &expr_type, Node &node)
{
  SizedType new_key_type = expr_type;
  if (expr_type.IsTupleTy()) {
    std::vector<SizedType> elements;
    for (const auto &field : expr_type.GetFields()) {
      SizedType keytype = create_key_type(field.type, node);
      elements.push_back(std::move(keytype));
    }
    new_key_type = CreateTuple(Struct::CreateTuple(elements));
  } else if (expr_type.IsRecordTy()) {
    std::vector<SizedType> elements;
    std::vector<std::string_view> names;
    for (const auto &field : expr_type.GetFields()) {
      SizedType keytype = create_key_type(field.type, node);
      elements.push_back(std::move(keytype));
      names.emplace_back(field.name);
    }
    new_key_type = CreateRecord(Struct::CreateRecord(elements, names));
  }

  return new_key_type;
}

std::optional<SizedType> TypeResolver::get_promoted_int(
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

std::optional<SizedType> TypeResolver::get_promoted_tuple(
    const SizedType &leftTy,
    const SizedType &rightTy)
{
  assert(leftTy.IsTupleTy() && leftTy.IsCompatible(rightTy));

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
    } else if (storedElemTy.IsRecordTy()) {
      auto new_elem = get_promoted_record(storedElemTy, assignElemTy);
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
          (storedElemTy.GetElementTy() != assignElemTy.GetElementTy())) {
        return std::nullopt;
      }
    }

    new_elems.emplace_back(storedElemTy);
  }
  return CreateTuple(Struct::CreateTuple(new_elems));
}

std::optional<SizedType> TypeResolver::get_promoted_record(
    const SizedType &storedTy,
    const SizedType &assignTy)
{
  assert(storedTy.IsRecordTy() && storedTy.IsCompatible(assignTy));

  std::vector<SizedType> new_elems;
  std::vector<std::string_view> names;
  // Maintain the ordering of the storedTy
  for (const auto &storedElemField : storedTy.GetFields()) {
    names.emplace_back(storedElemField.name);

    auto storedElemTy = storedElemField.type;
    auto assignElemTy = assignTy.GetField(storedElemField.name).type;
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
    } else if (storedElemTy.IsRecordTy()) {
      auto new_elem = get_promoted_record(storedElemTy, assignElemTy);
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
          (storedElemTy.GetElementTy() != assignElemTy.GetElementTy())) {
        return std::nullopt;
      }
    }

    new_elems.emplace_back(storedElemTy);
  }
  return CreateRecord(Struct::CreateRecord(new_elems, names));
}

// The leftExpr is optional because in cases of variable assignment,
// and map key/value adjustment we can't modify/cast the left
// but in cases of binops or if expressions we can modify/cast both
// the left and the right expressions
std::optional<SizedType> TypeResolver::update_int_type(
    const SizedType &rightTy,
    Expression &rightExpr,
    const SizedType &leftTy,
    const Expression *leftExpr)
{
  assert(leftTy.IsIntegerTy() && rightTy.IsIntegerTy());

  auto updatedTy =
      leftExpr ? get_promoted_int(leftTy, rightTy, *leftExpr, rightExpr)
               : get_promoted_int(leftTy, rightTy, std::nullopt, rightExpr);
  if (!updatedTy) {
    return std::nullopt;
  }

  if (*updatedTy != leftTy && leftExpr) {
    create_int_cast(const_cast<Expression &>(*leftExpr), *updatedTy);
  }

  if (*updatedTy != rightTy) {
    create_int_cast(rightExpr, *updatedTy);
  }

  return *updatedTy;
}

void TypeResolver::resolve_struct_type(SizedType &type, Node &node)
{
  SizedType inner_type = type;
  int pointer_level = 0;
  while (inner_type.IsPtrTy()) {
    inner_type = inner_type.GetPointeeTy();
    pointer_level++;
  }
  if (inner_type.IsCStructTy() && !inner_type.GetStruct()) {
    auto struct_type = bpftrace_.structs.Lookup(inner_type.GetName()).lock();
    if (!struct_type) {
      // Try to find the type as something other than a struct, e.g. 'char' or
      // 'uint64_t'
      auto stype = bpftrace_.btf_->get_stype(inner_type.GetName());
      if (stype.IsNoneTy()) {
        node.addError() << "Cannot resolve unknown type \""
                        << inner_type.GetName() << "\"\n";
      } else {
        type = stype;
        while (pointer_level > 0) {
          type = CreatePointer(type);
          pointer_level--;
        }
      }
    } else {
      type = CreateCStruct(inner_type.GetName(), struct_type);
      while (pointer_level > 0) {
        type = CreatePointer(type);
        pointer_level--;
      }
    }
  }
}

variable *TypeResolver::find_variable(const std::string &var_ident)
{
  if (auto *scope = find_variable_scope(var_ident)) {
    return &variables_[scope][var_ident];
  }
  return nullptr;
}

Node *TypeResolver::find_variable_scope(const std::string &var_ident, bool safe)
{
  for (auto *scope : scope_stack_) {
    if (auto search_val = variables_[scope].find(var_ident);
        search_val != variables_[scope].end()) {
      return scope;
    }
  }
  if (safe) {
    LOG(BUG) << "No scope found for variable: " << var_ident;
  }
  return nullptr;
}

Pass CreateTypeResolverPass()
{
  auto fn = [](ASTContext &ast,
               BPFtrace &b,
               CDefinitions &c_definitions,
               MapMetadata &mm,
               NamedParamDefaults &named_param_defaults,
               TypeMetadata &types,
               MacroRegistry &macro_registry) {
    TypeResolver type_resolver(
        ast, b, c_definitions, mm, named_param_defaults, types, macro_registry);
    type_resolver.analyse();
  };

  return Pass::create("TypeResolver", fn);
};

} // namespace bpftrace::ast
