#include <bpf/bpf.h>
#include <cassert>

#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/context_resolver.h"
#include "ast/passes/macro_expansion.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "dwarf_parser.h"
#include "probe_matcher.h"
#include "probe_types.h"
#include "struct.h"
#include "tracepoint_format_parser.h"
#include "util/result.h"

namespace bpftrace::ast {

// Tracks the resolved arguments and how they should be accessed.
struct ResolvedContext {
  // May be null, if no types are available. In this case, only arg0, arg1, etc.
  // translations will work and casts must be applied manually.
  //
  // Effectively this is used only to convert `arg.foo` into (some_type)arg(N).
  // If the underlying context type is properly typed already, then this should
  // be null and the type below should be rich enough to do field resolution.
  // For example, in the case of an fentry, `arg.foo` should be converted to
  // `ctx.foo`.
  std::shared_ptr<Struct> args;

  // The context type for the specific probe. This may support named fields
  // for `args.foo`, but may also just be struct pt_regs, etc. The translation
  // for `args` is strictly controlled by the `args` value above.
  SizedType type;
};

class ContextResolver : public Visitor<ContextResolver, bool> {
public:
  explicit ContextResolver(ASTContext &ast,
                           BPFtrace &bpftrace,
                           MacroRegistry &registry,
                           FunctionInfo &func_info)
      : ast_(ast),
        bpftrace_(bpftrace),
        registry_(registry),
        func_info_(func_info) {};

  using Visitor<ContextResolver, bool>::visit;
  bool visit(Builtin &builtin);
  bool visit(Expression &expr);
  bool visit(Subprog &subprog);
  bool visit(Probe &probe);

private:
  // Creates a placeholder in the struct manager for the named struct, and
  // adds to the BTF set for future resolution. This is only useful for certain
  // kernel structs, e.g. struct pt_regs, or tracepoint structures.
  static std::shared_ptr<Struct> load_struct(BPFtrace &bpftrace,
                                             const std::string &name);

  // Attempt to resolve the context for the given attachpoint.
  static Result<ResolvedContext> resolve_context(BPFtrace &bpftrace,
                                                 const AttachPoint &ap,
                                                 FunctionInfo &func_info);

  // Resolve the context for a specific node, errors may be applied. If true
  // is returned, then the context was resolved successfully.
  //
  // When the context has been resolved, the type will be attach to the node.
  bool resolve_context(Builtin &builtin);

  Expression rewrite(Node &node, const std::string &field_name);
  Expression rewrite(Node &node, size_t field_index);

  ASTContext &ast_;
  BPFtrace &bpftrace_;
  MacroRegistry &registry_;
  FunctionInfo &func_info_;

  // Probe currently being visited.
  Probe *probe_ = nullptr;

  // Tracks the current resolved context for rewriting. If no context or
  // arguments are ever encountered, then this may be uninitialized.
  std::optional<ResolvedContext> current_resolved_context_;
};

std::shared_ptr<Struct> ContextResolver::load_struct(BPFtrace &bpftrace,
                                                     const std::string &name)
{
  auto s = bpftrace.structs.LookupOrAdd(name, 0);
  bpftrace.btf_set_.insert(name);
  return s.lock();
}

Result<ResolvedContext> ContextResolver::resolve_context(
    BPFtrace &bpftrace,
    const AttachPoint &ap,
    FunctionInfo &func_info)
{
  auto probe_type = probetype(ap.provider);
  switch (probe_type) {
    case ProbeType::fentry:
    case ProbeType::fexit: {
      auto args = bpftrace.btf_->resolve_args(ap.func,
                                              probe_type == ProbeType::fexit,
                                              true,
                                              false,
                                              func_info.kernel_info());
      if (!args)
        return args.takeError();
      return ResolvedContext{
        .args = nullptr, // The context is typed; don't do any resolution here.
        .type = CreatePointer(CreateCStruct(std::shared_ptr<Struct>(*args)),
                              AddrSpace::none),
      };
    }
    case ProbeType::rawtracepoint: {
      auto args = bpftrace.btf_->resolve_raw_tracepoint_args(
          ap.func, func_info.kernel_info());
      if (!args)
        return args.takeError();
      return ResolvedContext{
        .args = nullptr, // See above, the context is typed.
        .type = CreatePointer(CreateCStruct(std::shared_ptr<Struct>(*args)),
                              AddrSpace::none)
      };
    }
    case ProbeType::tracepoint: {
      TracepointFormatParser parser(ap.target, ap.func, bpftrace);
      auto ok = parser.parse_format_file();
      if (!ok)
        return ok.takeError();
      auto args = parser.get_tracepoint_struct();
      if (!args)
        return args.takeError();
      // N.B. the structure itself will have pointers and fields that have
      // user annotations, which will change the address space as they are
      // followed. The `get_tracepoint_struct` function will mark anything
      // ambiguous as `AddrSpace::kernel` when required.
      return ResolvedContext{
        .args = nullptr, // Loosely typed, still don't convert.
        .type = CreatePointer(CreateCStruct(std::move(*args)), AddrSpace::none),
      };
    }
    case ProbeType::uprobe:
    case ProbeType::uretprobe: {
      Dwarf *dwarf = bpftrace.get_dwarf(ap.target);
      if (dwarf) {
        // Register-based, use cast, user address space. Note that limits on the
        // argument count are imposed by the standard library macros, not here.
        auto args = dwarf->resolve_args(ap.func);
        if (args) {
          for (auto &field : args->fields) {
            field.type.SetAS(AddrSpace::user);
          }
          return ResolvedContext{
            .args = args, // Perform automatic conversion.
            .type = CreatePointer(CreateCStruct(
                                      load_struct(bpftrace, "struct pt_regs")),
                                  AddrSpace::none)
          };
        }
      }
      return ResolvedContext{
        .args = nullptr, // No conversion available.
        .type = CreatePointer(CreateCStruct(
                                  load_struct(bpftrace, "struct pt_regs")),
                              AddrSpace::none)
      };
    }
    case ProbeType::kprobe:
    case ProbeType::kretprobe: {
      auto args = bpftrace.btf_->resolve_args(
          ap.func, false, false, false, func_info.kernel_info());
      if (!args) {
        return ResolvedContext{
          .args = nullptr, // No field names available.
          .type = CreatePointer(CreateCStruct(
                                    load_struct(bpftrace, "struct pt_regs")),
                                AddrSpace::none)
        };
      }
      return ResolvedContext{
        .args = std::move(*args), // Permit automatic resolution.
        .type = CreatePointer(CreateCStruct(
                                  load_struct(bpftrace, "struct pt_regs")),
                              AddrSpace::none)
      };
    }
    case ProbeType::watchpoint:
    case ProbeType::hardware:
    case ProbeType::software:
    case ProbeType::interval:
    case ProbeType::profile: {
      // Only perf-event based data.
      return ResolvedContext{
        .args = nullptr,
        .type = CreatePointer(
            CreateCStruct(load_struct(bpftrace, "struct bpf_perf_event_data")),
            AddrSpace::none)
      };
    }
    case ProbeType::iter:
      // The type depends on the iterator.
      return ResolvedContext{
        .args = nullptr,
        .type = CreatePointer(
            CreateCStruct(load_struct(bpftrace, "struct bpf_iter__" + ap.func)),
            AddrSpace::none)
      };
    default:
      // We don't yet have a valid context for this probe.
      return ResolvedContext{
        .args = nullptr,
        .type = CreatePointer(CreateVoid()),
      };
  }
}

bool ContextResolver::resolve_context(Builtin &builtin)
{
  // Have we already resolved?
  if (current_resolved_context_) {
    return true;
  }

  // Everything should be expanded by now.
  assert(probe_ != nullptr);
  if (probe_->attach_points.empty()) {
    return false; // Just ignore this, it will be pruned.
  }
  assert(probe_->attach_points.size() == 1);
  auto result = resolve_context(bpftrace_,
                                *probe_->attach_points.at(0),
                                func_info_);
  if (!result) {
    builtin.addError() << result.takeError();
    return false;
  }
  auto resolved = std::move(*result);

  // Add to our structs for use later on. When types are self-contained
  // and we do not rely on side channels e.g. during codegen, we may be
  // able to drop this code.
  if (resolved.args != nullptr) {
    auto args_type_name = probe_->args_typename();
    if (args_type_name && !bpftrace_.structs.Has(*args_type_name)) {
      bpftrace_.structs.Add(*args_type_name,
                            std::shared_ptr<Struct>(resolved.args));
    }
  }

  // Store for later use in rewrite.
  current_resolved_context_ = std::move(resolved);
  return true;
}

bool ContextResolver::visit(Builtin &builtin)
{
  if (builtin.ident == "ctx") {
    if (resolve_context(builtin)) {
      // Always set the type on the context.
      builtin.builtin_type = current_resolved_context_->type;
    }
    return false; // Never rewitten, even with errors.
  }

  // For other variables, we will rewrite only if the context can
  // be resolved or has been resolved already.
  if (builtin.argx() || builtin.ident == "args") {
    return resolve_context(builtin);
  }
  if (builtin.ident == "__builtin_retval") {
    return resolve_context(builtin);
  }

  // Does not need rewritten.
  return false;
}

bool ContextResolver::visit(Expression &expr)
{
  // Check if this is a FieldAccess that needs rewriting.
  if (auto *field_access = expr.as<FieldAccess>()) {
    // Visit the field access to get the struct definition.
    bool needs_rewrite = visit(field_access->expr);
    if (!needs_rewrite) {
      return false;
    }
    // Rewrite the entire field access using the stored resolution info.
    auto new_expr = rewrite(*field_access, field_access->field);
    expr.value = new_expr.value;
    return visit(expr);
  }

  // Check if this is an args, argx, or __builtin_retval that needs rewriting.
  if (auto *builtin = expr.as<Builtin>()) {
    bool needs_rewrite = visit(*builtin);
    if (!needs_rewrite) {
      return false;
    }
    if (auto arg_num = builtin->argx()) {
      // Rewrite to use a simple integer access.
      auto new_expr = rewrite(*builtin, *arg_num);
      expr.value = new_expr.value;
      return visit(expr);
    } else if (builtin->ident == "__builtin_retval") {
      if (current_resolved_context_->type.IsPtrTy() &&
          current_resolved_context_->type.GetPointeeTy().IsCStructTy() &&
          current_resolved_context_->type.GetPointeeTy().HasField(
              RETVAL_FIELD_NAME)) {
        // If we have BTF, we will have rewritten the return
        // value field to the special sentinel value `$retval`.
        auto new_expr = rewrite(*builtin, RETVAL_FIELD_NAME);
        expr.value = new_expr.value;
        return visit(expr);
      } else {
        // Arguments need that a register translation is necessary, which
        // is handled automatically by the `return_value` macro.
        expr.value = ast_.make_node<Call>(builtin->loc,
                                          "return_value",
                                          ExpressionList());
        expand_macro(ast_, expr, registry_);
        return visit(expr);
      }
    } else if (builtin->ident == "args") {
      // So this is *not* a field access on args, but simply args
      // used directly for something else.
      if (current_resolved_context_->args) {
        // We have argument type info that requires register-based translation.
        // Create a Record with all arguments by calling arg(N) for each field.
        NamedArgumentList named_args;
        for (size_t i = 0; i < current_resolved_context_->args->fields.size();
             i++) {
          const auto &field = current_resolved_context_->args->fields[i];
          // Skip return value field if present.
          if (field.name == RETVAL_FIELD_NAME) {
            continue;
          }
          auto arg_expr = rewrite(*builtin, i);
          auto *named_arg = ast_.make_node<NamedArgument>(builtin->loc,
                                                          field.name,
                                                          std::move(arg_expr));
          named_args.push_back(named_arg);
        }
        expr.value = ast_.make_node<Record>(builtin->loc,
                                            std::move(named_args));
        return visit(expr);
      }
      // The context is well-typed, just dereference it directly.
      builtin->ident = "ctx";
      expr.value = ast_.make_node<Unop>(builtin->loc, builtin, Operator::MUL);
      visit(expr);
      // If there is a field access immediately following this, we
      // still treat it as a raw context access. The above rewrite
      // merely handles the case with a raw `args`, e.g. a print.
      return true;
    }
  }

  // For other expressions, visit normally and propagate struct info. If the
  // expression has just been rewritten, this should always return false.
  return visit(expr.value);
}

bool ContextResolver::visit(Subprog &subprog)
{
  probe_ = nullptr;
  current_resolved_context_.reset();
  return Visitor<ContextResolver, bool>::visit(subprog);
}

bool ContextResolver::visit(Probe &probe)
{
  probe_ = &probe;
  current_resolved_context_.reset();
  return Visitor<ContextResolver, bool>::visit(probe);
}

Expression ContextResolver::rewrite(Node &node, const std::string &field_name)
{
  assert(current_resolved_context_);

  // Does this even have fields? If we have an expression list `args.foo` and
  // there are no args, then this is a native BTF type and we should just
  // rewrite to ctx.
  if (!current_resolved_context_->args) {
    auto *ctx_ident = ast_.make_node<Builtin>(node.loc, "ctx");
    auto *field_access = ast_.make_node<FieldAccess>(node.loc,
                                                     ctx_ident,
                                                     field_name);
    return field_access;
  }

  // Try to find a matching field.
  for (size_t field_index = 0;
       field_index < current_resolved_context_->args->fields.size();
       field_index++) {
    const auto &field = current_resolved_context_->args->fields[field_index];
    if (field.name == field_name) {
      return rewrite(node, field_index);
    }
  }

  // Nothing matched the field provided.
  node.addError() << "Unknown field: " << field_name;
  return ast_.make_node<None>(node.loc);
}

Expression ContextResolver::rewrite(Node &node, size_t field_index)
{
  assert(current_resolved_context_);

  // If there is no argument translation provided (the context is well-typed),
  // then we attempt to treat this as indexing the context type.
  if (!current_resolved_context_->args &&
      current_resolved_context_->type.IsPtrTy() &&
      current_resolved_context_->type.GetPointeeTy().IsCStructTy()) {
    const auto pointee = current_resolved_context_->type.GetPointeeTy();
    const auto &fields = pointee.GetFields();
    // Special case: for tracepoints, we ignore the common fields and any fields
    // that start with __ for index-based arguments.
    size_t __common_fields = 0;
    while (probe_ && probe_->attach_points.size() == 1 &&
           probetype(probe_->attach_points[0]->provider) ==
               ProbeType::tracepoint &&
           fields.size() > __common_fields &&
           (fields[__common_fields].name.starts_with("common_") ||
            fields[__common_fields].name.starts_with("__"))) {
      __common_fields++;
    }
    // If we have proper types, we index into the given BTF type. So for
    // example, `args1` becomes `args.foo` if `foo` is the second argument.
    if (fields.size() > __common_fields + field_index &&
        !fields[__common_fields + field_index].name.empty()) {
      return rewrite(node, fields[__common_fields + field_index].name);
    }
  }

  // Register-based: rewrite to (field_type)arg(field_index).
  auto *index = ast_.make_node<Integer>(node.loc,
                                        static_cast<uint64_t>(field_index));
  auto *call = ast_.make_node<Call>(node.loc, "arg", ExpressionList({ index }));
  auto expr = Expression(call);
  expand_macro(ast_, expr, registry_);

  // If we do have types for these arguments, then we can automatically cast to
  // the suitable type. If this is beyond the number of fields, we just let this
  // be the raw register associated with that conventional argument number.
  if (current_resolved_context_->args &&
      field_index < current_resolved_context_->args->fields.size()) {
    const auto &field_type =
        current_resolved_context_->args->fields.at(field_index).type;
    // Create cast with the field type that includes address space.
    auto *type_node = ast_.make_node<Typeof>(node.loc, field_type);
    expr.value = ast_.make_node<Cast>(node.loc, type_node, expr);
  }

  return expr;
}

// ContextLifter lifts all uses of the context into a single bound variable. It
// is incumbent on subsequent passes (such as the legacy field analyser), to be
// able to walk through this assignment and resolve type information.
//
// This lift is done to ensure that the context can be automatically captured
// and resolved in all nested contexts, such as anonymous functions, loops, etc.
//
// This also verifies that no `args` or `argx` nodes are left.
class ContextLifter : public Visitor<ContextLifter> {
public:
  explicit ContextLifter(ASTContext &ast) : ast_(ast) {};

  using Visitor<ContextLifter>::visit;
  void visit(Builtin &builtin);
  void visit(Probe &probe);
  void visit(Expression &expr);

private:
  ASTContext &ast_;
  Builtin *ctx_ = nullptr;
};

void ContextLifter::visit(Builtin &builtin)
{
  if (builtin.ident == "args" || builtin.argx()) {
    builtin.addError() << "Errant args, did ContextResolver fail?";
  } else if (builtin.ident == "__builtin_retval") {
    builtin.addError() << "Errant retval, did ContextResolver fail?";
  }
}

void ContextLifter::visit(Probe &probe)
{
  ctx_ = nullptr;
  Visitor<ContextLifter>::visit(probe);

  if (ctx_) {
    // Inject a declaration into the block. This gives something
    // that will automatically be plumbed in subsequent passes.
    probe.block->stmts.insert(probe.block->stmts.begin(),
                              ast_.make_node<AssignVarStatement>(
                                  probe.block->loc,
                                  ast_.make_node<Variable>(probe.block->loc,
                                                           "ctx"),
                                  ctx_));
  }
}

void ContextLifter::visit(Expression &expr)
{
  if (auto *builtin = expr.as<Builtin>()) {
    if (builtin->ident == "ctx") {
      // Transform into a local variable that will automatically be
      // lifted in subsequent passes into loops and functions. The
      // first context reference is captured and used in the assignment,
      // this is important because it has been annotated with a type.
      if (ctx_ == nullptr) {
        ctx_ = builtin;
      }
      expr.value = ast_.make_node<Variable>(builtin->loc, "ctx");
    }
  }
}

Pass CreateContextResolverPass()
{
  auto fn = [](ASTContext &ast,
               BPFtrace &b,
               MacroRegistry &registry,
               FunctionInfo &func_info) {
    ContextResolver resolver(ast, b, registry, func_info);
    resolver.visit(ast.root);
    if (ast.diagnostics().ok()) {
      ContextLifter lifter(ast);
      lifter.visit(ast.root);
    }
    return ContextTypes{};
  };

  return Pass::create("ContextResolver", fn);
};

} // namespace bpftrace::ast
