#include <algorithm>
#include <bpf/bpf.h>
#include <cassert>

#include "arch/arch.h"
#include "ast/passes/args_resolver.h"
#include "ast/tracepoint_helpers.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "dwarf_parser.h"
#include "log.h"
#include "probe_matcher.h"
#include "probe_types.h"
#include "util/result.h"

namespace bpftrace::ast {

char ArgParseError::ID;

void ArgParseError::log(llvm::raw_ostream &OS) const
{
  OS << "Could not parse arguments of \"" << probe_name_ << "\": " << detail_;
}

namespace {

class ArgsResolver : public Visitor<ArgsResolver> {
public:
  explicit ArgsResolver(ASTContext &ast,
                        BPFtrace &bpftrace,
                        ExpansionResult &ap_expansions,
                        std::vector<ProbeType> probe_types)
      : ast_(ast),
        bpftrace_(bpftrace),
        ap_expansions_(ap_expansions),
        probe_types_(std::move(probe_types))
  {
  }

  using Visitor<ArgsResolver>::visit;
  void visit(Builtin &builtin);
  void visit(Probe &probe);

private:
  void resolve_args(Probe &probe);
  Result<std::shared_ptr<Struct>> resolve_args(const AttachPoint &ap);

  ASTContext &ast_;
  BPFtrace &bpftrace_;
  ExpansionResult &ap_expansions_;
  std::vector<ProbeType> probe_types_;
  Probe *probe_ = nullptr;
};

} // namespace

void ArgsResolver::visit(Builtin &builtin)
{
  if (builtin.ident == "args" || builtin.ident == "__builtin_retval") {
    resolve_args(*probe_);
  }
}

Result<std::shared_ptr<Struct>> ArgsResolver::resolve_args(
    const AttachPoint &ap)
{
  auto probe_type = probetype(ap.provider);
  switch (probe_type) {
    case ProbeType::fentry:
    case ProbeType::fexit:
      return bpftrace_.btf_->resolve_args(
          ap.func, probe_type == ProbeType::fexit, true, false);
    case ProbeType::rawtracepoint:
      return bpftrace_.btf_->resolve_raw_tracepoint_args(ap.func);
    case ProbeType::tracepoint: {
      auto struct_name = get_tracepoint_struct_name(ap);
      auto args = bpftrace_.structs.Lookup(struct_name).lock();
      if (!args)
        return make_error<ast::ArgParseError>(ap.name(), "args not found");
      return args;
    }
    case ProbeType::uprobe: {
      Dwarf *dwarf = bpftrace_.get_dwarf(ap.target);
      if (dwarf) {
        auto args = dwarf->resolve_args(ap.func);
        if (args && args->fields.size() >= arch::Host::arguments().size()) {
          return make_error<ast::ArgParseError>(
              ap.name(),
              "\'args\' builtin is not supported for probes with stack-passed "
              "arguments.");
        }
        return args;
      }
      return make_error<ast::ArgParseError>(ap.name(),
                                            "no debuginfo found for " +
                                                ap.target);
    }
    default:
      return make_error<ast::ArgParseError>(
          ap.name(),
          "args builtin is not supported for probe type \"" + ap.provider +
              "\"");
  }
}

void ArgsResolver::resolve_args(Probe &probe)
{
  auto probe_type = probe.get_probetype();
  if (probe.attach_points.empty() ||
      std::ranges::find(probe_types_, probe_type) == probe_types_.end()) {
    return;
  }

  // Everything should be expanded by now
  assert(probe.attach_points.size() == 1);
  auto *ap = probe.attach_points.at(0);

  auto probe_args = resolve_args(*ap);

  if (!probe_args) {
    ap->addError() << probe_args.takeError();
    return;
  }

  bpftrace_.structs.Add(probe.args_typename(), std::move(*probe_args));
}

void ArgsResolver::visit(Probe &probe)
{
  probe_ = &probe;
  visit(probe.block);
}

Pass CreateArgsResolverPass(std::vector<ProbeType> &&probe_types)
{
  auto fn = [pt = std::move(probe_types)](ASTContext &ast,
                                          BPFtrace &b,
                                          ExpansionResult &ap_expansions) {
    ArgsResolver resolver(ast, b, ap_expansions, pt);
    resolver.visit(ast.root);
  };

  return Pass::create("ArgsResolver", fn);
};

} // namespace bpftrace::ast
