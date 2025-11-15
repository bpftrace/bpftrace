#include <bpf/bpf.h>
#include <cassert>

#include "arch/arch.h"
#include "ast/passes/args_resolver.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "dwarf_parser.h"
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
  explicit ArgsResolver(BPFtrace &bpftrace) : bpftrace_(bpftrace) {};

  using Visitor<ArgsResolver>::visit;
  void visit(Builtin &builtin);
  void visit(Probe &probe);

private:
  void resolve_args(Probe &probe);
  Result<std::shared_ptr<Struct>> resolve_args(const AttachPoint &ap);

  BPFtrace &bpftrace_;
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
      return nullptr;
  }
}

void ArgsResolver::resolve_args(Probe &probe)
{
  if (probe.attach_points.empty())
    return;

  // Everything should be expanded by now
  assert(probe.attach_points.size() == 1);
  auto *ap = probe.attach_points.at(0);

  auto probe_args = resolve_args(*ap);

  if (!probe_args) {
    ap->addError() << probe_args.takeError();
    return;
  }

  auto type_name = probe.args_typename();
  if (!type_name) {
    ap->addError() << "Cannot resolve ambiguous types.";
    return;
  }
  bpftrace_.structs.Add(*type_name, std::move(*probe_args));
}

void ArgsResolver::visit(Probe &probe)
{
  probe_ = &probe;
  visit(probe.block);
}

Pass CreateArgsResolverPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) {
    ArgsResolver resolver(b);
    resolver.visit(ast.root);
  };

  return Pass::create("ArgsResolver", fn);
};

} // namespace bpftrace::ast
