#include "ast/ast.h"
#include "ast/context.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"

namespace bpftrace::ast {

class PrintCheckPass : public Visitor<PrintCheckPass> {
public:
  PrintCheckPass(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace) {};

  using Visitor<PrintCheckPass>::visit;
  void visit(Call &call);

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
};

static uint64_t clamp(const Expression &v, bool want_signed)
{
  if (want_signed) {
    if (auto *i = v.as<NegativeInteger>()) {
      return i->value;
    } else if (auto *i = v.as<Integer>()) {
      return std::min<uint64_t>(i->value, std::numeric_limits<int64_t>::max());
    }
  } else {
    if (auto *i = v.as<Integer>()) {
      return i->value;
    } else if (auto *i = v.as<NegativeInteger>()) {
      return std::max<int64_t>(static_cast<int64_t>(i->value), 0);
    }
  }

  LOG(BUG) << "v is not an integer";
  return 0;
}

void PrintCheckPass::visit(Call &call)
{
  if (call.func == "print") {
    auto &arg = call.vargs.at(0);
    auto *map = arg.as<Map>();

    if (!map || !map->value_type.IsTSeriesTy() || call.vargs.size() == 1) {
      return;
    }

    if (call.vargs.size() == 2) {
      call.addError() << "print() must provide both min and max "
                         "arguments when used on "
                         "tseries() maps.";
      return;
    }

    auto map_info = bpftrace_.resources.maps_info.find(map->ident);
    if (map_info == bpftrace_.resources.maps_info.end()) {
      LOG(BUG) << "map name: \"" << map->ident << "\" not found";
    }
    auto &tseries_args = std::get<TSeriesArgs>(map_info->second.detail);
    bool is_signed = tseries_args.value_type.IsSigned();

    uint64_t min = clamp(call.vargs.at(1), is_signed);
    uint64_t max = clamp(call.vargs.at(2), is_signed);
    if ((is_signed && static_cast<int64_t>(min) > static_cast<int64_t>(max)) ||
        (!is_signed && min > max)) {
      call.addError()
          << "print()'s min argument cannot be greater than its max argument.";
    }
    call.vargs[1] = ast_.make_node<Integer>(Location(call.loc),
                                            min,
                                            !is_signed);
    call.vargs[2] = ast_.make_node<Integer>(Location(call.loc),
                                            max,
                                            !is_signed);
  }
}

Pass CreatePrintCheckPass()
{
  return Pass::create("PrintCheck", [](ASTContext &ast, BPFtrace &b) {
    std::unordered_set<std::string> macros;
    for (Macro *macro : ast.root->macros) {
      macros.insert(macro->name);
    }

    auto pc_pass = PrintCheckPass(ast, b);
    pc_pass.visit(ast.root);
  });
}

} // namespace bpftrace::ast
