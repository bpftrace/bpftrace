#include <optional>

#include "arch/arch.h"
#include "ast/passes/builtins.h"
#include "ast/passes/map_sugar.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

namespace {

class Builtins : public Visitor<Builtins, std::optional<Expression>> {
public:
  explicit Builtins(ASTContext &ast,
                    BPFtrace &bpftrace,
                    MapMetadata &map_metadata)
      : ast_(ast), bpftrace_(bpftrace), map_metadata_(map_metadata) {};

  using Visitor<Builtins, std::optional<Expression>>::visit;
  std::optional<Expression> visit(Builtin &builtin);
  std::optional<Expression> visit(Identifier &identifier);
  std::optional<Expression> visit(Expression &expression);
  std::optional<Expression> visit(Call &call);
  std::optional<Expression> check(const std::string &ident, Node &node);

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
  MapMetadata &map_metadata_;
};

} // namespace

std::optional<Expression> Builtins::check(const std::string &ident, Node &node)
{
  // N.B. this pass *should* include all the compile-time builtins (probe,
  // provider, etc.) but it presently cannot due to the expansion rules. All
  // builtins should be added here once probes are fully-expanded up front.
  //
  // All of these builtins should be directly evaluated and folded and not
  // associated with any code generation. These builtins should be kept to the
  // minimum possible set to support the standard library.
  if (ident == "__builtin_arch") {
    std::stringstream ss;
    ss << bpftrace::arch::current();
    return ast_.make_node<String>(ss.str(), Location(node.loc));
  }
  if (ident == "__builtin_safe_mode") {
    return ast_.make_node<Boolean>(bpftrace_.safe_mode_, Location(node.loc));
  }
  return std::nullopt;
}

std::optional<Expression> Builtins::visit(Builtin &builtin)
{
  return check(builtin.ident, builtin);
}

std::optional<Expression> Builtins::visit(Identifier &identifier)
{
  return check(identifier.ident, identifier);
}

std::optional<Expression> Builtins::visit(Call &call)
{
  for (size_t i = 0; i < call.vargs.size(); ++i) {
    visit(call.vargs.at(i));
  }
  if (call.func == "is_scalar") {
    if (call.vargs.size() != 1) {
      call.addError() << call.func << "() requires one argument";
      return std::nullopt;
    }
    if (auto *ma = call.vargs.at(0).as<MapAccess>()) {
      return ast_.make_node<Boolean>(map_metadata_.scalar[ma->map->ident],
                                     Location(call.loc));
    } else if (auto *map = call.vargs.at(0).as<Map>()) {
      return ast_.make_node<Boolean>(map_metadata_.scalar[map->ident],
                                     Location(call.loc));
    } else {
      call.addError() << call.func << "() expects the one argument to be a map";
    }
  }
  return std::nullopt;
}

std::optional<Expression> Builtins::visit(Expression &expression)
{
  auto replacement = visit(expression.value);
  if (replacement) {
    expression.value = replacement->value;
  }
  return std::nullopt;
}

Pass CreateBuiltinsPass()
{
  auto fn = [&](ASTContext &ast, BPFtrace &bpftrace, MapMetadata &mm) {
    Builtins builtins(ast, bpftrace, mm);
    builtins.visit(ast.root);
  };

  return Pass::create("Builtins", fn);
};

} // namespace bpftrace::ast
