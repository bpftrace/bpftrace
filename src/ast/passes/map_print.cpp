#include <set>
#include <vector>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/map_print.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

class MapFinder : public Visitor<MapFinder> {
public:
  MapFinder() = default;

  using Visitor<MapFinder>::visit;
  void visit(AssignScalarMapStatement &assign)
  {
    Visitor<MapFinder>::visit(assign);
    idents.insert(assign.map->ident);
  }
  void visit(AssignMapStatement &assign)
  {
    Visitor<MapFinder>::visit(assign);
    idents.insert(assign.map->ident);
  }

  std::set<std::string> idents;
};

Pass CreateMapPrintPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) -> MapPrintAdded {
    if (!b.config_->print_maps_on_exit) {
      return {};
    }

    MapFinder finder;
    finder.visit(ast.root);
    if (finder.idents.empty()) {
      return {};
    }

    // Construct an additional exit probe, which will iterate over
    // all the maps in the program and print out their value.
    auto print = [&](Expression expr) {
      return ast.make_node<ExprStatement>(
          ast.root->loc,
          ast.make_node<Call>(ast.root->loc,
                              "print",
                              std::vector<Expression>({ expr })));
    };
    auto print_str = [&](std::string s) {
      return print(ast.make_node<String>(ast.root->loc, s));
    };
    auto print_map = [&](std::string s) {
      return print(ast.make_node<Map>(ast.root->loc, s));
    };
    std::vector<Statement> stmts;
    stmts.emplace_back(print_str(""));
    stmts.emplace_back(print_str(""));
    for (const auto &ident : finder.idents) {
      stmts.emplace_back(print_map(ident));
    }
    auto *none = ast.make_node<None>(ast.root->loc);
    auto *block = ast.make_node<BlockExpr>(ast.root->loc, stmts, none);
    auto *attach_point = ast.make_node<AttachPoint>(ast.root->loc,
                                                    "end",
                                                    false);
    auto *probe = ast.make_node<Probe>(
        ast.root->loc, std::vector<AttachPoint *>({ attach_point }), block);
    ast.root->probes.push_back(probe);
    return {};
  };

  return Pass::create("MapPrint", fn);
}

} // namespace bpftrace::ast
