#include <iostream>
#include <sstream>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/visitor.h"
#include "gendoc.h"

using namespace bpftrace::ast;

namespace {
class Gendoc : public Visitor<Gendoc> {
public:
  using Visitor<Gendoc>::visit;
  void visit(Macro &macro);
  void visit(MapDeclStatement &map_decl);
  void visit(Subprog &subprog);

  // Macros may have multiple variants; the first is the name of the
  // macro, while the second map indexes the specific variant.
  std::map<std::string, std::map<std::string, std::vector<std::string>>> macros;

  // Functions always have a single name and variant.
  std::map<std::string, std::vector<std::string>> functions;

  // Maps are always indexed by map.
  std::map<std::string, std::vector<std::string>> maps;
};
} // namespace

void Gendoc::visit(Macro &macro)
{
  // We only skip macros if there is no prior definition.
  const auto &comments = macro.loc->comments();
  if (comments.empty() && !macros.contains(macro.name)) {
    return;
  }
  auto &map = macros[macro.name];
  std::stringstream ss;
  if (!macro.vargs.empty()) {
    ss << macro.name << "(";
    bool first = true;
    for (const auto &arg : macro.vargs) {
      if (!first) {
        ss << ", ";
      }
      if (auto *ident = arg.as<Identifier>()) {
        ss << ident->ident;
      } else if (auto *map = arg.as<Map>()) {
        ss << map->ident;
      } else if (auto *var = arg.as<Variable>()) {
        ss << var->ident;
      }
      first = false;
    }
    ss << ")";
  } else {
    ss << macro.name;
  }
  map[ss.str()] = comments;
}

void Gendoc::visit(bpftrace::ast::MapDeclStatement &map_decl)
{
  const auto &comments = map_decl.loc->comments();
  if (comments.empty()) {
    return;
  }
  maps[map_decl.ident] = comments;
}

void Gendoc::visit(Subprog &subprog)
{
  const auto &comments = subprog.loc->comments();
  if (comments.empty()) {
    return;
  }
  functions[subprog.name] = comments;
}

namespace bpftrace {

void gendoc(ASTContext &ast, std::ostream &out)
{
  Gendoc g;
  g.visit(ast.root);

  out << "## Helpers";
  for (const auto &[name, variants] : g.macros) {
    out << "### " << name << "\n";
    std::stringstream all_docs;
    for (const auto &[variant, docs] : variants) {
      out << "- " << variant << "\n";
      // all_docs << docs;
    }
    out << "\n";
    out << all_docs.str();
  }
  for (const auto &[name, docs] : g.functions) {
    out << "### " << name << "\n";
    // out << docs;
  }

  out << "## Maps";
  for (const auto &[name, docs] : g.maps) {
    out << "### " << name << "\n";
    // out << docs;
  }
}

} // namespace bpftrace
