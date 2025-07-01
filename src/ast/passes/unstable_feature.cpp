#include <cstring>
#include <string>

#include "ast/ast.h"
#include "ast/passes/unstable_feature.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "config.h"

namespace bpftrace::ast {

namespace {

const auto MAP_DECL = "map declarations";
const auto IMPORTS = "imports";
const auto MACROS = "macros";

std::string get_warning(const std::string &feature, const std::string &config)
{
  return std::string("Script is using an unstable feature: " + feature +
                     ". To prevent this warning you must explicitly enable it "
                     "in the config e.g. ") +
         config + std::string("=enable");
}

std::string get_error(const std::string &feature, const std::string &config)
{
  return std::string(feature +
                     " feature is not enabled by default. To enable "
                     "this unstable feature, set the config flag to enable. ") +
         config + std::string("=enable");
}

class UnstableFeature : public Visitor<UnstableFeature> {
public:
  explicit UnstableFeature(BPFtrace &bpftrace) : bpftrace_(bpftrace) {};

  using Visitor<UnstableFeature>::visit;
  void visit(MapDeclStatement &decl);
  void visit(Import &imp);
  void visit(Macro &macro);

private:
  BPFtrace &bpftrace_;
  // This set is so we don't warn multiple times for the same feature.
  std::unordered_set<std::string> warned_features;
};

} // namespace

// Note: for logged warnings we don't want to use the AST node's `addWarning()`
// as this also prints the code location which is overly noisy. We just
// want to notify users they're using an unstable feature. For errors it's ok to
// print the location because the script is going to fail anyway.

void UnstableFeature::visit(MapDeclStatement &decl)
{
  if (bpftrace_.config_->unstable_map_decl == ConfigUnstable::error) {
    decl.addError() << get_error(MAP_DECL, UNSTABLE_MAP_DECL);
    return;
  }
  if (bpftrace_.config_->unstable_map_decl == ConfigUnstable::warn &&
      !warned_features.contains(UNSTABLE_MAP_DECL)) {
    LOG(WARNING) << get_warning(MAP_DECL, UNSTABLE_MAP_DECL);
    warned_features.insert(UNSTABLE_MAP_DECL);
  }
}

void UnstableFeature::visit(Import &imp)
{
  if (bpftrace_.config_->unstable_import == ConfigUnstable::error) {
    imp.addError() << get_error(IMPORTS, UNSTABLE_IMPORT);
    return;
  }

  if (bpftrace_.config_->unstable_import == ConfigUnstable::warn &&
      !warned_features.contains(UNSTABLE_IMPORT)) {
    LOG(WARNING) << get_warning(IMPORTS, UNSTABLE_IMPORT);
    warned_features.insert(UNSTABLE_IMPORT);
  }
}

void UnstableFeature::visit(Macro &macro)
{
  if (bpftrace_.config_->unstable_macro == ConfigUnstable::error) {
    macro.addError() << get_error(MACROS, UNSTABLE_MACRO);
    return;
  }
  if (bpftrace_.config_->unstable_macro == ConfigUnstable::warn &&
      !warned_features.contains(UNSTABLE_MACRO)) {
    LOG(WARNING) << get_warning(MACROS, UNSTABLE_MACRO);
    warned_features.insert(UNSTABLE_MACRO);
  }
}

Pass CreateUnstableFeaturePass()
{
  return Pass::create("UnstableFeature", [](ASTContext &ast, BPFtrace &b) {
    auto configs = UnstableFeature(b);
    configs.visit(ast.root);
  });
};

} // namespace bpftrace::ast
