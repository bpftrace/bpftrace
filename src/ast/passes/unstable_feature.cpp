#include <cstring>
#include <format>
#include <string>

#include "ast/ast.h"
#include "ast/passes/unstable_feature.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "config.h"

namespace bpftrace::ast {

namespace {

std::string get_warning(const std::string &feature)
{
  return std::format("Script is using an unstable feature. To prevent this "
                     "warning you must explicitly enable the unstable "
                     "feature in the config e.g. {}=enable",
                     feature);
}

std::string get_error(std::string &&feature)
{
  return std::format(
      "Feature not enabled by default. To enable "
      "this unstable feature, set the config flag to enable. {}=enable",
      feature);
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

void UnstableFeature::visit(MapDeclStatement &decl)
{
  if (bpftrace_.config_->unstable_map_decl == ConfigUnstable::error) {
    decl.addError() << get_error(UNSTABLE_MAP_DECL);
    return;
  }
  if (bpftrace_.config_->unstable_map_decl == ConfigUnstable::warn &&
      !warned_features.contains(UNSTABLE_MAP_DECL)) {
    decl.addWarning() << get_warning(UNSTABLE_MAP_DECL);
    warned_features.insert(UNSTABLE_MAP_DECL);
  }
}

void UnstableFeature::visit(Import &imp)
{
  if (bpftrace_.config_->unstable_import == ConfigUnstable::error) {
    imp.addError() << get_error(UNSTABLE_IMPORT);
    return;
  }

  if (bpftrace_.config_->unstable_import == ConfigUnstable::warn &&
      !warned_features.contains(UNSTABLE_IMPORT)) {
    imp.addWarning() << get_warning(UNSTABLE_IMPORT);
    warned_features.insert(UNSTABLE_IMPORT);
  }
}

void UnstableFeature::visit(Macro &macro)
{
  if (bpftrace_.config_->unstable_macro == ConfigUnstable::error) {
    macro.addError() << get_error(UNSTABLE_MACRO);
    return;
  }
  if (bpftrace_.config_->unstable_macro == ConfigUnstable::warn &&
      !warned_features.contains(UNSTABLE_MACRO)) {
    macro.addWarning() << get_warning(UNSTABLE_MACRO);
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
