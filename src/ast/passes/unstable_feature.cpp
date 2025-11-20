#include <cstring>
#include <string>
#include <utility>

#include "ast/ast.h"
#include "ast/passes/unstable_feature.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "config.h"
#include "log.h"

namespace bpftrace::ast {

namespace {

const auto MAP_DECL = "map declarations";
const auto IMPORTS = "imports";
const auto IMPORT_STATEMENTS = "import statements";
const auto TSERIES = "tseries";
const auto ADDR = "address-of operator (&)";
const auto TYPEINFO = "typeinfo";

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
  void visit(MapAddr &map_addr);
  void visit(VariableAddr &var_addr);
  void visit(RootImport &imp);
  void visit(StatementImport &imp);
  void visit(Call &call);
  void visit(Typeinfo &typeinfo);

private:
  BPFtrace &bpftrace_;
  // This set is so we don't warn multiple times for the same feature.
  std::unordered_set<std::string> warned_features;

  void check_unstable_addr(Node &node);
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

void UnstableFeature::visit(StatementImport &imp)
{
  if (bpftrace_.config_->unstable_import_statement == ConfigUnstable::error) {
    imp.addError()
        << "Import statements that are not at the top level are primarily for "
           "the standard library. If this is functionality you need, please "
           "file an issue to explain why.";
    return;
  }

  if (bpftrace_.config_->unstable_import_statement == ConfigUnstable::warn &&
      !warned_features.contains(UNSTABLE_IMPORT_STATEMENT)) {
    LOG(WARNING) << get_warning(IMPORT_STATEMENTS, UNSTABLE_IMPORT_STATEMENT);
    warned_features.insert(UNSTABLE_IMPORT_STATEMENT);
  }
}

void UnstableFeature::visit(RootImport &imp)
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

void UnstableFeature::visit(Call &call)
{
  if (call.func != "tseries") {
    return;
  }

  if (bpftrace_.config_->unstable_tseries == ConfigUnstable::error) {
    call.addError() << get_error(TSERIES, UNSTABLE_TSERIES);
    return;
  }
  if (bpftrace_.config_->unstable_tseries == ConfigUnstable::warn &&
      !warned_features.contains(UNSTABLE_TSERIES)) {
    LOG(WARNING) << get_warning(TSERIES, UNSTABLE_TSERIES);
    warned_features.insert(UNSTABLE_TSERIES);
  }
}

void UnstableFeature::visit(Typeinfo &typeinfo)
{
  if (bpftrace_.config_->unstable_typeinfo == ConfigUnstable::error) {
    typeinfo.addError() << get_error(TYPEINFO, UNSTABLE_TYPEINFO);
  } else if (bpftrace_.config_->unstable_typeinfo == ConfigUnstable::warn &&
             !warned_features.contains(UNSTABLE_TYPEINFO)) {
    LOG(WARNING) << get_warning(TYPEINFO, UNSTABLE_TYPEINFO);
    warned_features.insert(UNSTABLE_TYPEINFO);
  }
}

void UnstableFeature::check_unstable_addr(Node &node)
{
  if (bpftrace_.config_->unstable_addr == ConfigUnstable::error) {
    node.addError() << get_error(ADDR, UNSTABLE_ADDR);
    return;
  }

  if (bpftrace_.config_->unstable_addr == ConfigUnstable::warn &&
      !warned_features.contains(UNSTABLE_ADDR)) {
    LOG(WARNING) << get_warning(ADDR, UNSTABLE_ADDR);
    warned_features.insert(UNSTABLE_ADDR);
  }
}

void UnstableFeature::visit(MapAddr &map_addr)
{
  check_unstable_addr(map_addr);
}

void UnstableFeature::visit(VariableAddr &var_addr)
{
  check_unstable_addr(var_addr);
}

Pass CreateUnstableFeaturePass()
{
  return Pass::create("UnstableFeature", [](ASTContext &ast, BPFtrace &b) {
    auto configs = UnstableFeature(b);
    configs.visit(ast.root);
  });
};

} // namespace bpftrace::ast
