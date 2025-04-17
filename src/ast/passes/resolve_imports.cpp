#include <filesystem>
#include <fstream>
#include <sstream>

#include "ast/passes/resolve_imports.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "driver.h"
#include "util/format.h"

namespace bpftrace::ast {

class ResolveImports : public Visitor<ResolveImports> {
public:
  ResolveImports(BPFtrace &bpftrace,
                 const std::vector<std::filesystem::path> &paths)
      : bpftrace_(bpftrace), paths_(paths) {};

  using Visitor<ResolveImports>::visit;
  void visit(Import &imp);

  Imports imports;

private:
  // Various import formats.
  Result<OK> importAny(Import &imp, const std::filesystem::path &path);
  Result<OK> importNative(Import &imp, const std::filesystem::path &path);
  Result<OK> importObject(Import &imp, const std::filesystem::path &path);

  BPFtrace &bpftrace_;
  const std::vector<std::filesystem::path> &paths_;
};

Result<OK> ResolveImports::importNative(Import &imp,
                                        const std::filesystem::path &path)
{
  if (imports.native.contains(path)) {
    return OK(); // Already added.
  }

  // Load the file.
  std::ifstream file(path);
  if (file.fail()) {
    imp.addError() << "error reading import '" << path
                   << "': " << std::strerror(errno);
    return OK();
  }
  std::stringstream buf;
  buf << file.rdbuf();

  // Construct our context.
  auto [it, added] = imports.native.try_emplace(
      path, std::make_unique<ASTContext>(path.string(), buf.str()));
  assert(added);
  auto &ast = it->second;

  // Perform the basic parse pass. Note that this parse is done extremely
  // early, and does zero expansion or parsing of attachpoints, etc.
  PassManager pm;
  pm.put(*ast);
  pm.put(bpftrace_);
  pm.add(CreateParsePass());

  // Attempt to parse the source.
  auto ok = pm.run();
  if (!ok) {
    return ok.takeError();
  }

  // Disallow `config` blocks as they cannot be merged.
  if (ast->root->config != nullptr && !ast->root->config->stmts.empty()) {
    ast->root->config->addError() << "invalid `config` within import";
  }

  return OK();
}

Result<OK> ResolveImports::importObject(Import &imp,
                                        const std::filesystem::path &path)
{
  if (imports.objects.contains(path)) {
    return OK(); // Already added.
  }

  // Load the file.
  std::ifstream file(path);
  if (file.fail()) {
    imp.addError() << "error reading import '" << path
                   << "': " << std::strerror(errno);
    return OK();
  }
  std::stringstream buf;
  buf << file.rdbuf();

  // Add for later.
  auto [_, added] = imports.objects.emplace(path, buf.str());
  assert(added);
  return OK();
}

Result<OK> ResolveImports::importAny(Import &imp,
                                     const std::filesystem::path &path)
{
  if (std::filesystem::is_directory(path)) {
    for (const auto &entry : std::filesystem::directory_iterator(path)) {
      auto ok = importAny(imp, entry);
      if (!ok) {
        return ok.takeError();
      }
    }
    return OK();
  } else {
    if (path.extension() == ".bt") {
      return importNative(imp, path);
    } else if (path.extension() == ".o") {
      return importObject(imp, path);
    } else {
      imp.addError() << "unknown import type: " << path.filename();
      return OK();
    }
  }
}

void ResolveImports::visit(Import &imp)
{
  if (!bpftrace_.config_->unstable_import) {
    imp.addError() << "Imports are not enabled by default. To enable "
                      "this unstable feature, set this config flag to 1 "
                      "e.g. unstable_import=1";
    return;
  }

  std::vector<std::string> checked;
  for (const auto &import_path : paths_) {
    // Check to see if this specific file exists.
    auto path = import_path / imp.name;
    checked.emplace_back(path.string());
    if (!std::filesystem::exists(path)) {
      continue; // No file found.
    }

    // Attempt the import.
    auto ok = importAny(imp, path);
    if (!ok) {
      imp.addError() << "import error: " << ok.takeError();
    }

    // Success.
    return;
  }

  // Unable to find a suitable import.
  auto &err = imp.addError();
  err << "Unable to find suitable path for import";
  err.addHint() << "checked: " << util::str_join(checked, ",");
}

Pass CreateResolveImportsPass(std::vector<std::string> &&import_paths)
{
  return Pass::create("ResolveImports",
                      [import_paths](ASTContext &ast, BPFtrace &b) {
                        // Add the source location as a primary path.
                        const auto &filename = ast.source()->filename;
                        std::vector<std::filesystem::path> updated_paths;
                        updated_paths.emplace_back(
                            std::filesystem::path(filename).parent_path());

                        // Add all additional paths.
                        for (const auto &path : import_paths) {
                          updated_paths.emplace_back(path);
                        }

                        // Resolve all imports.
                        ResolveImports analyser(b, updated_paths);
                        analyser.visit(ast.root);
                        return std::move(analyser.imports);
                      });
}

} // namespace bpftrace::ast
