#include <filesystem>
#include <fstream>
#include <sstream>

#include "ast/passes/resolve_imports.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "driver.h"
#include "stdlib/stdlib.h"
#include "util/format.h"
#include "util/result.h"

namespace bpftrace::ast {

using bpftrace::stdlib::Stdlib;

class ResolveImports : public Visitor<ResolveImports> {
public:
  ResolveImports(BPFtrace &bpftrace,
                 const std::vector<std::filesystem::path> &paths)
      : bpftrace_(bpftrace), paths_(paths) {};

  using Visitor<ResolveImports>::visit;
  void visit(Import &imp);

  // Public import call, see `allow_paths` below.
  Result<OK> importAny(Node &node, const std::string &name);

  // The import result, to be consumed by the pass.
  Imports imports;

  // Controls whether or not we are allowed to import from the filesystem. Note
  // that this starts as true, for all explicitly processed imports. We switch
  // this off in order to process implicit imports.
  bool allow_paths = true;

private:
  // Various import formats.
  //
  // Note that some formats support loading from the filesystem, while others
  // do not. Similarly, some formats support loading from in-memory objects,
  // and others do not.
  Result<OK> importAny(Node &node,
                       const std::string &name,
                       const std::filesystem::path &path);
  Result<OK> importAny(Node &node,
                       const std::string &name,
                       const std::string &data);
  Result<OK> importNative(Node &node,
                          const std::string &name,
                          const std::filesystem::path &path);
  Result<OK> importNative(Node &node,
                          const std::string &name,
                          const std::string &contents);
  Result<OK> importObject(Node &node,
                          const std::string &name,
                          const std::filesystem::path &path);
  Result<OK> importBitcode(Node &node,
                           const std::string &name,
                           const std::string &contents);

  BPFtrace &bpftrace_;
  const std::vector<std::filesystem::path> &paths_;
};

Result<OK> ResolveImports::importNative(Node &node,
                                        const std::string &name,
                                        const std::filesystem::path &path)
{
  // Load the file.
  std::ifstream file(path);
  if (file.fail()) {
    node.addError() << "error reading import '" << path
                    << "': " << std::strerror(errno);
    return OK();
  }
  std::stringstream buf;
  buf << file.rdbuf();
  return importNative(node, name, buf.str());
}

Result<OK> ResolveImports::importNative([[maybe_unused]] Node &node,
                                        const std::string &name,
                                        const std::string &contents)
{
  // Construct our context.
  auto [it, added] = imports.objects.emplace(name, ASTContext(name, contents));
  assert(added);

  auto &ast = std::get<ASTContext>(it->second);

  // Perform the basic parse pass. Note that this parse is done extremely
  // early, and does zero expansion or parsing of attachpoints, etc.
  PassManager pm;
  pm.put(ast);
  pm.put(bpftrace_);
  pm.add(CreateParsePass());

  // Attempt to parse the source.
  auto ok = pm.run();
  if (!ok) {
    return ok.takeError();
  }

  // Disallow `config` blocks as they cannot be merged.
  if (ast.root->config != nullptr && !ast.root->config->stmts.empty()) {
    ast.root->config->addError() << "invalid `config` within import";
  }

  // Recursively visit the parsed tree.
  visit(ast.root);

  return OK();
}

Result<OK> ResolveImports::importObject([[maybe_unused]] Node &node,
                                        const std::string &name,
                                        const std::filesystem::path &path)
{
  auto [_, added] = imports.objects.emplace(name, ExternalObject(path));
  assert(added);
  return OK();
}

Result<OK> ResolveImports::importBitcode([[maybe_unused]] Node &node,
                                         const std::string &name,
                                         const std::string &contents)
{
  auto [_, added] = imports.objects.emplace(name, Bitcode(contents));
  assert(added);
  return OK();
}

Result<OK> ResolveImports::importAny(Node &node,
                                     const std::string &name,
                                     const std::filesystem::path &path)
{
  if (imports.objects.contains(name)) {
    return OK(); // Already added.
  }

  if (std::filesystem::is_directory(path)) {
    // Recursively import all entries in the directory.
    for (const auto &entry : std::filesystem::directory_iterator(path)) {
      auto ok = importAny(node,
                          name + "/" + entry.path().filename().string(),
                          entry.path());
      if (!ok) {
        return ok.takeError();
      }
    }
    return OK();
  } else {
    // Import any support file-based extensions.
    if (path.extension() == ".bt") {
      return importNative(node, name, path);
    } else if (path.extension() == ".o") {
      return importObject(node, name, path);
    } else {
      node.addError() << "unknown import type: " << path.filename();
      return OK();
    }
  }
}

Result<OK> ResolveImports::importAny(Node &node,
                                     const std::string &name,
                                     const std::string &data)
{
  if (imports.objects.contains(name)) {
    return OK(); // Already added.
  }

  // Import supported extensions.
  std::filesystem::path path(name);
  if (path.extension() == ".bt") {
    return importNative(node, name, data);
  } else if (path.extension() == ".bc") {
    return importBitcode(node, name, data);
  } else if (path.extension() == ".btf") {
    // Ignore for now: these are BTF types.
    return OK();
  } else {
    node.addError() << "unknown import type: " << path;
    return OK();
  }
}

Result<OK> ResolveImports::importAny(Node &node, const std::string &name)
{
  if (imports.objects.contains(name)) {
    return OK(); // Already added.
  }

  std::vector<std::string> checked;
  if (allow_paths) {
    for (const auto &import_path : paths_) {
      // Check to see if this specific file exists.
      auto path = import_path / name;
      checked.emplace_back(path.string());
      if (!std::filesystem::exists(path)) {
        continue; // No file found.
      }

      // Attempt the import.
      return importAny(node, name, path);
    }
  }

  // See if this matches a set of builtins. Note that we do the "directory"
  // expansion here, importing anything that is matching as a path.
  bool found = false;
  for (const auto &[name, s] : Stdlib::files) {
    auto path = std::filesystem::path(name);
    if (path.string() == name) {
      return importAny(node, name, s);
    } else if (path.parent_path().string() == name) {
      auto ok = importAny(node, path.string(), s);
      if (!ok) {
        return ok.takeError();
      }
      // As long as we found at least one import that matched the standard
      // library paths, then we call it a victory.
      found = true;
    }
  }
  if (found) {
    return OK();
  }

  // Unable to find a suitable import.
  auto &err = node.addError();
  err << "Unable to find suitable path for import";
  if (!checked.empty()) {
    err.addHint() << "checked: " << util::str_join(checked, ",");
  }
  return OK();
}

void ResolveImports::visit(Import &imp)
{
  if (!bpftrace_.config_->unstable_import) {
    imp.addError() << "Imports are not enabled by default. To enable "
                      "this unstable feature, set this config flag to 1 "
                      "e.g. unstable_import=1";
    return;
  }

  auto ok = importAny(imp, imp.name);
  if (!ok) {
    imp.addError() << "import error: " << ok.takeError();
  }
}

Pass CreateResolveImportsPass(std::vector<std::string> &&import_paths)
{
  return Pass::create("ResolveImports",
                      [import_paths](ASTContext &ast,
                                     BPFtrace &b) -> Result<Imports> {
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

                        // Ensure that the standard library is imported. The
                        // implicit import is only permitted from the embedded
                        // standard library.  Overriding this is possible, but
                        // it must be explicitly imported.
                        analyser.allow_paths = false;
                        auto ok = analyser.importAny(*ast.root, "stdlib");
                        if (!ok) {
                          return ok.takeError();
                        }

                        // Return all calculated imports.
                        return std::move(analyser.imports);
                      });
}

} // namespace bpftrace::ast
