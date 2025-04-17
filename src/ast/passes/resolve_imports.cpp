#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_set>

#include "ast/passes/resolve_imports.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "driver.h"
#include "stdlib/stdlib.h"
#include "util/format.h"
#include "util/result.h"
#include "util/similar.h"

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
  bool checkPerms(const std::filesystem::path &path);

  // Various import formats.
  //
  // Note that some formats support loading from the filesystem, while others
  // do not. Similarly, some formats support loading from in-memory objects,
  // and others do not.
  Result<OK> importAny(Node &node,
                       const std::string &name,
                       const std::filesystem::path &path,
                       bool ignore_unknown);
  Result<OK> importAny(Node &node,
                       const std::string &name,
                       const std::string &data,
                       bool ignore_unknown);
  Result<OK> importScript(Node &node,
                          const std::string &name,
                          const std::filesystem::path &path);
  Result<OK> importScript(Node &node,
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

  // Record full packages/directories that have been imported separately from
  // the specific modules, in order to avoid re-importing these paths.
  std::unordered_set<std::string> packages_;
};

bool ResolveImports::checkPerms(const std::filesystem::path &path)
{
  auto check_one = [](const std::filesystem::path &path) {
    auto status = std::filesystem::status(path);
    auto permissions = status.permissions();
    return (permissions & std::filesystem::perms::others_write) ==
           std::filesystem::perms::none;
  };
  return check_one(path) && check_one(path.parent_path());
}

Result<OK> ResolveImports::importScript(Node &node,
                                        const std::string &name,
                                        const std::filesystem::path &path)
{
  if (imports.scripts.contains(name)) {
    return OK(); // Already added.
  }

  // Load the file.
  std::ifstream file(path);
  if (file.fail()) {
    node.addError() << "error reading import '" << path
                    << "': " << std::strerror(errno);
    return OK();
  }
  std::stringstream buf;
  buf << file.rdbuf();
  return importScript(node, name, buf.str());
}

Result<OK> ResolveImports::importScript([[maybe_unused]] Node &node,
                                        const std::string &name,
                                        const std::string &contents)
{
  if (imports.scripts.contains(name)) {
    return OK(); // Already added.
  }

  // Construct our context.
  auto [it, added] = imports.scripts.emplace(name, ASTContext(name, contents));
  assert(added);
  auto &ast = it->second;

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
  if (ast.root != nullptr && ast.root->config != nullptr &&
      !ast.root->config->stmts.empty()) {
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
  if (imports.objects.contains(name)) {
    return OK(); // Already added.
  }

  auto [_, added] = imports.objects.emplace(name, ExternalObject(path));
  assert(added);
  return OK();
}

Result<OK> ResolveImports::importBitcode([[maybe_unused]] Node &node,
                                         const std::string &name,
                                         const std::string &contents)
{
  if (imports.bitcode.contains(name)) {
    return OK(); // Already added.
  }

  auto [_, added] = imports.bitcode.emplace(name, Bitcode(contents));
  assert(added);
  return OK();
}

Result<OK> ResolveImports::importAny(Node &node,
                                     const std::string &name,
                                     const std::filesystem::path &path,
                                     bool ignore_unknown)
{
  if (!checkPerms(path)) {
    node.addError() << "cowardly refusing to import from a directory with "
                       "global write permissions: "
                    << path;
    return OK();
  }
  if (std::filesystem::is_directory(path)) {
    // Recursively import all entries in the directory. Note that the directory
    // iterator will never include '.' or '..' entries.
    for (const auto &entry : std::filesystem::directory_iterator(path)) {
      auto ok = importAny(node,
                          name + "/" + entry.path().filename().string(),
                          entry.path(),
                          true);
      if (!ok) {
        return ok.takeError();
      }
    }
    return OK();
  } else {
    // Import any support file-based extensions.
    if (path.extension() == ".bt") {
      return importScript(node, name, path);
    } else if (path.extension() == ".o" && path.stem().extension() == ".bpf") {
      return importObject(node, name, path);
    } else if (!ignore_unknown) {
      node.addError() << "unknown import type: " << path.filename();
    }
    return OK();
  }
}

Result<OK> ResolveImports::importAny(Node &node,
                                     const std::string &name,
                                     const std::string &data,
                                     bool ignore_unknown)
{
  // Import supported extensions.
  std::filesystem::path path(name);
  if (path.extension() == ".bt") {
    return importScript(node, name, data);
  } else if (path.extension() == ".bc") {
    return importBitcode(node, name, data);
  } else if (!ignore_unknown) {
    node.addError() << "unknown import type: " << path;
  }
  return OK();
}

Result<OK> ResolveImports::importAny(Node &node, const std::string &name)
{
  // Prevent direct re-importation of the same top-level name. This is used
  // because the name may match against directories or internal packages which
  // contain different files.
  if (packages_.contains(name)) {
    return OK();
  }
  packages_.emplace(name);

  std::vector<std::string> checked;
  if (allow_paths) {
    for (const auto &import_path : paths_) {
      // Check to see if this specific file exists.
      auto path = import_path / name;
      checked.emplace_back(path.string());
      std::error_code ec;
      if (!std::filesystem::exists(path, ec)) {
        continue; // No file found.
      }

      // For loading anything from the filesystem, ensure that the name import
      // is not inside a globally writable directory. Note that we log this as
      // a warning for a search, which is different than the case where the
      // path is imported explicitly.
      if (!checkPerms(path)) {
        node.addWarning() << "skipping due to global write permissions: "
                          << path;
        continue;
      }

      // Attempt the import.
      return importAny(node, name, path, false);
    }
  }

  // See if this matches a set of builtins. Note that we do the "directory"
  // expansion here, importing anything that is matching as a path.
  bool found = false;
  std::vector<std::string> similar;
  for (const auto &[internal_path, s] : Stdlib::files) {
    auto path = std::filesystem::path(internal_path);
    if (path.string() == name) {
      return importAny(node, name, s, false);
    } else if (path.parent_path().string() == name) {
      auto ok = importAny(node, path.string(), s, true);
      if (!ok) {
        return ok.takeError();
      }
      // As long as we found at least one import that matched the standard
      // library paths, then we call it a victory.
      found = true;
    }
    if (util::is_similar(name, internal_path)) {
      similar.push_back(internal_path);
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
  if (!similar.empty()) {
    err.addHint() << "similar to builtins: " << util::str_join(similar, ",");
  }
  return OK();
}

void ResolveImports::visit(Import &imp)
{
  // Ensure that the explicit statement is allowed.
  if (bpftrace_.config_->unstable_import == ConfigUnstable::error) {
    auto &err = imp.addError();
    err << "imports not enabled";
    err.addHint()
        << "set `unstable_import=warn` or `unstable_import=true` in config";
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
