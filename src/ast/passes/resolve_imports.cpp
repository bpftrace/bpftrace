#include <filesystem>
#include <fstream>
#include <sstream>

#include "ast/passes/resolve_imports.h"
#include "ast/visitor.h"
#include "driver.h"
#include "stdlib/stdlib.h"
#include "util/result.h"
#include "util/similar.h"
#include "util/strings.h"

namespace bpftrace::ast {

using bpftrace::stdlib::Stdlib;

class ResolveRootImports : public Visitor<ResolveRootImports> {
public:
  ResolveRootImports(Imports &imports,
                     const std::vector<std::filesystem::path> &paths = {})
      : imports_(imports), paths_(paths) {};

  using Visitor<ResolveRootImports>::visit;
  void visit(RootImport &imp);

private:
  Imports &imports_;
  const std::vector<std::filesystem::path> &paths_;
};

class ResolveStatementImports : public Visitor<ResolveStatementImports> {
public:
  ResolveStatementImports(Imports &imports,
                          const std::vector<std::filesystem::path> &paths = {})
      : imports_(imports), paths_(paths) {};

  using Visitor<ResolveStatementImports>::visit;
  void visit(StatementImport &imp);

private:
  Imports &imports_;
  const std::vector<std::filesystem::path> &paths_;
};

static bool check_permissions(const std::filesystem::path &path)
{
  auto check_one = [](const std::filesystem::path &path) {
    auto status = std::filesystem::status(path);
    auto permissions = status.permissions();
    return (permissions & std::filesystem::perms::others_write) ==
           std::filesystem::perms::none;
  };
  if (!check_one(path)) {
    return false;
  }
  if (path.parent_path().empty()) {
    return check_one(".");
  } else {
    return check_one(path.parent_path());
  }
}

static Result<OK> import_script(Node &node,
                                Imports &imports,
                                const std::string &name,
                                const std::string &&data,
                                const std::vector<std::filesystem::path> &paths,
                                std::map<std::string, ScriptObject> &contents,
                                bool internal)
{
  if (contents.contains(name)) {
    return OK(); // Already added.
  }

  // Construct our context.
  auto [it, added] = contents.emplace(
      name, ScriptObject(node, ASTContext(name, data), internal));
  assert(added);
  auto &ast = it->second.ast;

  // Perform the basic parse pass. Note that this parse is done extremely
  // early, and does zero expansion or parsing of attachpoints, etc.
  PassManager pm;
  pm.put(ast);
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
  ResolveRootImports resolver(imports, paths);
  resolver.visit(ast.root);

  return OK();
}

static Result<OK> import_script(Node &node,
                                Imports &imports,
                                const std::string &name,
                                const std::filesystem::path &path,
                                const std::vector<std::filesystem::path> &paths,
                                std::map<std::string, ScriptObject> &contents)
{
  if (contents.contains(name)) {
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
  return import_script(node, imports, name, buf.str(), paths, contents, false);
}

static Result<OK> import_object(Node &node,
                                const std::string &name,
                                const std::filesystem::path &path,
                                std::map<std::string, ExternalObject> &contents)
{
  if (contents.contains(name)) {
    return OK(); // Already added.
  }

  auto added = contents.emplace(name, ExternalObject(node, path)).second;
  assert(added);
  return OK();
}

static Result<OK> import_c(Node &node,
                           const std::string &name,
                           const std::filesystem::path &path,
                           std::map<std::string, LoadedObject> &contents)
{
  if (contents.contains(name)) {
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
  auto [_, added] = contents.emplace(name, LoadedObject(node, buf.str()));
  assert(added);
  return OK();
}

static Result<OK> import_c(Node &node,
                           const std::string &name,
                           const std::string_view &data,
                           std::map<std::string, LoadedObject> &contents)
{
  if (contents.contains(name)) {
    return OK(); // Already added.
  }

  auto [_, added] = contents.emplace(name, LoadedObject(node, data));
  assert(added);
  return OK();
}

Result<OK> Imports::import_any(Node &node,
                               const std::string &name,
                               const std::filesystem::path &path,
                               const std::vector<std::filesystem::path> &paths,
                               bool ignore_unknown,
                               bool allow_directories)
{
  if (!check_permissions(path)) {
    node.addError() << "cowardly refusing to import from a directory with "
                       "global write permissions: "
                    << path;
    return OK();
  }
  if (std::filesystem::is_directory(path)) {
    // If `recurse` is not set, just ignore this directory.
    if (!allow_directories) {
      return OK();
    }
    // Recursively import all entries in the directory. Note that the directory
    // iterator will never include '.' or '..' entries.
    for (const auto &entry : std::filesystem::directory_iterator(path)) {
      auto ok = import_any(node,
                           name + "/" + entry.path().filename().string(),
                           entry.path(),
                           paths,
                           true,
                           false);
      if (!ok) {
        return ok.takeError();
      }
    }
    return OK();
  } else {
    // Import any support file-based extensions.
    if (path.extension() == ".bt") {
      return import_script(node, *this, name, path, paths, scripts);
    } else if (path.extension() == ".c" && path.stem().extension() == ".bpf") {
      return import_c(node, name, path, c_sources);
    } else if (path.extension() == ".h") {
      return import_c(node, name, path, c_headers);
    } else if (path.extension() == ".o" && path.stem().extension() == ".bpf") {
      return import_object(node, name, path, objects);
    } else if (!ignore_unknown) {
      node.addError() << "unknown import type: " << path.filename();
    }
    return OK();
  }
}

Result<OK> Imports::import_any(Node &node,
                               const std::string &name,
                               const std::string_view &data,
                               const std::vector<std::filesystem::path> &paths,
                               bool ignore_unknown)
{
  // Import supported extensions.
  std::filesystem::path path(name);
  if (path.extension() == ".bt") {
    return import_script(
        node, *this, name, std::string(data), paths, scripts, true);
  } else if (path.extension() == ".c" && path.stem().extension() == ".bpf") {
    return import_c(node, name, data, c_sources);
  } else if (path.extension() == ".h") {
    return import_c(node, name, data, c_headers);
  } else if (!ignore_unknown) {
    node.addError() << "unknown import type: " << path;
  }
  return OK();
}

Result<OK> Imports::import_any(Node &node,
                               const std::string &name,
                               const std::vector<std::filesystem::path> &paths)
{
  // Prevent direct re-importation of the same top-level name. This is used
  // because the name may match against directories or internal packages which
  // contain different files.
  if (packages_.contains(name)) {
    return OK();
  }
  packages_.emplace(name);

  std::vector<std::string> checked;
  for (const auto &import_path : paths) {
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
    if (!check_permissions(path)) {
      node.addWarning() << "skipping due to global write permissions: " << path;
      continue;
    }

    // Attempt the import.
    return import_any(node, name, path, paths, false, true);
  }

  // See if this matches a set of builtins. Note that we do the "directory"
  // expansion here, importing anything that is matching as a path.
  bool found = false;
  std::vector<std::string> similar;
  for (const auto &[internal_path, s] : Stdlib::files) {
    auto path = std::filesystem::path(internal_path);
    if (path.string() == name) {
      return import_any(node, name, s, paths, false);
    } else if (path.parent_path().string() == name) {
      auto ok = import_any(node, path.string(), s, paths, true);
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

void ResolveStatementImports::visit(StatementImport &imp)
{
  static std::string import_error =
      "Import statements that are not at the root are limited to specific "
      "object (.o), header (.h), or C source (.c or bpf.c) files";
  std::filesystem::path path(imp.name);
  if (std::filesystem::is_directory(path)) {
    imp.addError() << import_error;
  } else if (path.extension() == ".bt") {
    imp.addError() << import_error;
  } else {
    for (const auto &[internal_path, s] : Stdlib::files) {
      auto path = std::filesystem::path(internal_path);
      if (path.parent_path().string() == imp.name) {
        imp.addError() << import_error;
      }
    }
  }
  auto ok = imports_.import_any(imp, imp.name, paths_);
  if (!ok) {
    imp.addError() << "import error: " << ok.takeError();
  }
}

void ResolveRootImports::visit(RootImport &imp)
{
  auto ok = imports_.import_any(imp, imp.name, paths_);
  if (!ok) {
    imp.addError() << "import error: " << ok.takeError();
  }
}

Pass CreateResolveRootImportsPass(std::vector<std::string> &&import_paths)
{
  return Pass::create("ResolveRootImports",
                      [import_paths](ASTContext &ast) -> Result<Imports> {
                        Imports imports;
                        // Add the source location as a primary path.
                        const auto &filename = ast.source()->filename;
                        std::vector<std::filesystem::path> updated_paths;
                        updated_paths.emplace_back(
                            std::filesystem::path(filename).parent_path());

                        // Add all additional paths.
                        for (const auto &path : import_paths) {
                          updated_paths.emplace_back(path);
                        }

                        ResolveRootImports analyser(imports, updated_paths);
                        analyser.visit(ast.root);

                        // Ensure that the essential part of the standard
                        // library is imported. All other parts of the standard
                        // library are conditionally imported based on inlined
                        // import statements. The implicit import is only
                        // permitted from the embedded standard library.
                        // Overriding this is possible, but it must be
                        // explicitly imported.
                        auto ok = imports.import_any(*ast.root, "stdlib");
                        if (!ok) {
                          return ok.takeError();
                        }
                        return imports;
                      });
}

// This is primarily for the standard library so we can conditionally
// import specific bpf.c files instead of importing, compiling, and type
// processing all of the stdlib bpf.c files which increase start up latency
// and also possibly create/allocate unused maps
Pass CreateResolveStatementImportsPass()
{
  return Pass::create("ResolveStatementImports",
                      [](ASTContext &ast, Imports &imports) {
                        // Add the source location as a primary path.
                        const auto &filename = ast.source()->filename;
                        std::vector<std::filesystem::path> updated_paths;
                        updated_paths.emplace_back(
                            std::filesystem::path(filename).parent_path());
                        ResolveStatementImports analyser(imports,
                                                         updated_paths);
                        analyser.visit(ast.root);
                      });
}

} // namespace bpftrace::ast
