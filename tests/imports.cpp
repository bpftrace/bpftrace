#include <filesystem>
#include <optional>
#include <sstream>

#include "ast/passes/parse_passes.h"
#include "ast/passes/resolve_imports.h"
#include "mocks.h"
#include "util/temp.h"
#include "gmock/gmock-matchers.h"
#include "gtest/gtest.h"

namespace bpftrace::test::imports {

using ::bpftrace::ast::Imports;
using ::bpftrace::util::TempDir;
using ::bpftrace::util::TempFile;
using ::testing::HasSubstr;

class ImportTest : public ::testing::Test {
protected:
  std::vector<TempFile> files;

  [[nodiscard]] static bool set_perms(TempDir &base,
                                      const std::string &path,
                                      const std::filesystem::perms &perms)
  {
    std::error_code ec = {};
    std::filesystem::permissions(
        base.path() / path, perms, std::filesystem::perm_options::replace, ec);
    return !static_cast<bool>(ec);
  }
  [[nodiscard]] bool create_dir(
      TempDir &base,
      const std::string &path,
      std::optional<std::filesystem::perms> perms = std::nullopt)
  {
    std::error_code ec = {};
    std::filesystem::create_directories(base.path() / path, ec);
    if (ec) {
      return false;
    }
    if (perms.has_value()) {
      return set_perms(base, path, perms.value());
    }
    return true;
  }
  [[nodiscard]] bool create_file(
      TempDir &base,
      const std::string &path,
      std::string contents,
      std::optional<std::filesystem::perms> perms = std::nullopt)
  {
    std::filesystem::path p(path);
    std::filesystem::path parent = p;
    while (parent.has_parent_path()) {
      // These will always use the default permissions.
      parent = parent.parent_path();
      if (!create_dir(base, parent.string())) {
        return false;
      }
    }

    // Create the file at the given path.
    auto f = base.create_file(path, false);
    if (!f) {
      return false;
    }
    if (!f->write_all(contents)) {
      return false;
    }
    files.emplace_back(std::move(*f));
    if (perms.has_value()) {
      return set_perms(base, path, perms.value());
    }
    return true;
  }
};

using checkFn = std::function<void(Imports &)>;

void test(const std::string &input,
          std::vector<std::string> &&import_paths,
          std::variant<checkFn, std::string> check)
{
  BPFtrace bpftrace;
  bpftrace.config_->unstable_import = ConfigUnstable::enable;
  ast::ASTContext ast("stdin", input);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(get_mock_function_info())
                .add(ast::AllParsePasses({}, std::move(import_paths)))
                .run();
  std::stringstream out;
  ast.diagnostics().emit(out);
  if (std::holds_alternative<checkFn>(check)) {
    ASSERT_TRUE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    std::get<checkFn>(check)(ok->get<Imports>());
  } else {
    ASSERT_FALSE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(out.str(), HasSubstr(std::get<std::string>(check)))
        << msg.str() << out.str();
  }
}

TEST(Imports, stdlib_works)
{
  std::function<void(Imports &)> fn = []([[maybe_unused]] Imports &imports) {
    // Should be implicitly imported. As we add files to the standard library,
    // we should check that one of each kind exists here.
  };

  // The standard library import should be implicit.
  test(R"(begin {})", {}, fn);

  // Importing explicitly without any explicit file system paths should be the
  // same result as importing the standard library implicitly.
  test(R"(import "stdlib"; begin {})", {}, fn);
}

TEST_F(ImportTest, stdlib_implicit_rules)
{
  auto dir = TempDir::create();
  ASSERT_TRUE(bool(dir));

  // If we have a `stdlib` directory, it should override the implicit import.
  ASSERT_TRUE(create_file(*dir, "stdlib/foo.bt", ""));
  test(R"(import "stdlib"; begin {})", { dir->path() }, [](Imports &imports) {
    EXPECT_TRUE(imports.scripts.contains("stdlib/foo.bt"));
    EXPECT_FALSE(imports.scripts.contains("stdlib/base.bt"));
  });

  // An explicit filesystem stdlib import should continue to override the
  // embedded stdlib, even when the script references a macro with the same
  // name as one of the embedded stdlib macros.
  ASSERT_TRUE(create_file(*dir, "stdlib/cpu.bt", R"(macro cpu() { 123 })"));
  test(R"(import "stdlib"; begin { print(cpu()); })",
       { dir->path() },
       [](Imports &imports) {
         EXPECT_TRUE(imports.scripts.contains("stdlib/foo.bt"));
         EXPECT_TRUE(imports.scripts.contains("stdlib/cpu.bt"));
         EXPECT_FALSE(imports.scripts.contains("stdlib/base.bt"));
         EXPECT_FALSE(imports.scripts.contains("stdlib/meta.bt"));
       });

  // Without the explicit import, stdlib .bt files are only imported
  // if the script references macros from them.
  test(R"(begin {})", { dir->path() }, [](Imports &imports) {
    EXPECT_FALSE(imports.scripts.contains("stdlib/foo.bt"));
    EXPECT_FALSE(imports.scripts.contains("stdlib/base.bt"));
  });

  // Referencing a macro from base.bt should import it.
  test(R"(begin { print(cpu()); })", { dir->path() }, [](Imports &imports) {
    EXPECT_FALSE(imports.scripts.contains("stdlib/strings.bt"));
    EXPECT_FALSE(imports.scripts.contains("stdlib/meta.bt"));
    EXPECT_TRUE(imports.scripts.contains("stdlib/base.bt"));
  });

  // This test is to illustrate something that can be improved later. The `cpu`
  // macro takes no arguments but the call to `cpu` in this test passes
  // arguments meaning that if another `cpu` marco is defined by the user that
  // does take arguments we are unneccesarily importing part of the stdlib. One
  // potential fix is having cmake count the number of arguments and adding this
  // to the macro_to_file map and then comparing this number to the actual ast
  // Call argument count.
  test(R"(macro cpu(x, y) { x + y } begin { print(cpu(1, 2)); })",
       { dir->path() },
       [](Imports &imports) {
         EXPECT_FALSE(imports.scripts.contains("stdlib/strings.bt"));
         EXPECT_FALSE(imports.scripts.contains("stdlib/meta.bt"));
         EXPECT_TRUE(imports.scripts.contains("stdlib/base.bt"));
       });

  // Referencing a macro from base.bt inside another macro should import it.
  test(R"(macro get_cpu() { cpu } begin { print(get_cpu()); })",
       { dir->path() },
       [](Imports &imports) {
         EXPECT_FALSE(imports.scripts.contains("stdlib/strings.bt"));
         EXPECT_FALSE(imports.scripts.contains("stdlib/meta.bt"));
         EXPECT_TRUE(imports.scripts.contains("stdlib/base.bt"));
       });

  // Referencing a macro from base.bt that references a macro in another stdlib
  // file
  test(R"(begin { @a[1,2] = 1; $b = !has_key(@a, (1,2)); })",
       { dir->path() },
       [](Imports &imports) {
         EXPECT_FALSE(imports.scripts.contains("stdlib/strings.bt"));
         EXPECT_TRUE(imports.scripts.contains("stdlib/base.bt"));
         EXPECT_TRUE(imports.scripts.contains("stdlib/meta.bt"));
       });

  // Imported .bt files that reference stdlib macros should also trigger
  // stdlib imports.
  ASSERT_TRUE(create_file(*dir, "mylib.bt", R"(macro myfunc() { cpu() })"));
  test(R"(import "mylib.bt"; begin { print(myfunc()); })",
       { dir->path() },
       [](Imports &imports) {
         EXPECT_TRUE(imports.scripts.contains("mylib.bt"));
         EXPECT_TRUE(imports.scripts.contains("stdlib/base.bt"));
         EXPECT_FALSE(imports.scripts.contains("stdlib/meta.bt"));
       });

  // Referencing a macro from base.bt that references a macro in another stdlib
  // file from a manuallys imported bt file
  ASSERT_TRUE(
      create_file(*dir, "mylib2.bt", R"(macro myfunc(@a) { has_key(@a, 1) })"));
  test(R"(import "mylib2.bt"; begin { @b[1] = 2; print(myfunc(@b)); })",
       { dir->path() },
       [](Imports &imports) {
         EXPECT_TRUE(imports.scripts.contains("mylib2.bt"));
         EXPECT_TRUE(imports.scripts.contains("stdlib/base.bt"));
         EXPECT_TRUE(imports.scripts.contains("stdlib/meta.bt"));
       });
}

TEST_F(ImportTest, world_writable_ignored)
{
  const std::string &err = "global write permissions";

  // This is the directory itself that is broken. This should fail all
  // recursive imports.
  auto dir = TempDir::create();
  ASSERT_TRUE(bool(dir));
  ASSERT_TRUE(create_dir(*dir, "a"));
  ASSERT_TRUE(create_dir(*dir, "a/lib", std::filesystem::perms(0777)));
  ASSERT_TRUE(create_file(*dir, "a/lib/foo.bt", ""));
  test(R"(import "lib"; begin {})", { dir->path() / "a" }, err);
  test(R"(import "lib/foo.bt"; begin {})", { dir->path() / "a" }, err);

  // This is a base that is broken. We don't allow the recursive import
  // (because that could move), but do allow the nested import, because
  // the contents of the `lib` directory itself should not change.
  ASSERT_TRUE(create_dir(*dir, "b", std::filesystem::perms(0777)));
  ASSERT_TRUE(create_dir(*dir, "b/lib"));
  ASSERT_TRUE(create_file(*dir, "b/lib/foo.bt", ""));
  test(R"(import "lib"; begin {})", { dir->path() / "b" }, err);
  test(R"(import "lib/foo.bt"; begin {})",
       { dir->path() / "b" },
       []([[maybe_unused]] Imports &import) {});
}

TEST_F(ImportTest, import_ordering)
{
  auto dir = TempDir::create();
  ASSERT_TRUE(bool(dir));
  ASSERT_TRUE(create_file(*dir, "a/lib/foo.bt", ""));
  ASSERT_TRUE(create_file(*dir, "b/lib/bar.bt", ""));

  // This should match the first directory, and import everything there only.
  test(R"(import "lib"; begin {})",
       { dir->path() / "a", dir->path() / "b" },
       [](Imports &imports) {
         EXPECT_TRUE(imports.scripts.contains("lib/foo.bt"));
         EXPECT_FALSE(imports.scripts.contains("lib/bar.bt"));
       });

  // This should match only the second import.
  test(R"(import "lib/bar.bt"; begin {})",
       { dir->path() / "a", dir->path() / "b" },
       [](Imports &imports) {
         EXPECT_FALSE(imports.scripts.contains("lib/foo.bt"));
         EXPECT_TRUE(imports.scripts.contains("lib/bar.bt"));
       });
}

} // namespace bpftrace::test::imports
