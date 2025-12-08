#include <filesystem>
#include <optional>
#include <sstream>

#include "ast/passes/parser.h"
#include "ast/passes/resolve_imports.h"
#include "mocks.h"
#include "util/temp.h"
#include "gmock/gmock-matchers.h"
#include "gtest/gtest.h"

namespace bpftrace::test::imports {

using ::bpftrace::ast::Imports;
using ::bpftrace::test::create_bpftrace;
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
  auto bpftrace = create_bpftrace();
  bpftrace->config_->unstable_import = ConfigUnstable::enable;
  ast::ASTContext ast("stdin", input);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  auto ok = ast::PassManager()
                .put(ast)
                .put(*bpftrace)
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

  // Without the explicit import, it should use the builtin one.
  test(R"(begin {})", { dir->path() }, [](Imports &imports) {
    EXPECT_FALSE(imports.scripts.contains("stdlib/foo.bt"));
    EXPECT_TRUE(imports.scripts.contains("stdlib/base.bt"));
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
