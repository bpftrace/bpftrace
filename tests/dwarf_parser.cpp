#include "dwarf_parser.h"
#include "kprobe_lines.h"
#include "mocks.h"
#include "gtest/gtest.h"

#include <cstdlib>

#ifdef HAVE_LIBDW
namespace bpftrace::test {

class ScopedEnvironment {
public:
  ScopedEnvironment(const char *name, const char *value) : name_(name)
  {
    if (const char *old_value = std::getenv(name))
      old_value_ = old_value;
    EXPECT_EQ(::setenv(name, value, 1), 0);
  }

  ~ScopedEnvironment()
  {
    if (old_value_)
      ::setenv(name_.c_str(), old_value_->c_str(), 1);
    else
      ::unsetenv(name_.c_str());
  }

private:
  std::string name_;
  std::optional<std::string> old_value_;
};

TEST(dwarf_parser, inherited_parameter_names)
{
  auto bpftrace = create_bpftrace();
  auto dwarf = Dwarf::GetFromBinary(bpftrace.get(), DWARF_ORIGIN_BINARY, "");
  ASSERT_NE(dwarf, nullptr);
  EXPECT_EQ(dwarf->get_function_params("add_named"),
            (std::vector<std::string>{ "int left", "int right" }));

  auto args = dwarf->resolve_args("add_named");
  ASSERT_NE(args, nullptr);
  ASSERT_EQ(args->fields.size(), 2);
  EXPECT_TRUE(args->HasField("left"));
  EXPECT_TRUE(args->HasField("right"));
}

TEST(dwarf_parser, source_line_mapping)
{
  auto bpftrace = create_bpftrace();
  auto dwarf = Dwarf::GetFromBinary(bpftrace.get(), DATA_SOURCE_BINARY, "");
  ASSERT_NE(dwarf, nullptr);

  auto location = dwarf->line_to_addr("data_source.c", 62, 0, "");
  ASSERT_TRUE(location.operator bool()) << llvm::toString(location.takeError());
}

TEST(dwarf_parser, source_line_not_mapped_is_typed)
{
  auto bpftrace = create_bpftrace();
  auto dwarf = Dwarf::GetFromBinary(bpftrace.get(), DATA_SOURCE_BINARY, "");
  ASSERT_NE(dwarf, nullptr);

  auto location = dwarf->line_to_addr("data_source.c", 999, 0, "");
  ASSERT_FALSE(location);

  bool line_not_mapped = false;
  auto error = handleErrors(
      std::move(location), [&](const DwarfParseError &parse_error) {
        line_not_mapped = parse_error.kind() ==
                          DwarfParseError::Kind::LineNotMapped;
      });
  EXPECT_TRUE(line_not_mapped);
  EXPECT_TRUE(error.operator bool());
}

TEST(dwarf_parser, list_kprobe_lines_requires_kernel_dwarf)
{
  ScopedEnvironment vmlinux("BPFTRACE_VMLINUX", "/nonexistent/vmlinux");

  auto bpftrace = get_mock_bpftrace();
  ast::ASTContext context;
  ast::AttachPoint ap(context, ast::Location(), "kprobe@missing.c:1", true);
  ap.source_file = "missing.c";
  ap.line_num = 1;

  auto query = query_kprobe_lines(*bpftrace, ap);
  EXPECT_FALSE(query.exact_attachable);
  EXPECT_THAT(query.error,
              ::testing::HasSubstr("No kernel DWARF debug info available"));
}

TEST(dwarf_parser, source_line_mapping_uses_load_bias)
{
  ScopedEnvironment vmlinux("BPFTRACE_VMLINUX", DWARF_PIE_BINARY);
  auto bpftrace = create_bpftrace();
  auto dwarf = Dwarf::GetFromKernel(bpftrace.get(), "");
  ASSERT_NE(dwarf, nullptr);

  auto location = dwarf->line_to_addr("dwarf_pie.c", 3, 0, "");
  ASSERT_TRUE(location.operator bool()) << llvm::toString(location.takeError());
  EXPECT_EQ(location->symbol, "pie_target");
  EXPECT_GT(location->symbol_size, 0);
  EXPECT_LT(location->symbol_offset, location->symbol_size);
}

} // namespace bpftrace::test
#endif
