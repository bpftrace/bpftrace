#include "dwarf_parser.h"
#include "mocks.h"
#include "util/symbols.h"
#include "gtest/gtest.h"

#ifdef HAVE_LIBDW
#include "dwarf_common.h"
namespace bpftrace::test {

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

class dwarf_parser_fixture : public test_dwarf {};

TEST_F(dwarf_parser_fixture, source_location_function_info)
{
  auto bpftrace = create_bpftrace();
  auto dwarf = Dwarf::GetFromBinary(bpftrace.get(), bin_, "");
  ASSERT_NE(dwarf, nullptr);

  auto info = dwarf->get_function_info("data_source.c", 202);
  ASSERT_TRUE(info);

  // clang-tidy doesn't seem to acknowledge that ASSERT_*() will
  // return from function so that these are in fact checked accesses.
  //
  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  EXPECT_FALSE(info->name.empty());
  ASSERT_TRUE(info->low_pc);
  EXPECT_FALSE(info->declaration_file.empty());
  // NOLINTEND(bugprone-unchecked-optional-access)
}

#ifdef HAVE_SOURCE_LOCATION_FIXTURES
TEST(dwarf_parser, source_location_inline_function_info)
{
  auto bpftrace = create_bpftrace();
  auto dwarf = Dwarf::GetFromBinary(bpftrace.get(), DWARF_INLINE_BINARY, "");
  ASSERT_NE(dwarf, nullptr);

  auto info = dwarf->get_function_info("dwarf_inline.c", 3);
  ASSERT_TRUE(info);

  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  EXPECT_EQ(info->name, "physical_target");
  ASSERT_TRUE(info->inline_function);
  EXPECT_EQ(info->inline_function->name, "inline_target");
  EXPECT_EQ(info->inline_function->declaration_line, 1);
  EXPECT_EQ(info->inline_function->call_line, 10);
  // NOLINTEND(bugprone-unchecked-optional-access)
}

TEST(dwarf_parser, source_location_prefers_statement)
{
  auto bpftrace = create_bpftrace();
  auto dwarf = Dwarf::GetFromBinary(bpftrace.get(),
                                    DWARF_LINE_SELECTION_BINARY,
                                    "");
  ASSERT_NE(dwarf, nullptr);

  auto symbols = util::resolve_symbols(DWARF_LINE_SELECTION_BINARY,
                                       { "line_selection_preferred" },
                                       false);
  if (!symbols)
    FAIL() << llvm::toString(symbols.takeError());
  ASSERT_EQ(symbols->size(), 1);

  auto location = dwarf->line_to_addr("dwarf_line_selection.c", 10, 1, "");
  if (!location)
    FAIL() << llvm::toString(location.takeError());
  EXPECT_EQ(location->address, symbols->front().v_addr);
}

TEST(dwarf_parser, source_location_keeps_physical_function_consistent)
{
  auto bpftrace = create_bpftrace();
  auto dwarf = Dwarf::GetFromBinary(bpftrace.get(),
                                    DWARF_FUNCTION_CONSISTENCY_BINARY,
                                    "");
  ASSERT_NE(dwarf, nullptr);

  auto location = dwarf->line_to_addr(
      "dwarf_function_consistency_input.c", 3, 0, "");
  if (!location)
    FAIL() << llvm::toString(location.takeError());

  auto symbol = util::resolve_symbol(DWARF_FUNCTION_CONSISTENCY_BINARY,
                                     location->address);
  if (!symbol)
    FAIL() << llvm::toString(symbol.takeError());
  ASSERT_EQ(symbol->name, "physical_first");

  auto info = dwarf->get_function_info("dwarf_function_consistency_input.c", 3);
  ASSERT_TRUE(info);

  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  EXPECT_EQ(info->name, symbol->name);
  EXPECT_FALSE(info->inline_function);
  ASSERT_TRUE(info->low_pc);
  EXPECT_LE(*info->low_pc, location->address);
  // NOLINTEND(bugprone-unchecked-optional-access)
}

TEST(dwarf_parser, source_location_inline_definition_after_callsite)
{
  auto bpftrace = create_bpftrace();
  auto dwarf = Dwarf::GetFromBinary(bpftrace.get(),
                                    DWARF_INLINE_AFTER_CALLSITE_BINARY,
                                    "");
  ASSERT_NE(dwarf, nullptr);

  auto info = dwarf->get_function_info("dwarf_inline_after_callsite_input.c",
                                       32);
  ASSERT_TRUE(info);

  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  EXPECT_EQ(info->name, "physical_late");
  ASSERT_TRUE(info->inline_function);
  EXPECT_EQ(info->inline_function->name, "inline_late");
  EXPECT_EQ(info->inline_function->declaration_line, 30);
  EXPECT_EQ(info->inline_function->call_line, 12);
  // NOLINTEND(bugprone-unchecked-optional-access)
}
#endif // HAVE_SOURCE_LOCATION_FIXTURES

} // namespace bpftrace::test
#endif
