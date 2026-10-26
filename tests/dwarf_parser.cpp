#include "dwarf_parser.h"
#include "mocks.h"
#include "util/symbols.h"
#include "gtest/gtest.h"

#ifdef HAVE_LIBDW
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

#ifdef HAVE_SOURCE_LOCATION_FIXTURES
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
#endif

} // namespace bpftrace::test
#endif
