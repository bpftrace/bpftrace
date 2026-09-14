#include "dwarf_parser.h"
#include "mocks.h"
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

} // namespace bpftrace::test
#endif
