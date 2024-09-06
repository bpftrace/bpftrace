#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, tuple)
{
  test(R"_(k:f { @t = (1, 2, "str"); })_",

       NAME);
}

TEST(codegen, tuple_map_val_different_sizes)
{
  test(R"_(k:f { @a = (1, "hi"); @a = (1, "hellolongstr"); })_",

       NAME);
}

TEST(codegen, tuple_variable_different_sizes)
{
  test(R"_(k:f { $t = (1, "hi"); $t = (1, "hellolongstr"); })_",

       NAME);
}

TEST(codegen, nested_tuple_different_sizes)
{
  test(R"_(k:f { $t = (1, ("hi", 3)); $t = (1, ("hellolongstr", 4)); })_",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
