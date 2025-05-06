#include <fstream>
#include <string>

#include "types/helpers.h"
#include "types/types.h"
#include "gtest/gtest.h"

namespace bpftrace::test::types {

using namespace bpftrace::types;

static std::string to_str(const AnyType &type)
{
  std::stringstream out;
  out << type;
  return out.str();
}

TEST(btf, to_str)
{
  BTF btf;
  auto int8 = btf.add<Integer>("int8", 1, 1);
  ASSERT_TRUE(bool(int8));
  EXPECT_EQ(to_str(AnyType(*int8)), "int8");
}

TEST(btf, kernel_types)
{
  std::ifstream file("/sys/kernel/btf/vmlinux");
  std::stringstream buffer;
  buffer << file.rdbuf();
  std::string content = buffer.str();
  auto btf = BTF::parse(content.c_str(), content.size());
  ASSERT_TRUE(bool(btf));

  // Want to see all the functions available?
  for (const Function &func : *btf | filter<Function>()) {
    std::cerr << func << "\n";
  }

  // Let's just look at the variables.
  for (const Var &var : *btf | filter<Var>()) {
    std::cerr << var << "\n";
  }

  // Just integer types in the kernel.
  for (const Integer &i : *btf | filter<Integer>()) {
    std::cerr << i << "\n";
  }
}

TEST(btf, map_types)
{
  BTF btf;
  auto int8 = btf.add<Integer>("int8", 1, 1);
  ASSERT_TRUE(bool(int8));
  EXPECT_EQ(to_str(AnyType(*int8)), "int8");

  auto m = createMap(btf,
                     MapInfo{
                         .map_type = BPF_MAP_TYPE_HASH,
                         .key = *int8,
                         .value = *int8,
                         .nr_elements = 1,
                     });
  ASSERT_TRUE(bool(m));
  EXPECT_EQ(to_str(AnyType(*m)), "struct (anon)");

  for (const auto &t : btf) {
    std::cerr << "[" << t.type_id() << "] " << t << "\n";
  }
}

} // namespace bpftrace::test::types
