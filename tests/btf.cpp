#include <cstdlib>
#include <unistd.h>
#include "gtest/gtest.h"
#include "btf.h"
#include "struct.h"
#include "bpftrace.h"
#include "mocks.h"

namespace bpftrace {
namespace test {
namespace btf {

#include "btf_data.h"

TEST(btf, resolve_struct)
{
  BTF btf(data, data_len);

  ASSERT_EQ(btf.has_data(), true);

  std::map<std::string, Struct> structs;

  btf.resolve_struct("Foo3", structs);

  //btf.dump_struct("Foo2");

  ASSERT_EQ(structs.size(), 3U);
  ASSERT_EQ(structs.count("Foo1"), 1U);
  ASSERT_EQ(structs.count("Foo2"), 1U);
  ASSERT_EQ(structs.count("Foo3"), 1U);

  EXPECT_EQ(structs["Foo1"].size, 16);
  ASSERT_EQ(structs["Foo1"].fields.size(), 3U);
  ASSERT_EQ(structs["Foo1"].fields.count("a"), 1U);
  ASSERT_EQ(structs["Foo1"].fields.count("b"), 1U);
  ASSERT_EQ(structs["Foo1"].fields.count("c"), 1U);

  EXPECT_EQ(structs["Foo1"].fields["a"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo1"].fields["a"].type.size, 4U);
  EXPECT_EQ(structs["Foo1"].fields["a"].offset, 0);

  EXPECT_EQ(structs["Foo1"].fields["b"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo1"].fields["b"].type.size, 1U);
  EXPECT_EQ(structs["Foo1"].fields["b"].offset, 4);

  EXPECT_EQ(structs["Foo1"].fields["c"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo1"].fields["c"].type.size, 8U);
  EXPECT_EQ(structs["Foo1"].fields["c"].offset, 8);

  EXPECT_EQ(structs["Foo2"].size, 24);
  ASSERT_EQ(structs["Foo2"].fields.size(), 2U);
  ASSERT_EQ(structs["Foo2"].fields.count("a"), 1U);
  ASSERT_EQ(structs["Foo2"].fields.count("f"), 1U);

  EXPECT_EQ(structs["Foo2"].fields["a"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo2"].fields["a"].type.size, 4U);
  EXPECT_EQ(structs["Foo2"].fields["a"].offset, 0);

  EXPECT_EQ(structs["Foo2"].fields["f"].type.type, Type::cast);
  EXPECT_EQ(structs["Foo2"].fields["f"].type.size, 16U);
  EXPECT_EQ(structs["Foo2"].fields["f"].offset, 8);

  EXPECT_EQ(structs["Foo3"].size, 16);
  ASSERT_EQ(structs["Foo3"].fields.size(), 2U);
  ASSERT_EQ(structs["Foo3"].fields.count("foo1"), 1U);
  ASSERT_EQ(structs["Foo3"].fields.count("foo2"), 1U);

  EXPECT_EQ(structs["Foo3"].fields["foo1"].type.type, Type::cast);
  EXPECT_EQ(structs["Foo3"].fields["foo1"].type.size, 8U);
  EXPECT_EQ(structs["Foo3"].fields["foo1"].type.is_pointer, true);
  EXPECT_EQ(structs["Foo3"].fields["foo1"].type.cast_type, "Foo1");
  EXPECT_EQ(structs["Foo3"].fields["foo1"].offset, 0);

  EXPECT_EQ(structs["Foo3"].fields["foo2"].type.type, Type::cast);
  EXPECT_EQ(structs["Foo3"].fields["foo2"].type.size, 8U);
  EXPECT_EQ(structs["Foo3"].fields["foo2"].type.is_pointer, true);
  EXPECT_EQ(structs["Foo3"].fields["foo2"].type.cast_type, "Foo2");
  EXPECT_EQ(structs["Foo3"].fields["foo2"].offset, 8);

  structs.clear();

  btf.resolve_struct("spinlock", structs);
  //btf.dump_structs(structs);

  ASSERT_EQ(structs.size(), 5U);
  ASSERT_EQ(structs.count("qspinlock"), 1U);
  ASSERT_EQ(structs.count("raw_spinlock"), 1U);
  ASSERT_EQ(structs.count("spinlock"), 1U);
  ASSERT_EQ(structs.count("type_0"), 1U);
  ASSERT_EQ(structs.count("type_9"), 1U);

  EXPECT_EQ(structs["qspinlock"].size, 4);
  ASSERT_EQ(structs["qspinlock"].fields.size(), 3U);
  ASSERT_EQ(structs["qspinlock"].fields.count("locked"), 1U);
  ASSERT_EQ(structs["qspinlock"].fields.count("val"), 1U);
  ASSERT_EQ(structs["qspinlock"].fields.count("pending"), 1U);

  EXPECT_EQ(structs["qspinlock"].fields["locked"].type.type, Type::integer);
  EXPECT_EQ(structs["qspinlock"].fields["locked"].type.size, 1U);
  EXPECT_EQ(structs["qspinlock"].fields["locked"].offset, 0);

  EXPECT_EQ(structs["qspinlock"].fields["pending"].type.type, Type::integer);
  EXPECT_EQ(structs["qspinlock"].fields["pending"].type.size, 1U);
  EXPECT_EQ(structs["qspinlock"].fields["pending"].offset, 1);

  EXPECT_EQ(structs["qspinlock"].fields["val"].type.type, Type::cast);
  EXPECT_EQ(structs["qspinlock"].fields["val"].type.size, 4U);
  EXPECT_EQ(structs["qspinlock"].fields["val"].offset, 0);
  EXPECT_EQ(structs["qspinlock"].fields["val"].type.cast_type, "type_9");

  EXPECT_EQ(structs["raw_spinlock"].size, 16);
  ASSERT_EQ(structs["raw_spinlock"].fields.size(), 2U);
  ASSERT_EQ(structs["raw_spinlock"].fields.count("raw_lock"), 1U);
  ASSERT_EQ(structs["raw_spinlock"].fields.count("owner"), 1U);

  EXPECT_EQ(structs["raw_spinlock"].fields["raw_lock"].type.type, Type::cast);
  EXPECT_EQ(structs["raw_spinlock"].fields["raw_lock"].type.size, 4U);
  EXPECT_EQ(structs["raw_spinlock"].fields["raw_lock"].offset, 0);
  EXPECT_EQ(structs["raw_spinlock"].fields["raw_lock"].type.cast_type, "qspinlock");

  EXPECT_EQ(structs["raw_spinlock"].fields["owner"].type.type, Type::cast);
  EXPECT_EQ(structs["raw_spinlock"].fields["owner"].type.size, 8U);
  EXPECT_EQ(structs["raw_spinlock"].fields["owner"].offset, 8);
  EXPECT_EQ(structs["raw_spinlock"].fields["owner"].type.cast_type, "type_0");
  EXPECT_EQ(structs["raw_spinlock"].fields["owner"].type.is_pointer, true);

  EXPECT_EQ(structs["spinlock"].size, 16);
  ASSERT_EQ(structs["spinlock"].fields.size(), 2U);
  ASSERT_EQ(structs["spinlock"].fields.count("padding"), 1U);
  ASSERT_EQ(structs["spinlock"].fields.count("rlock"), 1U);

  EXPECT_EQ(structs["spinlock"].fields["padding"].type.type, Type::string);
  EXPECT_EQ(structs["spinlock"].fields["padding"].type.size, 10U);
  EXPECT_EQ(structs["spinlock"].fields["padding"].offset, 0);

  EXPECT_EQ(structs["spinlock"].fields["rlock"].type.type, Type::cast);
  EXPECT_EQ(structs["spinlock"].fields["rlock"].type.size, 16U);
  EXPECT_EQ(structs["spinlock"].fields["rlock"].offset, 0);
  EXPECT_EQ(structs["spinlock"].fields["rlock"].type.cast_type, "raw_spinlock");
}

TEST(btf, has_struct)
{
  char *path = strdup("/tmp/XXXXXX");
  ASSERT_TRUE(path != NULL);

  int fd = mkstemp(path);
  ASSERT_TRUE(fd >= 0);

  EXPECT_EQ(write(fd, data, data_len), data_len);
  close(fd);

  ASSERT_EQ(setenv("BPFTRACE_BTF", path, true), 0);

  auto bpftrace = get_strict_mock_bpftrace();

  ASSERT_EQ(bpftrace->has_struct("Foo1"), true);
  ASSERT_EQ(bpftrace->has_struct("Foo"), false);
  ASSERT_EQ(bpftrace->has_struct("Foo2"), true);
  ASSERT_EQ(bpftrace->has_struct("Foo2"), true);
  ASSERT_EQ(bpftrace->has_struct("qspinlock"), true);
  ASSERT_EQ(bpftrace->has_struct("raw_spinlock"), true);
  ASSERT_EQ(bpftrace->has_struct("spinlock"), true);

  std::remove(path);
}

} // namespace btf
} // namespace test
} // namespace bpftrace
