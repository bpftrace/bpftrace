#include "ast/passes/field_analyser.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace {
namespace test {
namespace field_analyser {

#include "btf_common.h"

using ::testing::_;

void test(BPFtrace &bpftrace, const std::string &input, int expected_result = 0)
{
  std::stringstream out;
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  Driver driver(bpftrace);
  EXPECT_EQ(driver.parse_str(input), 0);

  ast::FieldAnalyser fields(driver.root.get(), bpftrace, out);
  EXPECT_EQ(fields.analyse(), expected_result) << msg.str() + out.str();
}

void test(const std::string &input, int expected_result = 0)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, input, expected_result);
}

class field_analyser_btf : public test_btf
{
};

TEST_F(field_analyser_btf, kfunc_args)
{
  // func_1 and func_2 have different args, but none of them
  // is used in probe code, so we're good -> PASS
  test("kfunc:func_1, kfunc:func_2 { }", 0);
  // func_1 and func_2 have different args, one of them
  // is used in probe code, we can't continue -> FAIL
  test("kfunc:func_1, kfunc:func_2 { $x = args->foo; }", 1);
  // func_2 and func_3 have same args -> PASS
  test("kfunc:func_2, kfunc:func_3 { }", 0);
  // func_2 and func_3 have same args -> PASS
  test("kfunc:func_2, kfunc:func_3 { $x = args->foo1; }", 0);
  // aaa does not exist -> FAIL
  test("kfunc:func_2, kfunc:aaa { $x = args->foo1; }", 1);
  // func_* have different args, but none of them
  // is used in probe code, so we're good -> PASS
  test("kfunc:func_* { }", 0);
  // func_* have different args, one of them
  // is used in probe code, we can't continue -> FAIL
  test("kfunc:func_* { $x = args->foo1; }", 1);
}

TEST_F(field_analyser_btf, btf_types)
{
  BPFtrace bpftrace;
  bpftrace.parse_btf({});
  test(bpftrace,
       "kprobe:sys_read {\n"
       "  @x1 = (struct Foo1 *) curtask;\n"
       "  @x2 = (struct Foo2 *) curtask;\n"
       "  @x3 = (struct Foo3 *) curtask;\n"
       "}",
       0);

  ASSERT_TRUE(bpftrace.structs.Has("struct Foo1"));
  ASSERT_TRUE(bpftrace.structs.Has("struct Foo2"));
  ASSERT_TRUE(bpftrace.structs.Has("struct Foo3"));
  auto foo1 = bpftrace.structs.Lookup("struct Foo1").lock();
  auto foo2 = bpftrace.structs.Lookup("struct Foo2").lock();
  auto foo3 = bpftrace.structs.Lookup("struct Foo3").lock();

  EXPECT_EQ(foo1->size, 16);
  ASSERT_EQ(foo1->fields.size(), 3U);
  ASSERT_TRUE(foo1->HasField("a"));
  ASSERT_TRUE(foo1->HasField("b"));
  ASSERT_TRUE(foo1->HasField("c"));

  EXPECT_EQ(foo1->GetField("a").type.type, Type::integer);
  EXPECT_EQ(foo1->GetField("a").type.GetSize(), 4U);
  EXPECT_EQ(foo1->GetField("a").offset, 0);

  EXPECT_EQ(foo1->GetField("b").type.type, Type::integer);
  EXPECT_EQ(foo1->GetField("b").type.GetSize(), 1U);
  EXPECT_EQ(foo1->GetField("b").offset, 4);

  EXPECT_EQ(foo1->GetField("c").type.type, Type::integer);
  EXPECT_EQ(foo1->GetField("c").type.GetSize(), 8U);
  EXPECT_EQ(foo1->GetField("c").offset, 8);

  EXPECT_EQ(foo2->size, 24);
  ASSERT_EQ(foo2->fields.size(), 3U);
  ASSERT_TRUE(foo2->HasField("a"));
  ASSERT_TRUE(foo2->HasField("f"));
  ASSERT_TRUE(foo2->HasField("g"));

  EXPECT_EQ(foo2->GetField("a").type.type, Type::integer);
  EXPECT_EQ(foo2->GetField("a").type.GetSize(), 4U);
  EXPECT_EQ(foo2->GetField("a").offset, 0);

  EXPECT_EQ(foo2->GetField("f").type.type, Type::record);
  EXPECT_EQ(foo2->GetField("f").type.GetSize(), 16U);
  EXPECT_EQ(foo2->GetField("f").offset, 8);

  EXPECT_EQ(foo2->GetField("g").type.type, Type::integer);
  EXPECT_EQ(foo2->GetField("g").type.GetSize(), 1U);
  EXPECT_EQ(foo2->GetField("g").offset, 8);

  EXPECT_EQ(foo3->size, 16);
  ASSERT_EQ(foo3->fields.size(), 2U);
  ASSERT_TRUE(foo3->HasField("foo1"));
  ASSERT_TRUE(foo3->HasField("foo2"));

  auto foo1_field = foo3->GetField("foo1");
  auto foo2_field = foo3->GetField("foo2");
  EXPECT_TRUE(foo1_field.type.IsPtrTy());
  EXPECT_EQ(foo1_field.type.GetPointeeTy()->GetName(), "struct Foo1");
  EXPECT_EQ(foo1_field.offset, 0);

  EXPECT_TRUE(foo2_field.type.IsPtrTy());
  EXPECT_EQ(foo2_field.type.GetPointeeTy()->GetName(), "struct Foo2");
  EXPECT_EQ(foo2_field.offset, 8);
}

TEST_F(field_analyser_btf, btf_types_struct_ptr)
{
  BPFtrace bpftrace;
  bpftrace.parse_btf({});
  test(bpftrace,
       "kprobe:sys_read {\n"
       "  @x1 = ((struct Foo3 *) curtask);\n"
       "  @x3 = @x1->foo2;\n"
       "}",
       0);

  // @x1->foo2 should do 2 things:
  // - add struct Foo2 (without resolving its fields)
  // - resolve fields of struct Foo3

  ASSERT_TRUE(bpftrace.structs.Has("struct Foo2"));
  ASSERT_TRUE(bpftrace.structs.Has("struct Foo3"));
  auto foo2 = bpftrace.structs.Lookup("struct Foo2").lock();
  auto foo3 = bpftrace.structs.Lookup("struct Foo3").lock();

  EXPECT_EQ(foo2->size, 24);
  ASSERT_EQ(foo2->fields.size(), 0U); // fields are not resolved
  EXPECT_EQ(foo3->size, 16);
  ASSERT_EQ(foo3->fields.size(), 2U); // fields are resolved
}

#ifdef HAVE_LIBDW

#include "dwarf_common.h"

class field_analyser_dwarf : public test_dwarf
{
};

TEST_F(field_analyser_dwarf, uprobe_args)
{
  std::string uprobe = "uprobe:" + std::string(bin_);
  test(uprobe + ":func_1 { $x = args->a; }", 0);
  test(uprobe + ":func_2 { $x = args->b; }", 0);

  // func_1 and func_2 have different args, but none of them
  // is used in probe code, so we're good -> PASS
  test(uprobe + ":func_1, " + uprobe + ":func_2 { }", 0);
  // func_1 and func_2 have different args, one of them
  // is used in probe code, we can't continue -> FAIL
  test(uprobe + ":func_1, " + uprobe + ":func_2 { $x = args->a; }", 1);
  // func_2 and func_3 have same args -> PASS
  test(uprobe + ":func_2, " + uprobe + ":func_3 { }", 0);
  test(uprobe + ":func_2, " + uprobe + ":func_3 { $x = args->a; }", 0);

  // Probes with wildcards (need non-mock BPFtrace)
  BPFtrace bpftrace;
  // func_* have different args, but none of them
  // is used in probe code, so we're good -> PASS
  test(bpftrace, uprobe + ":func_* { }", 0);
  // func_* have different args, one of them
  // is used in probe code, we can't continue -> FAIL
  test(bpftrace, uprobe + ":func_* { $x = args->a; }", 1);
}

TEST_F(field_analyser_dwarf, parse_struct)
{
  BPFtrace bpftrace;
  std::string uprobe = "uprobe:" + std::string(bin_);
  test(bpftrace, uprobe + ":func_1 { $x = args->foo1->a; }", 0);

  ASSERT_TRUE(bpftrace.structs.Has("struct Foo1"));
  auto str = bpftrace.structs.Lookup("struct Foo1").lock();

  ASSERT_TRUE(str->HasFields());
  ASSERT_EQ(str->fields.size(), 3);
  ASSERT_EQ(str->size, 16);

  ASSERT_TRUE(str->HasField("a"));
  ASSERT_TRUE(str->GetField("a").type.IsIntTy());
  ASSERT_EQ(str->GetField("a").type.GetSize(), 4);
  ASSERT_EQ(str->GetField("a").offset, 0);

  ASSERT_TRUE(str->HasField("b"));
  ASSERT_TRUE(str->GetField("b").type.IsIntTy());
  ASSERT_EQ(str->GetField("b").type.GetSize(), 1);
  ASSERT_EQ(str->GetField("b").offset, 4);

  ASSERT_TRUE(str->HasField("c"));
  ASSERT_TRUE(str->GetField("c").type.IsIntTy());
  ASSERT_EQ(str->GetField("c").type.GetSize(), 8);
}

#endif // HAVE_LIBDW

} // namespace field_analyser
} // namespace test
} // namespace bpftrace
