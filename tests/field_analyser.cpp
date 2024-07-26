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

  ast::FieldAnalyser fields(driver.ctx.root, bpftrace, out);
  EXPECT_EQ(fields.analyse(), expected_result) << msg.str() + out.str();
}

void test(const std::string &input, int expected_result = 0)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, input, expected_result);
}

class field_analyser_btf : public test_btf {};

TEST_F(field_analyser_btf, kfunc_args)
{
  // func_1 and func_2 have different args, but none of them
  // is used in probe code, so we're good -> PASS
  test("kfunc:func_1, kfunc:func_2 { }", 0);
  // func_1 and func_2 have different args, one of them
  // is used in probe code, we can't continue -> FAIL
  test("kfunc:func_1, kfunc:func_2 { $x = args.foo; }", 1);
  // func_2 and func_3 have same args -> PASS
  test("kfunc:func_2, kfunc:func_3 { }", 0);
  // func_2 and func_3 have same args -> PASS
  test("kfunc:func_2, kfunc:func_3 { $x = args.foo1; }", 0);
  // aaa does not exist -> FAIL
  test("kfunc:func_2, kfunc:aaa { $x = args.foo1; }", 1);
  // func_* have different args, but none of them
  // is used in probe code, so we're good -> PASS
  test("kfunc:func_* { }", 0);
  // func_* have different args, one of them
  // is used in probe code, we can't continue -> FAIL
  test("kfunc:func_* { $x = args.foo1; }", 1);
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

  EXPECT_TRUE(foo1->GetField("a").type.IsIntTy());
  EXPECT_EQ(foo1->GetField("a").type.GetSize(), 4U);
  EXPECT_EQ(foo1->GetField("a").offset, 0);

  EXPECT_TRUE(foo1->GetField("b").type.IsIntTy());
  EXPECT_EQ(foo1->GetField("b").type.GetSize(), 1U);
  EXPECT_EQ(foo1->GetField("b").offset, 4);

  EXPECT_TRUE(foo1->GetField("c").type.IsIntTy());
  EXPECT_EQ(foo1->GetField("c").type.GetSize(), 8U);
  EXPECT_EQ(foo1->GetField("c").offset, 8);

  EXPECT_EQ(foo2->size, 24);
  ASSERT_EQ(foo2->fields.size(), 3U);
  ASSERT_TRUE(foo2->HasField("a"));
  ASSERT_TRUE(foo2->HasField("f"));
  ASSERT_TRUE(foo2->HasField("g"));

  EXPECT_TRUE(foo2->GetField("a").type.IsIntTy());
  EXPECT_EQ(foo2->GetField("a").type.GetSize(), 4U);
  EXPECT_EQ(foo2->GetField("a").offset, 0);

  EXPECT_TRUE(foo2->GetField("f").type.IsRecordTy());
  EXPECT_EQ(foo2->GetField("f").type.GetSize(), 16U);
  EXPECT_EQ(foo2->GetField("f").offset, 8);

  EXPECT_TRUE(foo2->GetField("g").type.IsIntTy());
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

TEST_F(field_analyser_btf, btf_arrays)
{
  BPFtrace bpftrace;
  bpftrace.parse_btf({});
  test(bpftrace,
       "BEGIN {\n"
       "  @ = (struct Arrays *) 0;\n"
       "}",
       0);

  ASSERT_TRUE(bpftrace.structs.Has("struct Arrays"));
  auto arrs = bpftrace.structs.Lookup("struct Arrays").lock();

  EXPECT_EQ(arrs->size, 64);
  ASSERT_EQ(arrs->fields.size(), 6U);
  ASSERT_TRUE(arrs->HasField("int_arr"));
  ASSERT_TRUE(arrs->HasField("char_arr"));
  ASSERT_TRUE(arrs->HasField("ptr_arr"));
  ASSERT_TRUE(arrs->HasField("multi_dim"));
  ASSERT_TRUE(arrs->HasField("zero"));
  ASSERT_TRUE(arrs->HasField("flexible"));

  EXPECT_TRUE(arrs->GetField("int_arr").type.IsArrayTy());
  EXPECT_EQ(arrs->GetField("int_arr").type.GetNumElements(), 4);
  EXPECT_TRUE(arrs->GetField("int_arr").type.GetElementTy()->IsIntTy());
  EXPECT_EQ(arrs->GetField("int_arr").type.GetSize(), 16U);
  EXPECT_EQ(arrs->GetField("int_arr").offset, 0);

  EXPECT_TRUE(arrs->GetField("char_arr").type.IsStringTy());
  EXPECT_EQ(arrs->GetField("char_arr").type.GetSize(), 8U);
  EXPECT_EQ(arrs->GetField("char_arr").offset, 16);

  EXPECT_TRUE(arrs->GetField("ptr_arr").type.IsArrayTy());
  EXPECT_EQ(arrs->GetField("ptr_arr").type.GetNumElements(), 2);
  EXPECT_TRUE(arrs->GetField("ptr_arr").type.GetElementTy()->IsPtrTy());
  EXPECT_EQ(arrs->GetField("ptr_arr").type.GetSize(), 2 * sizeof(uintptr_t));
  EXPECT_EQ(arrs->GetField("ptr_arr").offset, 24);

  // BTF flattens multi-dimensional arrays, so this test doesn't
  // check the correct number of elements. The correct values are
  // below in 'field_analyser_btf.btf_arrays_multi_dim'.
  EXPECT_TRUE(arrs->GetField("multi_dim").type.IsArrayTy());
  EXPECT_EQ(arrs->GetField("multi_dim").type.GetNumElements(), 6);
  EXPECT_TRUE(arrs->GetField("multi_dim").type.GetElementTy()->IsIntTy());
  EXPECT_EQ(arrs->GetField("multi_dim").type.GetSize(), 24U);
  EXPECT_EQ(arrs->GetField("multi_dim").offset, 40);

  EXPECT_TRUE(arrs->GetField("zero").type.IsArrayTy());
  EXPECT_EQ(arrs->GetField("zero").type.GetNumElements(), 0);
  EXPECT_TRUE(arrs->GetField("zero").type.GetElementTy()->IsIntTy());
  EXPECT_EQ(arrs->GetField("zero").type.GetSize(), 0U);
  EXPECT_EQ(arrs->GetField("zero").offset, 64);

  EXPECT_TRUE(arrs->GetField("flexible").type.IsArrayTy());
  EXPECT_EQ(arrs->GetField("flexible").type.GetNumElements(), 0);
  EXPECT_TRUE(arrs->GetField("flexible").type.GetElementTy()->IsIntTy());
  EXPECT_EQ(arrs->GetField("flexible").type.GetSize(), 0U);
  EXPECT_EQ(arrs->GetField("flexible").offset, 64);
}

TEST_F(field_analyser_btf, btf_arrays_multi_dim)
{
  GTEST_SKIP() << "BTF flattens multi-dimensional arrays #3082";

  BPFtrace bpftrace;
  bpftrace.parse_btf({});
  test(bpftrace,
       "BEGIN {\n"
       "  @ = (struct Arrays *) 0;\n"
       "}",
       0);

  ASSERT_TRUE(bpftrace.structs.Has("struct Arrays"));
  auto arrs = bpftrace.structs.Lookup("struct Arrays").lock();

  ASSERT_TRUE(arrs->HasField("multi_dim"));
  EXPECT_TRUE(arrs->GetField("multi_dim").type.IsArrayTy());
  EXPECT_EQ(arrs->GetField("multi_dim").offset, 40);
  EXPECT_EQ(arrs->GetField("multi_dim").type.GetSize(), 24U);
  EXPECT_EQ(arrs->GetField("multi_dim").type.GetNumElements(), 3);

  EXPECT_TRUE(arrs->GetField("multi_dim").type.GetElementTy()->IsArrayTy());
  EXPECT_EQ(arrs->GetField("multi_dim").type.GetElementTy()->GetSize(), 8U);
  EXPECT_EQ(arrs->GetField("multi_dim").type.GetElementTy()->GetNumElements(),
            2);

  EXPECT_TRUE(arrs->GetField("multi_dim")
                  .type.GetElementTy()
                  ->GetElementTy()
                  ->IsIntTy());
  EXPECT_EQ(arrs->GetField("multi_dim")
                .type.GetElementTy()
                ->GetElementTy()
                ->GetSize(),
            4U);
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

TEST_F(field_analyser_btf, btf_types_arr_access)
{
  BPFtrace bpftrace;
  bpftrace.parse_btf({});
  test(bpftrace,
       "kfunc:func_1 {\n"
       "  @foo2 = args.foo3[0].foo2;\n"
       "}",
       0);

  // args.foo3[0].foo2 should do 2 things:
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

TEST_F(field_analyser_btf, btf_types_bitfields)
{
  BPFtrace bpftrace;
  bpftrace.parse_btf({});
  test(bpftrace, "kprobe:sys_read { @ = curtask->pid; }");

  ASSERT_TRUE(bpftrace.structs.Has("struct task_struct"));
  auto task_struct = bpftrace.structs.Lookup("struct task_struct").lock();

  ASSERT_TRUE(task_struct->HasField("a"));
  EXPECT_TRUE(task_struct->GetField("a").type.IsIntTy());
  EXPECT_EQ(task_struct->GetField("a").type.GetSize(), 4U);
  EXPECT_EQ(task_struct->GetField("a").offset, 9);
  EXPECT_TRUE(task_struct->GetField("a").bitfield.has_value());
  EXPECT_EQ(task_struct->GetField("a").bitfield->read_bytes, 0x2U);
  EXPECT_EQ(task_struct->GetField("a").bitfield->access_rshift, 4U);
  EXPECT_EQ(task_struct->GetField("a").bitfield->mask, 0xFFU);

  ASSERT_TRUE(task_struct->HasField("b"));
  EXPECT_TRUE(task_struct->GetField("b").type.IsIntTy());
  EXPECT_EQ(task_struct->GetField("b").type.GetSize(), 4U);
  EXPECT_EQ(task_struct->GetField("b").offset, 10);
  EXPECT_TRUE(task_struct->GetField("b").bitfield.has_value());
  EXPECT_EQ(task_struct->GetField("b").bitfield->read_bytes, 0x1U);
  EXPECT_EQ(task_struct->GetField("b").bitfield->access_rshift, 4U);
  EXPECT_EQ(task_struct->GetField("b").bitfield->mask, 0x1U);

  ASSERT_TRUE(task_struct->HasField("c"));
  EXPECT_TRUE(task_struct->GetField("c").type.IsIntTy());
  EXPECT_EQ(task_struct->GetField("c").type.GetSize(), 4U);
  EXPECT_EQ(task_struct->GetField("c").offset, 10);
  EXPECT_TRUE(task_struct->GetField("c").bitfield.has_value());
  EXPECT_EQ(task_struct->GetField("c").bitfield->read_bytes, 0x1U);
  EXPECT_EQ(task_struct->GetField("c").bitfield->access_rshift, 5U);
  EXPECT_EQ(task_struct->GetField("c").bitfield->mask, 0x7U);

  ASSERT_TRUE(task_struct->HasField("d"));
  EXPECT_TRUE(task_struct->GetField("d").type.IsIntTy());
  EXPECT_EQ(task_struct->GetField("d").type.GetSize(), 4U);
  EXPECT_EQ(task_struct->GetField("d").offset, 12);
  EXPECT_TRUE(task_struct->GetField("d").bitfield.has_value());
  EXPECT_EQ(task_struct->GetField("d").bitfield->read_bytes, 0x3U);
  EXPECT_EQ(task_struct->GetField("d").bitfield->access_rshift, 0U);
  EXPECT_EQ(task_struct->GetField("d").bitfield->mask, 0xFFFFFU);
}

TEST_F(field_analyser_btf, btf_anon_union_first_in_struct)
{
  BPFtrace bpftrace;
  bpftrace.parse_btf({});
  test(bpftrace, "BEGIN { @ = (struct FirstFieldsAreAnonUnion *)0; }");

  ASSERT_TRUE(bpftrace.structs.Has("struct FirstFieldsAreAnonUnion"));
  auto record =
      bpftrace.structs.Lookup("struct FirstFieldsAreAnonUnion").lock();

  ASSERT_TRUE(record->HasField("a"));
  EXPECT_TRUE(record->GetField("a").type.IsIntTy());
  EXPECT_EQ(record->GetField("a").type.GetSize(), 4U);
  EXPECT_EQ(record->GetField("a").offset, 0);

  ASSERT_TRUE(record->HasField("b"));
  EXPECT_TRUE(record->GetField("b").type.IsIntTy());
  EXPECT_EQ(record->GetField("b").type.GetSize(), 4U);
  EXPECT_EQ(record->GetField("b").offset, 0);

  ASSERT_TRUE(record->HasField("c"));
  EXPECT_TRUE(record->GetField("c").type.IsIntTy());
  EXPECT_EQ(record->GetField("c").type.GetSize(), 4U);
  EXPECT_EQ(record->GetField("c").offset, 4);
}

#ifdef HAVE_LIBLLDB

#include "dwarf_common.h"

class field_analyser_dwarf : public test_dwarf {};

TEST_F(field_analyser_dwarf, uprobe_args)
{
  std::string uprobe = "uprobe:" + std::string(bin_);
  test(uprobe + ":func_1 { $x = args.a; }", 0);
  test(uprobe + ":func_2 { $x = args.b; }", 0);
  // Backwards compatibility
  test(uprobe + ":func_1 { $x = args->a; }", 0);

  // func_1 and func_2 have different args, but none of them
  // is used in probe code, so we're good -> PASS
  test(uprobe + ":func_1, " + uprobe + ":func_2 { }", 0);
  // func_1 and func_2 have different args, one of them
  // is used in probe code, we can't continue -> FAIL
  test(uprobe + ":func_1, " + uprobe + ":func_2 { $x = args.a; }", 1);
  // func_2 and func_3 have same args -> PASS
  test(uprobe + ":func_2, " + uprobe + ":func_3 { }", 0);
  test(uprobe + ":func_2, " + uprobe + ":func_3 { $x = args.a; }", 0);

  // Probes with wildcards (need non-mock BPFtrace)
  BPFtrace bpftrace;
  // func_* have different args, but none of them
  // is used in probe code, so we're good -> PASS
  test(bpftrace, uprobe + ":func_* { }", 0);
  // func_* have different args, one of them
  // is used in probe code, we can't continue -> FAIL
  test(bpftrace, uprobe + ":func_* { $x = args.a; }", 1);
}

TEST_F(field_analyser_dwarf, parse_struct)
{
  BPFtrace bpftrace;
  std::string uprobe = "uprobe:" + std::string(bin_);
  test(bpftrace, uprobe + ":func_1 { $x = args.foo1->a; }", 0);

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

TEST_F(field_analyser_dwarf, parse_arrays)
{
  BPFtrace bpftrace;
  std::string uprobe = "uprobe:" + std::string(bin_);
  test(bpftrace,
       uprobe + ":func_arrays {\n"
                "  @ = (struct Arrays *) args.arr;\n"
                "}");

  ASSERT_TRUE(bpftrace.structs.Has("struct Arrays"));
  auto arrs = bpftrace.structs.Lookup("struct Arrays").lock();

  EXPECT_EQ(arrs->size, 64);
  ASSERT_EQ(arrs->fields.size(), 6U);
  ASSERT_TRUE(arrs->HasField("int_arr"));
  ASSERT_TRUE(arrs->HasField("char_arr"));
  ASSERT_TRUE(arrs->HasField("ptr_arr"));
  ASSERT_TRUE(arrs->HasField("multi_dim"));
  ASSERT_TRUE(arrs->HasField("zero"));
  ASSERT_TRUE(arrs->HasField("flexible"));

  EXPECT_TRUE(arrs->GetField("int_arr").type.IsArrayTy());
  EXPECT_EQ(arrs->GetField("int_arr").type.GetNumElements(), 4);
  EXPECT_TRUE(arrs->GetField("int_arr").type.GetElementTy()->IsIntTy());
  EXPECT_EQ(arrs->GetField("int_arr").type.GetSize(), 16U);
  EXPECT_EQ(arrs->GetField("int_arr").offset, 0);

  EXPECT_TRUE(arrs->GetField("char_arr").type.IsStringTy());
  EXPECT_EQ(arrs->GetField("char_arr").type.GetSize(), 8U);
  EXPECT_EQ(arrs->GetField("char_arr").offset, 16);

  EXPECT_TRUE(arrs->GetField("ptr_arr").type.IsArrayTy());
  EXPECT_EQ(arrs->GetField("ptr_arr").type.GetNumElements(), 2);
  EXPECT_TRUE(arrs->GetField("ptr_arr").type.GetElementTy()->IsPtrTy());
  EXPECT_EQ(arrs->GetField("ptr_arr").type.GetSize(), 2 * sizeof(uintptr_t));
  EXPECT_EQ(arrs->GetField("ptr_arr").offset, 24);

  ASSERT_TRUE(arrs->HasField("multi_dim"));
  EXPECT_TRUE(arrs->GetField("multi_dim").type.IsArrayTy());
  EXPECT_EQ(arrs->GetField("multi_dim").offset, 40);
  EXPECT_EQ(arrs->GetField("multi_dim").type.GetSize(), 24U);
  EXPECT_EQ(arrs->GetField("multi_dim").type.GetNumElements(), 3);

  EXPECT_TRUE(arrs->GetField("multi_dim").type.GetElementTy()->IsArrayTy());
  EXPECT_EQ(arrs->GetField("multi_dim").type.GetElementTy()->GetSize(), 8U);
  EXPECT_EQ(arrs->GetField("multi_dim").type.GetElementTy()->GetNumElements(),
            2);

  EXPECT_TRUE(arrs->GetField("multi_dim")
                  .type.GetElementTy()
                  ->GetElementTy()
                  ->IsIntTy());
  EXPECT_EQ(arrs->GetField("multi_dim")
                .type.GetElementTy()
                ->GetElementTy()
                ->GetSize(),
            4U);

  EXPECT_TRUE(arrs->GetField("zero").type.IsArrayTy());
  EXPECT_EQ(arrs->GetField("zero").type.GetNumElements(), 0);
  EXPECT_TRUE(arrs->GetField("zero").type.GetElementTy()->IsIntTy());
  EXPECT_EQ(arrs->GetField("zero").type.GetSize(), 0U);
  EXPECT_EQ(arrs->GetField("zero").offset, 64);

  EXPECT_TRUE(arrs->GetField("flexible").type.IsArrayTy());
  EXPECT_EQ(arrs->GetField("flexible").type.GetNumElements(), 0);
  EXPECT_TRUE(arrs->GetField("flexible").type.GetElementTy()->IsIntTy());
  EXPECT_EQ(arrs->GetField("flexible").type.GetSize(), 0U);
  EXPECT_EQ(arrs->GetField("flexible").offset, 64);
}

TEST_F(field_analyser_dwarf, parse_struct_anonymous_fields)
{
  GTEST_SKIP() << "Anonymous fields not supported #3084";

  BPFtrace bpftrace;
  std::string uprobe = "uprobe:" + std::string(bin_);
  test(bpftrace, uprobe + ":func_1 { $x = args.foo2->g; }", 0);

  ASSERT_TRUE(bpftrace.structs.Has("struct Foo2"));
  auto str = bpftrace.structs.Lookup("struct Foo2").lock();

  ASSERT_TRUE(str->HasFields());
  ASSERT_EQ(str->fields.size(), 3);
  ASSERT_EQ(str->size, 72);

  ASSERT_TRUE(str->HasField("a"));
  ASSERT_TRUE(str->GetField("a").type.IsIntTy());
  ASSERT_EQ(str->GetField("a").type.GetSize(), 4);
  ASSERT_EQ(str->GetField("a").offset, 0);

  ASSERT_TRUE(str->HasField("f"));
  ASSERT_TRUE(str->GetField("f").type.IsRecordTy());
  ASSERT_EQ(str->GetField("f").type.GetSize(), 64);
  ASSERT_EQ(str->GetField("f").offset, 8);

  ASSERT_TRUE(str->HasField("g"));
  ASSERT_TRUE(str->GetField("g").type.IsIntTy());
  ASSERT_EQ(str->GetField("g").type.GetSize(), 1);
  ASSERT_EQ(str->GetField("g").offset, 8);
}

TEST_F(field_analyser_dwarf, dwarf_types_bitfields)
{
  BPFtrace bpftrace;
  std::string uprobe = "uprobe:" + std::string(bin_);
  test(bpftrace,
       uprobe + ":func_1 { @ = ((struct task_struct *)curtask)->pid; }",
       0);

  ASSERT_TRUE(bpftrace.structs.Has("struct task_struct"));
  auto task_struct = bpftrace.structs.Lookup("struct task_struct").lock();

  ASSERT_TRUE(task_struct->HasField("a"));
  EXPECT_TRUE(task_struct->GetField("a").type.IsIntTy());
  EXPECT_EQ(task_struct->GetField("a").type.GetSize(), 4U);
  EXPECT_TRUE(task_struct->GetField("a").bitfield.has_value());

  EXPECT_TRUE(task_struct->GetField("a").offset == 8 ||
              task_struct->GetField("a").offset == 9);
  if (task_struct->GetField("a").offset == 8) { // DWARF < 4
    EXPECT_EQ(task_struct->GetField("a").bitfield->read_bytes, 0x3U);
    EXPECT_EQ(task_struct->GetField("a").bitfield->access_rshift, 12U);
    EXPECT_EQ(task_struct->GetField("a").bitfield->mask, 0xFFU);
  } else { // DWARF >= 4
    EXPECT_EQ(task_struct->GetField("a").bitfield->read_bytes, 0x2U);
    EXPECT_EQ(task_struct->GetField("a").bitfield->access_rshift, 4U);
    EXPECT_EQ(task_struct->GetField("a").bitfield->mask, 0xFFU);
  }

  ASSERT_TRUE(task_struct->HasField("b"));
  EXPECT_TRUE(task_struct->GetField("b").type.IsIntTy());
  EXPECT_EQ(task_struct->GetField("b").type.GetSize(), 4U);
  EXPECT_TRUE(task_struct->GetField("b").bitfield.has_value());

  EXPECT_TRUE(task_struct->GetField("b").offset == 8 ||
              task_struct->GetField("b").offset == 10);
  if (task_struct->GetField("b").offset == 8) { // DWARF < 4
    EXPECT_EQ(task_struct->GetField("b").bitfield->read_bytes, 0x3U);
    EXPECT_EQ(task_struct->GetField("b").bitfield->access_rshift, 20U);
    EXPECT_EQ(task_struct->GetField("b").bitfield->mask, 0x1U);
  } else { // DWARF >= 4
    EXPECT_EQ(task_struct->GetField("b").bitfield->read_bytes, 0x1U);
    EXPECT_EQ(task_struct->GetField("b").bitfield->access_rshift, 4U);
    EXPECT_EQ(task_struct->GetField("b").bitfield->mask, 0x1U);
  }

  ASSERT_TRUE(task_struct->HasField("c"));
  EXPECT_TRUE(task_struct->GetField("c").type.IsIntTy());
  EXPECT_EQ(task_struct->GetField("c").type.GetSize(), 4U);
  EXPECT_TRUE(task_struct->GetField("c").bitfield.has_value());

  EXPECT_TRUE(task_struct->GetField("c").offset == 8 ||
              task_struct->GetField("c").offset == 10);

  if (task_struct->GetField("c").offset == 8) { // DWARF < 4
    EXPECT_EQ(task_struct->GetField("c").bitfield->read_bytes, 0x3U);
    EXPECT_EQ(task_struct->GetField("c").bitfield->access_rshift, 21U);
    EXPECT_EQ(task_struct->GetField("c").bitfield->mask, 0x7U);
  } else { // DWARF >= 4
    EXPECT_EQ(task_struct->GetField("c").bitfield->read_bytes, 0x1U);
    EXPECT_EQ(task_struct->GetField("c").bitfield->access_rshift, 5U);
    EXPECT_EQ(task_struct->GetField("c").bitfield->mask, 0x7U);
  }

  ASSERT_TRUE(task_struct->HasField("d"));
  EXPECT_TRUE(task_struct->GetField("d").type.IsIntTy());
  EXPECT_EQ(task_struct->GetField("d").type.GetSize(), 4U);
  EXPECT_EQ(task_struct->GetField("d").offset, 12);
  EXPECT_TRUE(task_struct->GetField("d").bitfield.has_value());
  EXPECT_EQ(task_struct->GetField("d").bitfield->read_bytes, 0x3U);
  EXPECT_EQ(task_struct->GetField("d").bitfield->access_rshift, 0U);
  EXPECT_EQ(task_struct->GetField("d").bitfield->mask, 0xFFFFFU);
}

TEST(field_analyser_subprog, struct_cast)
{
  test("struct x { int a; } fn f(): void { $s = (struct x *)0; }", 0);
}

#endif // HAVE_LIBLLDB

} // namespace field_analyser
} // namespace test
} // namespace bpftrace
