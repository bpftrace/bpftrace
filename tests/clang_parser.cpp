#include "gtest/gtest.h"
#include "clang_parser.h"
#include "driver.h"
#include "bpftrace.h"

namespace bpftrace {
namespace test {
namespace clang_parser {

void parse(const std::string &input, BPFtrace &bpftrace)
{
  auto extended_input = input + "kprobe:sys_read { 1 }";
  Driver driver(bpftrace);
  ASSERT_EQ(driver.parse_str(extended_input), 0);

  ClangParser clang;
  clang.parse(driver.root_, bpftrace);
}

TEST(clang_parser, integers)
{
  BPFtrace bpftrace;
  parse("struct Foo { int x; int y, z; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("Foo"), 1U);

  EXPECT_EQ(structs["Foo"].size, 12);
  ASSERT_EQ(structs["Foo"].fields.size(), 3U);
  ASSERT_EQ(structs["Foo"].fields.count("x"), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("y"), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("z"), 1U);

  EXPECT_EQ(structs["Foo"].fields["x"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo"].fields["x"].type.size, 4U);
  EXPECT_EQ(structs["Foo"].fields["x"].offset, 0);

  EXPECT_EQ(structs["Foo"].fields["y"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo"].fields["y"].type.size, 4U);
  EXPECT_EQ(structs["Foo"].fields["y"].offset, 4);

  EXPECT_EQ(structs["Foo"].fields["z"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo"].fields["z"].type.size, 4U);
  EXPECT_EQ(structs["Foo"].fields["z"].offset, 8);
}

TEST(clang_parser, c_union)
{
  BPFtrace bpftrace;
  parse("union Foo { char c; short s; int i; long l; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("Foo"), 1U);

  EXPECT_EQ(structs["Foo"].size, 8);
  ASSERT_EQ(structs["Foo"].fields.size(), 4U);
  ASSERT_EQ(structs["Foo"].fields.count("c"), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("s"), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("i"), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("l"), 1U);

  EXPECT_EQ(structs["Foo"].fields["c"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo"].fields["c"].type.size, 1U);
  EXPECT_EQ(structs["Foo"].fields["c"].offset, 0);

  EXPECT_EQ(structs["Foo"].fields["s"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo"].fields["s"].type.size, 2U);
  EXPECT_EQ(structs["Foo"].fields["s"].offset, 0);

  EXPECT_EQ(structs["Foo"].fields["i"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo"].fields["i"].type.size, 4U);
  EXPECT_EQ(structs["Foo"].fields["i"].offset, 0);

  EXPECT_EQ(structs["Foo"].fields["l"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo"].fields["l"].type.size, 8U);
  EXPECT_EQ(structs["Foo"].fields["l"].offset, 0);
}

TEST(clang_parser, integer_ptr)
{
  BPFtrace bpftrace;
  parse("struct Foo { int *x; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("Foo"), 1U);

  EXPECT_EQ(structs["Foo"].size, 8);
  ASSERT_EQ(structs["Foo"].fields.size(), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("x"), 1U);

  EXPECT_EQ(structs["Foo"].fields["x"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo"].fields["x"].type.size, sizeof(uintptr_t));
  EXPECT_EQ(structs["Foo"].fields["x"].type.is_pointer, true);
  EXPECT_EQ(structs["Foo"].fields["x"].type.pointee_size, sizeof(int));
  EXPECT_EQ(structs["Foo"].fields["x"].offset, 0);
}

TEST(clang_parser, string_ptr)
{
  BPFtrace bpftrace;
  parse("struct Foo { char *str; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("Foo"), 1U);

  EXPECT_EQ(structs["Foo"].size, 8);
  ASSERT_EQ(structs["Foo"].fields.size(), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("str"), 1U);

  EXPECT_EQ(structs["Foo"].fields["str"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo"].fields["str"].type.size, sizeof(uintptr_t));
  EXPECT_EQ(structs["Foo"].fields["str"].type.is_pointer, true);
  EXPECT_EQ(structs["Foo"].fields["str"].type.pointee_size, 1U);
  EXPECT_EQ(structs["Foo"].fields["str"].offset, 0);
}

TEST(clang_parser, string_array)
{
  BPFtrace bpftrace;
  parse("struct Foo { char str[32]; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("Foo"), 1U);

  EXPECT_EQ(structs["Foo"].size, 32);
  ASSERT_EQ(structs["Foo"].fields.size(), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("str"), 1U);

  EXPECT_EQ(structs["Foo"].fields["str"].type.type, Type::string);
  EXPECT_EQ(structs["Foo"].fields["str"].type.size, 32U);
  EXPECT_EQ(structs["Foo"].fields["str"].offset, 0);
}

TEST(clang_parser, nested_struct_named)
{
  BPFtrace bpftrace;
  parse("struct Bar { int x; } struct Foo { struct Bar bar; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 2U);
  ASSERT_EQ(structs.count("Foo"), 1U);
  ASSERT_EQ(structs.count("Bar"), 1U);

  EXPECT_EQ(structs["Foo"].size, 4);
  ASSERT_EQ(structs["Foo"].fields.size(), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("bar"), 1U);

  EXPECT_EQ(structs["Foo"].fields["bar"].type.type, Type::cast);
  EXPECT_EQ(structs["Foo"].fields["bar"].type.cast_type, "Bar");
  EXPECT_EQ(structs["Foo"].fields["bar"].type.size, 4U);
  EXPECT_EQ(structs["Foo"].fields["bar"].offset, 0);
}

TEST(clang_parser, nested_struct_ptr_named)
{
  BPFtrace bpftrace;
  parse("struct Bar { int x; } struct Foo { struct Bar *bar; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 2U);
  ASSERT_EQ(structs.count("Foo"), 1U);
  ASSERT_EQ(structs.count("Bar"), 1U);

  EXPECT_EQ(structs["Foo"].size, 8);
  ASSERT_EQ(structs["Foo"].fields.size(), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("bar"), 1U);

  EXPECT_EQ(structs["Foo"].fields["bar"].type.type, Type::cast);
  EXPECT_EQ(structs["Foo"].fields["bar"].type.cast_type, "Bar");
  EXPECT_EQ(structs["Foo"].fields["bar"].type.size, sizeof(uintptr_t));
  EXPECT_EQ(structs["Foo"].fields["bar"].type.is_pointer, true);
  EXPECT_EQ(structs["Foo"].fields["bar"].type.pointee_size, 4U);
  EXPECT_EQ(structs["Foo"].fields["bar"].offset, 0);
}

TEST(clang_parser, nested_struct_anon)
{
  BPFtrace bpftrace;
  parse("struct Foo { struct { int x; } bar; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 2U);
  ASSERT_EQ(structs.count("Foo"), 1U);

  EXPECT_EQ(structs["Foo"].size, 4);
  ASSERT_EQ(structs["Foo"].fields.size(), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("bar"), 1U);

  EXPECT_EQ(structs["Foo"].fields["bar"].type.type, Type::cast);
  EXPECT_EQ(structs["Foo"].fields["bar"].type.cast_type, "Foo::(anonymous at definitions.h:1:14)");
  EXPECT_EQ(structs["Foo"].fields["bar"].type.size, 4U);
  EXPECT_EQ(structs["Foo"].fields["bar"].offset, 0);
}

TEST(clang_parser, nested_struct_indirect_fields)
{
  BPFtrace bpftrace;
  parse("struct Foo { struct { int x; int y;}; int a; struct { int z; }; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs["Foo"].fields.size(), 4U);
  EXPECT_EQ(structs["Foo"].fields["x"].offset, 0);
  EXPECT_EQ(structs["Foo"].fields["x"].type.size, 4U);
  EXPECT_EQ(structs["Foo"].fields["y"].offset, 4);
  EXPECT_EQ(structs["Foo"].fields["y"].type.size, 4U);
  EXPECT_EQ(structs["Foo"].fields["a"].offset, 8);
  EXPECT_EQ(structs["Foo"].fields["a"].type.size, 4U);
  EXPECT_EQ(structs["Foo"].fields["z"].offset, 12);
  EXPECT_EQ(structs["Foo"].fields["z"].type.size, 4U);
}

TEST(clang_parser, nested_struct_anon_union_struct)
{
  BPFtrace bpftrace;
  parse("struct Foo { union { long long _xy; struct { int x; int y;}; }; int a; struct { int z; }; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs["Foo"].fields.size(), 5U);
  EXPECT_EQ(structs["Foo"].fields["_xy"].offset, 0);
  EXPECT_EQ(structs["Foo"].fields["_xy"].type.size, 8U);
  EXPECT_EQ(structs["Foo"].fields["x"].offset, 0);
  EXPECT_EQ(structs["Foo"].fields["x"].type.size, 4U);
  EXPECT_EQ(structs["Foo"].fields["y"].offset, 4);
  EXPECT_EQ(structs["Foo"].fields["y"].type.size, 4U);
  EXPECT_EQ(structs["Foo"].fields["a"].offset, 8);
  EXPECT_EQ(structs["Foo"].fields["a"].type.size, 4U);
  EXPECT_EQ(structs["Foo"].fields["z"].offset, 12);
  EXPECT_EQ(structs["Foo"].fields["z"].type.size, 4U);
}

TEST(clang_parser, builtin_headers)
{
  // size_t is definied in stddef.h
  BPFtrace bpftrace;
  parse("#include <stddef.h>\nstruct Foo { size_t x, y, z; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.count("Foo"), 1U);

  EXPECT_EQ(structs["Foo"].size, 24);
  ASSERT_EQ(structs["Foo"].fields.size(), 3U);
  ASSERT_EQ(structs["Foo"].fields.count("x"), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("y"), 1U);
  ASSERT_EQ(structs["Foo"].fields.count("z"), 1U);

  EXPECT_EQ(structs["Foo"].fields["x"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo"].fields["x"].type.size, 8U);
  EXPECT_EQ(structs["Foo"].fields["x"].offset, 0);

  EXPECT_EQ(structs["Foo"].fields["y"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo"].fields["y"].type.size, 8U);
  EXPECT_EQ(structs["Foo"].fields["y"].offset, 8);

  EXPECT_EQ(structs["Foo"].fields["z"].type.type, Type::integer);
  EXPECT_EQ(structs["Foo"].fields["z"].type.size, 8U);
  EXPECT_EQ(structs["Foo"].fields["z"].offset, 16);
}

TEST(clang_parser, macro_preprocessor)
{
  // size_t is definied in stddef.h
  BPFtrace bpftrace;
  parse("#define FOO size_t\n k:f { 0 }", bpftrace);

  auto &macros = bpftrace.macros_;

  ASSERT_EQ(macros.count("FOO"), 1U);
  ASSERT_EQ(macros["FOO"], "size_t");
}

} // namespace clang_parser
} // namespace test
} // namespace bpftrace
