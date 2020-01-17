#include "gtest/gtest.h"
#include "clang_parser.h"
#include "driver.h"
#include "bpftrace.h"
#include "struct.h"
#include "field_analyser.h"
#include <iostream>

namespace bpftrace {
namespace test {
namespace clang_parser {

using StructMap = std::map<std::string, Struct>;

static void parse(const std::string &input, BPFtrace &bpftrace, bool result = true,
                  const std::string& probe = "kprobe:sys_read { 1 }")
{
  auto extended_input = input + probe;
  Driver driver(bpftrace);
  ASSERT_EQ(driver.parse_str(extended_input), 0);

  ast::FieldAnalyser fields(driver.root_, bpftrace);
  EXPECT_EQ(fields.analyse(), 0);

  ClangParser clang;
  ASSERT_EQ(clang.parse(driver.root_, bpftrace), result);
}

TEST(clang_parser, integers)
{
  BPFtrace bpftrace;
  parse("struct Foo { int x; int y, z; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 12);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 3U);
  ASSERT_EQ(structs["struct Foo"].fields.count("x"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("y"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("z"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["x"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["x"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["x"].offset, 0);

  EXPECT_EQ(structs["struct Foo"].fields["y"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["y"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["y"].offset, 4);

  EXPECT_EQ(structs["struct Foo"].fields["z"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["z"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["z"].offset, 8);
}

TEST(clang_parser, c_union)
{
  BPFtrace bpftrace;
  parse("union Foo { char c; short s; int i; long l; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("union Foo"), 1U);

  EXPECT_EQ(structs["union Foo"].size, 8);
  ASSERT_EQ(structs["union Foo"].fields.size(), 4U);
  ASSERT_EQ(structs["union Foo"].fields.count("c"), 1U);
  ASSERT_EQ(structs["union Foo"].fields.count("s"), 1U);
  ASSERT_EQ(structs["union Foo"].fields.count("i"), 1U);
  ASSERT_EQ(structs["union Foo"].fields.count("l"), 1U);

  EXPECT_EQ(structs["union Foo"].fields["c"].type.type, Type::integer);
  EXPECT_EQ(structs["union Foo"].fields["c"].type.size, 1U);
  EXPECT_EQ(structs["union Foo"].fields["c"].offset, 0);

  EXPECT_EQ(structs["union Foo"].fields["s"].type.type, Type::integer);
  EXPECT_EQ(structs["union Foo"].fields["s"].type.size, 2U);
  EXPECT_EQ(structs["union Foo"].fields["s"].offset, 0);

  EXPECT_EQ(structs["union Foo"].fields["i"].type.type, Type::integer);
  EXPECT_EQ(structs["union Foo"].fields["i"].type.size, 4U);
  EXPECT_EQ(structs["union Foo"].fields["i"].offset, 0);

  EXPECT_EQ(structs["union Foo"].fields["l"].type.type, Type::integer);
  EXPECT_EQ(structs["union Foo"].fields["l"].type.size, 8U);
  EXPECT_EQ(structs["union Foo"].fields["l"].offset, 0);
}

TEST(clang_parser, c_enum)
{
  BPFtrace bpftrace;
  parse("enum E {NONE}; struct Foo { enum E e; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 4);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("e"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["e"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["e"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["e"].offset, 0);
}

TEST(clang_parser, integer_ptr)
{
  BPFtrace bpftrace;
  parse("struct Foo { int *x; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 8);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("x"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["x"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["x"].type.size, sizeof(uintptr_t));
  EXPECT_EQ(structs["struct Foo"].fields["x"].type.is_pointer, true);
  EXPECT_EQ(structs["struct Foo"].fields["x"].type.pointee_size, sizeof(int));
  EXPECT_EQ(structs["struct Foo"].fields["x"].offset, 0);
}

TEST(clang_parser, string_ptr)
{
  BPFtrace bpftrace;
  parse("struct Foo { char *str; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 8);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("str"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["str"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["str"].type.size, sizeof(uintptr_t));
  EXPECT_EQ(structs["struct Foo"].fields["str"].type.is_pointer, true);
  EXPECT_EQ(structs["struct Foo"].fields["str"].type.pointee_size, 1U);
  EXPECT_EQ(structs["struct Foo"].fields["str"].offset, 0);
}

TEST(clang_parser, string_array)
{
  BPFtrace bpftrace;
  parse("struct Foo { char str[32]; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 32);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("str"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["str"].type.type, Type::string);
  EXPECT_EQ(structs["struct Foo"].fields["str"].type.size, 32U);
  EXPECT_EQ(structs["struct Foo"].fields["str"].offset, 0);
}

TEST(clang_parser, nested_struct_named)
{
  BPFtrace bpftrace;
  parse("struct Bar { int x; } struct Foo { struct Bar bar; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 2U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);
  ASSERT_EQ(structs.count("struct Bar"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 4);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("bar"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["bar"].type.type, Type::cast);
  EXPECT_EQ(structs["struct Foo"].fields["bar"].type.cast_type, "struct Bar");
  EXPECT_EQ(structs["struct Foo"].fields["bar"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["bar"].offset, 0);
}

TEST(clang_parser, nested_struct_ptr_named)
{
  BPFtrace bpftrace;
  parse("struct Bar { int x; } struct Foo { struct Bar *bar; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 2U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);
  ASSERT_EQ(structs.count("struct Bar"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 8);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("bar"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["bar"].type.type, Type::cast);
  EXPECT_EQ(structs["struct Foo"].fields["bar"].type.cast_type, "struct Bar");
  EXPECT_EQ(structs["struct Foo"].fields["bar"].type.size, sizeof(uintptr_t));
  EXPECT_EQ(structs["struct Foo"].fields["bar"].type.is_pointer, true);
  EXPECT_EQ(structs["struct Foo"].fields["bar"].type.pointee_size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["bar"].offset, 0);
}

TEST(clang_parser, nested_struct_no_type)
{
  BPFtrace bpftrace;
  // bar and baz's struct/union do not have type names, but are not anonymous
  // since they are called bar and baz
  parse("struct Foo { struct { int x; } bar; union { int y; } baz; }", bpftrace);

  std::string bar = "struct Foo::(anonymous at definitions.h:1:14)";
  std::string baz = "union Foo::(anonymous at definitions.h:1:37)";

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 3U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);
  ASSERT_EQ(structs.count(bar), 1U);
  ASSERT_EQ(structs.count(baz), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 8);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 2U);
  ASSERT_EQ(structs["struct Foo"].fields.count("bar"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("baz"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["bar"].type.type, Type::cast);
  EXPECT_EQ(structs["struct Foo"].fields["bar"].type.cast_type, bar);
  EXPECT_EQ(structs["struct Foo"].fields["bar"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["bar"].offset, 0);

  EXPECT_EQ(structs["struct Foo"].fields["baz"].type.type, Type::cast);
  EXPECT_EQ(structs["struct Foo"].fields["baz"].type.cast_type, baz);
  EXPECT_EQ(structs["struct Foo"].fields["baz"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["baz"].offset, 4);

  EXPECT_EQ(structs[bar].size, 4);
  ASSERT_EQ(structs[bar].fields.size(), 1U);
  ASSERT_EQ(structs[bar].fields.count("x"), 1U);

  EXPECT_EQ(structs[bar].fields["x"].type.type, Type::integer);
  EXPECT_EQ(structs[bar].fields["x"].type.size, 4U);
  EXPECT_EQ(structs[bar].fields["x"].offset, 0);

  EXPECT_EQ(structs[baz].size, 4);
  ASSERT_EQ(structs[baz].fields.size(), 1U);
  ASSERT_EQ(structs[baz].fields.count("y"), 1U);

  EXPECT_EQ(structs[baz].fields["y"].type.type, Type::integer);
  EXPECT_EQ(structs[baz].fields["y"].type.size, 4U);
  EXPECT_EQ(structs[baz].fields["y"].offset, 0);
}

TEST(clang_parser, nested_struct_unnamed_fields)
{
  BPFtrace bpftrace;
  parse("struct Foo"
        "{"
        "  struct { int x; int y; };" // Anonymous struct field
        "  int a;"
        "  struct Bar { int z; };" // Struct definition - not a field of Foo
        "}",
        bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 2U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);
  ASSERT_EQ(structs.count("struct Bar"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 12);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 3U);
  ASSERT_EQ(structs["struct Foo"].fields.count("x"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("y"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("a"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["x"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["x"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["x"].offset, 0);
  EXPECT_EQ(structs["struct Foo"].fields["y"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["y"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["y"].offset, 4);
  EXPECT_EQ(structs["struct Foo"].fields["a"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["a"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["a"].offset, 8);


  EXPECT_EQ(structs["struct Bar"].size, 4);
  EXPECT_EQ(structs["struct Bar"].fields.size(), 1U);
  EXPECT_EQ(structs["struct Bar"].fields.count("z"), 1U);

  EXPECT_EQ(structs["struct Bar"].fields["z"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Bar"].fields["z"].type.size, 4U);
  EXPECT_EQ(structs["struct Bar"].fields["z"].offset, 0);
}

TEST(clang_parser, nested_struct_anon_union_struct)
{
  BPFtrace bpftrace;
  parse("struct Foo"
        "{"
        "  union"
        "  {"
        "    long long _xy;"
        "    struct { int x; int y;};"
        "  };"
        "  int a;"
        "  struct { int z; };"
        "}",
        bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 16);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 5U);
  ASSERT_EQ(structs["struct Foo"].fields.count("_xy"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("x"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("y"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("a"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("z"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["_xy"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["_xy"].type.size, 8U);
  EXPECT_EQ(structs["struct Foo"].fields["_xy"].offset, 0);

  EXPECT_EQ(structs["struct Foo"].fields["x"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["x"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["x"].offset, 0);

  EXPECT_EQ(structs["struct Foo"].fields["y"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["y"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["y"].offset, 4);

  EXPECT_EQ(structs["struct Foo"].fields["a"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["a"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["a"].offset, 8);

  EXPECT_EQ(structs["struct Foo"].fields["z"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["z"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["z"].offset, 12);
}

TEST(clang_parser, bitfields)
{
  BPFtrace bpftrace;
  parse("struct Foo { int a:8, b:8, c:16; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 4);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 3U);
  ASSERT_EQ(structs["struct Foo"].fields.count("a"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("b"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("c"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["a"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["a"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["a"].offset, 0);
  EXPECT_TRUE(structs["struct Foo"].fields["a"].is_bitfield);
  EXPECT_EQ(structs["struct Foo"].fields["a"].bitfield.read_bytes, 0x1U);
  EXPECT_EQ(structs["struct Foo"].fields["a"].bitfield.access_rshift, 0U);
  EXPECT_EQ(structs["struct Foo"].fields["a"].bitfield.mask, 0xFFU);

  EXPECT_EQ(structs["struct Foo"].fields["b"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["b"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["b"].offset, 1);
  EXPECT_TRUE(structs["struct Foo"].fields["b"].is_bitfield);
  EXPECT_EQ(structs["struct Foo"].fields["b"].bitfield.read_bytes, 0x1U);
  EXPECT_EQ(structs["struct Foo"].fields["b"].bitfield.access_rshift, 0U);
  EXPECT_EQ(structs["struct Foo"].fields["b"].bitfield.mask, 0xFFU);

  EXPECT_EQ(structs["struct Foo"].fields["c"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["c"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["c"].offset, 2);
  EXPECT_TRUE(structs["struct Foo"].fields["c"].is_bitfield);
  EXPECT_EQ(structs["struct Foo"].fields["c"].bitfield.read_bytes, 0x2U);
  EXPECT_EQ(structs["struct Foo"].fields["c"].bitfield.access_rshift, 0U);
  EXPECT_EQ(structs["struct Foo"].fields["c"].bitfield.mask, 0xFFFFU);
}

TEST(clang_parser, bitfields_uneven_fields)
{
  BPFtrace bpftrace;
  parse("struct Foo { int a:1, b:1, c:3, d:20, e:7; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 4);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 5U);
  ASSERT_EQ(structs["struct Foo"].fields.count("a"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("b"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("c"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("d"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("e"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["a"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["a"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["a"].offset, 0);
  EXPECT_TRUE(structs["struct Foo"].fields["a"].is_bitfield);
  EXPECT_EQ(structs["struct Foo"].fields["a"].bitfield.read_bytes, 1U);
  EXPECT_EQ(structs["struct Foo"].fields["a"].bitfield.access_rshift, 0U);
  EXPECT_EQ(structs["struct Foo"].fields["a"].bitfield.mask, 0x1U);

  EXPECT_EQ(structs["struct Foo"].fields["b"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["b"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["b"].offset, 0);
  EXPECT_TRUE(structs["struct Foo"].fields["b"].is_bitfield);
  EXPECT_EQ(structs["struct Foo"].fields["b"].bitfield.read_bytes, 1U);
  EXPECT_EQ(structs["struct Foo"].fields["b"].bitfield.access_rshift, 1U);
  EXPECT_EQ(structs["struct Foo"].fields["b"].bitfield.mask, 0x1U);

  EXPECT_EQ(structs["struct Foo"].fields["c"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["c"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["c"].offset, 0);
  EXPECT_TRUE(structs["struct Foo"].fields["c"].is_bitfield);
  EXPECT_EQ(structs["struct Foo"].fields["c"].bitfield.read_bytes, 1U);
  EXPECT_EQ(structs["struct Foo"].fields["c"].bitfield.access_rshift, 2U);
  EXPECT_EQ(structs["struct Foo"].fields["c"].bitfield.mask, 0x7U);

  EXPECT_EQ(structs["struct Foo"].fields["d"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["d"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["d"].offset, 0);
  EXPECT_TRUE(structs["struct Foo"].fields["d"].is_bitfield);
  EXPECT_EQ(structs["struct Foo"].fields["d"].bitfield.read_bytes, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["d"].bitfield.access_rshift, 5U);
  EXPECT_EQ(structs["struct Foo"].fields["d"].bitfield.mask, 0xFFFFFU);

  EXPECT_EQ(structs["struct Foo"].fields["e"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["e"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["e"].offset, 3);
  EXPECT_TRUE(structs["struct Foo"].fields["e"].is_bitfield);
  EXPECT_EQ(structs["struct Foo"].fields["e"].bitfield.read_bytes, 1U);
  EXPECT_EQ(structs["struct Foo"].fields["e"].bitfield.access_rshift, 1U);
  EXPECT_EQ(structs["struct Foo"].fields["e"].bitfield.mask, 0x7FU);
}

TEST(clang_parser, bitfields_with_padding)
{
  BPFtrace bpftrace;
  parse("struct Foo { int pad; int a:28, b:4; long int end;}", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 1U);
  ASSERT_EQ(structs.count("struct Foo"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 16);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 4U);
  ASSERT_EQ(structs["struct Foo"].fields.count("pad"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("a"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("b"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("end"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["a"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["a"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["a"].offset, 4);
  EXPECT_TRUE(structs["struct Foo"].fields["a"].is_bitfield);
  EXPECT_EQ(structs["struct Foo"].fields["a"].bitfield.read_bytes, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["a"].bitfield.access_rshift, 0U);
  EXPECT_EQ(structs["struct Foo"].fields["a"].bitfield.mask, 0xFFFFFFFU);

  EXPECT_EQ(structs["struct Foo"].fields["b"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["b"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["b"].offset, 7);
  EXPECT_TRUE(structs["struct Foo"].fields["b"].is_bitfield);
  EXPECT_EQ(structs["struct Foo"].fields["b"].bitfield.read_bytes, 1U);
  EXPECT_EQ(structs["struct Foo"].fields["b"].bitfield.access_rshift, 4U);
  EXPECT_EQ(structs["struct Foo"].fields["b"].bitfield.mask, 0xFU);
}

TEST(clang_parser, builtin_headers)
{
  // size_t is definied in stddef.h
  BPFtrace bpftrace;
  parse("#include <stddef.h>\nstruct Foo { size_t x, y, z; }", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.count("struct Foo"), 1U);

  EXPECT_EQ(structs["struct Foo"].size, 24);
  ASSERT_EQ(structs["struct Foo"].fields.size(), 3U);
  ASSERT_EQ(structs["struct Foo"].fields.count("x"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("y"), 1U);
  ASSERT_EQ(structs["struct Foo"].fields.count("z"), 1U);

  EXPECT_EQ(structs["struct Foo"].fields["x"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["x"].type.size, 8U);
  EXPECT_EQ(structs["struct Foo"].fields["x"].offset, 0);

  EXPECT_EQ(structs["struct Foo"].fields["y"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["y"].type.size, 8U);
  EXPECT_EQ(structs["struct Foo"].fields["y"].offset, 8);

  EXPECT_EQ(structs["struct Foo"].fields["z"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo"].fields["z"].type.size, 8U);
  EXPECT_EQ(structs["struct Foo"].fields["z"].offset, 16);
}

TEST(clang_parser, macro_preprocessor)
{
  BPFtrace bpftrace;
  parse("#define FOO size_t\n k:f { 0 }", bpftrace);
  parse("#define _UNDERSCORE 314\n k:f { 0 }", bpftrace);

  auto &macros = bpftrace.macros_;

  ASSERT_EQ(macros.count("FOO"), 1U);
  EXPECT_EQ(macros["FOO"], "size_t");

  ASSERT_EQ(macros.count("_UNDERSCORE"), 1U);
  EXPECT_EQ(macros["_UNDERSCORE"], "314");
}

TEST(clang_parser, parse_fail)
{
  BPFtrace bpftrace;
  parse("struct a { int a; struct b b; };", bpftrace, false);
}

#ifdef HAVE_LIBBPF_BTF_DUMP

#include "btf_data.h"

class clang_parser_btf : public ::testing::Test {
 protected:
  void SetUp() override
  {
    char *path = strdup("/tmp/XXXXXX");
    if (!path)
      return;

    int fd = mkstemp(path);
    if (fd < 0)
    {
      std::remove(path);
      return;
    }

    if (write(fd, btf_data, btf_data_len) != btf_data_len)
    {
      close(fd);
      std::remove(path);
      return;
    }

    close(fd);
    setenv("BPFTRACE_BTF", path, true);
    path_ = path;
  }

  void TearDown() override
  {
    // clear the environment and remove the temp file
    unsetenv("BPFTRACE_BTF");
    if (path_)
      std::remove(path_);
  }

  char *path_ = nullptr;
};

TEST_F(clang_parser_btf, btf)
{
  BPFtrace bpftrace;
  parse("", bpftrace, true,
        "kprobe:sys_read {\n"
        "  @x1 = (struct Foo1 *) curtask;\n"
        "  @x2 = (struct Foo2 *) curtask;\n"
        "  @x3 = (struct Foo3 *) curtask;\n"
        "}");

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 3U);
  ASSERT_EQ(structs.count("struct Foo1"), 1U);
  ASSERT_EQ(structs.count("struct Foo2"), 1U);
  ASSERT_EQ(structs.count("struct Foo3"), 1U);

  EXPECT_EQ(structs["struct Foo1"].size, 16);
  ASSERT_EQ(structs["struct Foo1"].fields.size(), 3U);
  ASSERT_EQ(structs["struct Foo1"].fields.count("a"), 1U);
  ASSERT_EQ(structs["struct Foo1"].fields.count("b"), 1U);
  ASSERT_EQ(structs["struct Foo1"].fields.count("c"), 1U);

  EXPECT_EQ(structs["struct Foo1"].fields["a"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo1"].fields["a"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo1"].fields["a"].offset, 0);

  EXPECT_EQ(structs["struct Foo1"].fields["b"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo1"].fields["b"].type.size, 1U);
  EXPECT_EQ(structs["struct Foo1"].fields["b"].offset, 4);

  EXPECT_EQ(structs["struct Foo1"].fields["c"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo1"].fields["c"].type.size, 8U);
  EXPECT_EQ(structs["struct Foo1"].fields["c"].offset, 8);

  EXPECT_EQ(structs["struct Foo2"].size, 24);
  ASSERT_EQ(structs["struct Foo2"].fields.size(), 3U);
  ASSERT_EQ(structs["struct Foo2"].fields.count("a"), 1U);
  ASSERT_EQ(structs["struct Foo2"].fields.count("f"), 1U);
  ASSERT_EQ(structs["struct Foo2"].fields.count("g"), 1U);

  EXPECT_EQ(structs["struct Foo2"].fields["a"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo2"].fields["a"].type.size, 4U);
  EXPECT_EQ(structs["struct Foo2"].fields["a"].offset, 0);

  EXPECT_EQ(structs["struct Foo2"].fields["f"].type.type, Type::cast);
  EXPECT_EQ(structs["struct Foo2"].fields["f"].type.size, 16U);
  EXPECT_EQ(structs["struct Foo2"].fields["f"].offset, 8);

  EXPECT_EQ(structs["struct Foo2"].fields["g"].type.type, Type::integer);
  EXPECT_EQ(structs["struct Foo2"].fields["g"].type.size, 1U);
  EXPECT_EQ(structs["struct Foo2"].fields["g"].offset, 8);

  EXPECT_EQ(structs["struct Foo3"].size, 16);
  ASSERT_EQ(structs["struct Foo3"].fields.size(), 2U);
  ASSERT_EQ(structs["struct Foo3"].fields.count("foo1"), 1U);
  ASSERT_EQ(structs["struct Foo3"].fields.count("foo2"), 1U);

  EXPECT_EQ(structs["struct Foo3"].fields["foo1"].type.type, Type::cast);
  EXPECT_EQ(structs["struct Foo3"].fields["foo1"].type.size, 8U);
  EXPECT_EQ(structs["struct Foo3"].fields["foo1"].type.is_pointer, true);
  EXPECT_EQ(structs["struct Foo3"].fields["foo1"].type.cast_type, "struct Foo1");
  EXPECT_EQ(structs["struct Foo3"].fields["foo1"].offset, 0);

  EXPECT_EQ(structs["struct Foo3"].fields["foo2"].type.type, Type::cast);
  EXPECT_EQ(structs["struct Foo3"].fields["foo2"].type.size, 8U);
  EXPECT_EQ(structs["struct Foo3"].fields["foo2"].type.is_pointer, true);
  EXPECT_EQ(structs["struct Foo3"].fields["foo2"].type.cast_type, "struct Foo2");
  EXPECT_EQ(structs["struct Foo3"].fields["foo2"].offset, 8);
}

TEST_F(clang_parser_btf, btf_field_struct)
{
  BPFtrace bpftrace;
  parse("",
        bpftrace,
        true,
        "kprobe:sys_read {\n"
        "  @x3 = ((struct Foo3 *) curtask)->foo2->g;\n"
        "}");

  /* task_struct->Foo3->Foo2->char */
  EXPECT_EQ(bpftrace.btf_set_.size(), 4U);
  EXPECT_NE(bpftrace.btf_set_.find("struct task_struct"), bpftrace.btf_set_.end());
  EXPECT_NE(bpftrace.btf_set_.find("struct Foo3"), bpftrace.btf_set_.end());
  EXPECT_NE(bpftrace.btf_set_.find("struct Foo2"), bpftrace.btf_set_.end());
  EXPECT_NE(bpftrace.btf_set_.find("char"), bpftrace.btf_set_.end());
}
#endif // HAVE_LIBBPF_BTF_DUMP

TEST(clang_parser, struct_typedef)
{
  // Make sure we can differentiate between "struct max_align_t {}" and
  // "typedef struct {} max_align_t"
  BPFtrace bpftrace;
  parse("#include <__stddef_max_align_t.h>\n"
        "struct max_align_t { int x; };", bpftrace);

  StructMap &structs = bpftrace.structs_;

  ASSERT_EQ(structs.size(), 2U);
  ASSERT_EQ(structs.count("struct max_align_t"), 1U);
  ASSERT_EQ(structs.count("max_align_t"), 1U);

  // Non-typedef'd struct
  EXPECT_EQ(structs["struct max_align_t"].size, 4);
  ASSERT_EQ(structs["struct max_align_t"].fields.size(), 1U);
  ASSERT_EQ(structs["struct max_align_t"].fields.count("x"), 1U);

  EXPECT_EQ(structs["struct max_align_t"].fields["x"].type.type, Type::integer);
  EXPECT_EQ(structs["struct max_align_t"].fields["x"].type.size, 4U);
  EXPECT_EQ(structs["struct max_align_t"].fields["x"].offset, 0);

  // typedef'd struct (defined in __stddef_max_align_t.h builtin header)
  EXPECT_EQ(structs["max_align_t"].size, 32);
  ASSERT_EQ(structs["max_align_t"].fields.size(), 2U);
  ASSERT_EQ(structs["max_align_t"].fields.count("__clang_max_align_nonce1"), 1U);
  ASSERT_EQ(structs["max_align_t"].fields.count("__clang_max_align_nonce2"), 1U);

  EXPECT_EQ(structs["max_align_t"].fields["__clang_max_align_nonce1"].type.type, Type::integer);
  EXPECT_EQ(structs["max_align_t"].fields["__clang_max_align_nonce1"].type.size, 8U);
  EXPECT_EQ(structs["max_align_t"].fields["__clang_max_align_nonce1"].offset, 0);

  // double are not parsed correctly yet so these fields are junk for now
  EXPECT_EQ(structs["max_align_t"].fields["__clang_max_align_nonce2"].type.type, Type::none);
  EXPECT_EQ(structs["max_align_t"].fields["__clang_max_align_nonce2"].type.size, 0U);
  EXPECT_EQ(structs["max_align_t"].fields["__clang_max_align_nonce2"].offset, 16);
}

} // namespace clang_parser
} // namespace test
} // namespace bpftrace
