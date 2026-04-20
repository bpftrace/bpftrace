#include "ast/passes/types/parsed_type_bridge.h"
#include "ast/ast.h"
#include "ast/context.h"
#include "ast/location.h"
#include "ast_matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace bpftrace::test::parsed_type_bridge {

using namespace bpftrace::ast;

namespace {

Location loc(ASTContext &ctx)
{
  return ctx.location(SourceLocation{});
}

} // namespace

TEST(parsed_type_bridge, parsed_type_to_sized_type_builtin_array)
{
  ASTContext ctx;
  auto *elem = ctx.make_node<ast::ParsedType>(loc(ctx),
                                              ast::ParsedType::Kind::Identifier,
                                              "string");
  auto *type = ctx.make_node<ast::ParsedType>(loc(ctx),
                                              static_cast<uint64_t>(16),
                                              elem);

  auto sized = parsed_type_to_sized_type(*type);

  EXPECT_EQ(sized, CreateString(16));
}

TEST(parsed_type_bridge, parsed_type_to_sized_type_builtin_unsized)
{
  ASTContext ctx;
  auto *type = ctx.make_node<ast::ParsedType>(loc(ctx),
                                              ast::ParsedType::Kind::Identifier,
                                              "string");

  auto sized = parsed_type_to_sized_type(*type);

  EXPECT_EQ(sized, CreateString(0));
}

TEST(parsed_type_bridge, parsed_type_to_sized_type_known_builtin_scalars)
{
  ASTContext ctx;

  auto *bool_type = ctx.make_node<ast::ParsedType>(
      loc(ctx), ast::ParsedType::Kind::Identifier, "bool");
  EXPECT_EQ(parsed_type_to_sized_type(*bool_type), CreateBool());

  auto *int_type = ctx.make_node<ast::ParsedType>(
      loc(ctx), ast::ParsedType::Kind::Identifier, "int32");
  EXPECT_EQ(parsed_type_to_sized_type(*int_type), CreateInt32());

  auto *avg_type = ctx.make_node<ast::ParsedType>(
      loc(ctx), ast::ParsedType::Kind::Identifier, "avg_t");
  EXPECT_EQ(parsed_type_to_sized_type(*avg_type), CreateAvg(true));

  auto *uavg_type = ctx.make_node<ast::ParsedType>(
      loc(ctx), ast::ParsedType::Kind::Identifier, "uavg_t");
  EXPECT_EQ(parsed_type_to_sized_type(*uavg_type), CreateAvg(false));
}

TEST(parsed_type_bridge, parsed_type_to_sized_type_pointer_to_struct)
{
  ASTContext ctx;
  auto *pointee = ctx.make_node<ast::ParsedType>(loc(ctx),
                                                 ast::ParsedType::Kind::Struct,
                                                 "task_struct");
  auto *type = ctx.make_node<ast::ParsedType>(loc(ctx), pointee);

  auto sized = parsed_type_to_sized_type(*type);

  EXPECT_EQ(sized, CreatePointer(CreateCStruct("struct task_struct")));
}

TEST(parsed_type_bridge, parsed_type_to_sized_type_array_of_pointer_to_struct)
{
  ASTContext ctx;
  auto *pointee = ctx.make_node<ast::ParsedType>(loc(ctx),
                                                 ast::ParsedType::Kind::Struct,
                                                 "task_struct");
  auto *ptr = ctx.make_node<ast::ParsedType>(loc(ctx), pointee);
  auto *type = ctx.make_node<ast::ParsedType>(loc(ctx),
                                              static_cast<uint64_t>(8),
                                              ptr);

  auto sized = parsed_type_to_sized_type(*type);

  EXPECT_EQ(sized,
            CreateArray(8, CreatePointer(CreateCStruct("struct task_struct"))));
}

TEST(parsed_type_bridge, parsed_type_to_sized_type_array_of_pointer_to_typdef)
{
  ASTContext ctx;
  auto *pointee = ctx.make_node<ast::ParsedType>(
      loc(ctx), ast::ParsedType::Kind::Identifier, "rand_typedef");
  auto *ptr = ctx.make_node<ast::ParsedType>(loc(ctx), pointee);
  auto *type = ctx.make_node<ast::ParsedType>(loc(ctx),
                                              static_cast<uint64_t>(8),
                                              ptr);

  auto sized = parsed_type_to_sized_type(*type);

  EXPECT_EQ(sized,
            CreateArray(8, CreatePointer(CreateCStruct("rand_typedef"))));
}

TEST(parsed_type_bridge, parsed_type_to_sized_type_pointer_to_pointer)
{
  ASTContext ctx;
  auto *base = ctx.make_node<ast::ParsedType>(loc(ctx),
                                              ast::ParsedType::Kind::Identifier,
                                              "int64");
  auto *inner_ptr = ctx.make_node<ast::ParsedType>(loc(ctx), base);
  auto *type = ctx.make_node<ast::ParsedType>(loc(ctx), inner_ptr);

  auto sized = parsed_type_to_sized_type(*type);

  EXPECT_EQ(sized, CreatePointer(CreatePointer(CreateInt64())));
}

TEST(parsed_type_bridge, parsed_type_to_sized_type_void)
{
  ASTContext ctx;
  auto *type = ctx.make_node<ast::ParsedType>(loc(ctx),
                                              ast::ParsedType::Kind::Identifier,
                                              "void");

  auto sized = parsed_type_to_sized_type(*type);

  EXPECT_EQ(sized, CreateVoid());
}

TEST(parsed_type_bridge, sized_type_to_parsed_type_preserves_named_types)
{
  ASTContext ctx;

  auto *struct_type = sized_type_to_parsed_type(ctx,
                                                loc(ctx),
                                                CreateCStruct("struct sock"));
  EXPECT_EQ(
      *struct_type,
      ast::ParsedType(ctx, loc(ctx), ast::ParsedType::Kind::Struct, "sock"));

  auto *union_type = sized_type_to_parsed_type(ctx,
                                               loc(ctx),
                                               CreateCStruct("union foo"));
  EXPECT_EQ(
      *union_type,
      ast::ParsedType(ctx, loc(ctx), ast::ParsedType::Kind::Union, "foo"));

  auto *enum_type = sized_type_to_parsed_type(ctx,
                                              loc(ctx),
                                              CreateEnum(64, "bar"));
  EXPECT_EQ(*enum_type,
            ast::ParsedType(ctx, loc(ctx), ast::ParsedType::Kind::Enum, "bar"));
}

TEST(parsed_type_bridge, sized_type_to_parsed_type_known_scalars)
{
  ASTContext ctx;

  auto *bool_type = sized_type_to_parsed_type(ctx, loc(ctx), CreateBool());
  EXPECT_EQ(*bool_type,
            ast::ParsedType(
                ctx, loc(ctx), ast::ParsedType::Kind::Identifier, "bool"));

  auto *int_type = sized_type_to_parsed_type(ctx, loc(ctx), CreateInt64());
  EXPECT_EQ(*int_type,
            ast::ParsedType(
                ctx, loc(ctx), ast::ParsedType::Kind::Identifier, "int64"));

  auto *avg_type = sized_type_to_parsed_type(ctx, loc(ctx), CreateAvg(true));
  EXPECT_EQ(*avg_type,
            ast::ParsedType(
                ctx, loc(ctx), ast::ParsedType::Kind::Identifier, "avg_t"));

  auto *uavg_type = sized_type_to_parsed_type(ctx, loc(ctx), CreateAvg(false));
  EXPECT_EQ(*uavg_type,
            ast::ParsedType(
                ctx, loc(ctx), ast::ParsedType::Kind::Identifier, "uavg_t"));
}

TEST(parsed_type_bridge, sized_type_to_parsed_type_void)
{
  ASTContext ctx;

  auto *type = sized_type_to_parsed_type(ctx, loc(ctx), CreateVoid());
  EXPECT_EQ(*type,
            ast::ParsedType(
                ctx, loc(ctx), ast::ParsedType::Kind::Identifier, "void"));
}

TEST(parsed_type_bridge, sized_type_to_parsed_type_preserves_nested_types)
{
  ASTContext ctx;

  auto *type = sized_type_to_parsed_type(
      ctx, loc(ctx), CreatePointer(CreateArray(4, CreateInt8())));

  EXPECT_THAT(*type,
              bpftrace::test::ParsedType(ast::ParsedType::Kind::Pointer)
                  .WithInner(
                      bpftrace::test::ParsedType(ast::ParsedType::Kind::Array)
                          .WithArraySize(4)
                          .WithInner(bpftrace::test::ParsedType(
                              ast::ParsedType::Kind::Identifier, "int8"))));
}

TEST(parsed_type_bridge, sized_type_to_parsed_type_pointer_to_pointer)
{
  ASTContext ctx;

  auto *type = sized_type_to_parsed_type(
      ctx, loc(ctx), CreatePointer(CreatePointer(CreateInt64())));

  EXPECT_THAT(*type,
              bpftrace::test::ParsedType(ast::ParsedType::Kind::Pointer)
                  .WithInner(
                      bpftrace::test::ParsedType(ast::ParsedType::Kind::Pointer)
                          .WithInner(bpftrace::test::ParsedType(
                              ast::ParsedType::Kind::Identifier, "int64"))));
}

TEST(parsed_type_bridge, sized_type_to_parsed_type_array_of_pointer_to_struct)
{
  ASTContext ctx;

  auto *type = sized_type_to_parsed_type(
      ctx,
      loc(ctx),
      CreateArray(4, CreatePointer(CreateCStruct("struct task_struct"))));

  EXPECT_THAT(*type,
              bpftrace::test::ParsedType(ast::ParsedType::Kind::Array)
                  .WithArraySize(4)
                  .WithInner(
                      bpftrace::test::ParsedType(ast::ParsedType::Kind::Pointer)
                          .WithInner(bpftrace::test::ParsedType(
                              ast::ParsedType::Kind::Struct, "task_struct"))));
}

TEST(parsed_type_bridge, sized_type_to_parsed_type_array_of_pointer_to_typedef)
{
  ASTContext ctx;

  auto *type = sized_type_to_parsed_type(
      ctx,
      loc(ctx),
      CreateArray(4, CreatePointer(CreateCStruct("rand_typedef"))));

  EXPECT_THAT(*type,
              bpftrace::test::ParsedType(ast::ParsedType::Kind::Array)
                  .WithArraySize(4)
                  .WithInner(
                      bpftrace::test::ParsedType(ast::ParsedType::Kind::Pointer)
                          .WithInner(bpftrace::test::ParsedType(
                              ast::ParsedType::Kind::Identifier,
                              "rand_typedef"))));
}

} // namespace bpftrace::test::parsed_type_bridge
