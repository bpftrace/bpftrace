#include "ast/passes/types/parsed_type_bridge.h"

#include <cassert>

#include "ast/ast.h"

namespace bpftrace {

namespace {

constexpr std::string_view STRUCT_PREFIX = "struct ";
constexpr std::string_view UNION_PREFIX = "union ";

} // namespace

SizedType parsed_type_to_sized_type(const ast::ParsedType &type)
{
  switch (type.kind) {
    case ast::ParsedType::Kind::Identifier:
      if (auto bt = ident_to_builtin_type(type.name)) {
        return *bt;
      }
      return CreateCStruct(type.name);
    case ast::ParsedType::Kind::Struct:
    case ast::ParsedType::Kind::Union:
      return CreateCStruct(type.type_name());
    case ast::ParsedType::Kind::Enum:
      return CreateEnum(64, type.name);
    case ast::ParsedType::Kind::Pointer:
      assert(type.inner);
      return CreatePointer(parsed_type_to_sized_type(*type.inner));
    case ast::ParsedType::Kind::Array:
      assert(type.inner);
      return normalize_array_to_sized_type(
          CreateArray(type.array_size, parsed_type_to_sized_type(*type.inner)));
  }

  return CreateNone();
}

ast::ParsedType *sized_type_to_parsed_type(ast::ASTContext &ctx,
                                           const ast::Location &loc,
                                           const SizedType &type)
{
  if (type.IsPtrTy()) {
    auto *pointee = sized_type_to_parsed_type(ctx, loc, type.GetPointeeTy());
    return ctx.make_node<ast::ParsedType>(loc, pointee);
  }

  if (type.IsArrayTy()) {
    auto *element = sized_type_to_parsed_type(ctx, loc, type.GetElementTy());
    return ctx.make_node<ast::ParsedType>(loc, type.GetNumElements(), element);
  }

  if (type.IsStringTy() || type.IsBufferTy() || type.IsInetTy()) {
    auto *base = ctx.make_node<ast::ParsedType>(
        loc, ast::ParsedType::Kind::Identifier, typestr(type.GetTy()));
    if (type.GetSize() == 0) {
      return base;
    }
    return ctx.make_node<ast::ParsedType>(loc, type.GetSize(), base);
  }

  if (type.IsEnumTy()) {
    return ctx.make_node<ast::ParsedType>(loc,
                                          ast::ParsedType::Kind::Enum,
                                          type.GetName());
  }

  if (type.IsCStructTy()) {
    const auto &name = type.GetName();
    if (name.starts_with(STRUCT_PREFIX)) {
      return ctx.make_node<ast::ParsedType>(loc,
                                            ast::ParsedType::Kind::Struct,
                                            name.substr(STRUCT_PREFIX.size()));
    }
    if (name.starts_with(UNION_PREFIX)) {
      return ctx.make_node<ast::ParsedType>(loc,
                                            ast::ParsedType::Kind::Union,
                                            name.substr(UNION_PREFIX.size()));
    }
    return ctx.make_node<ast::ParsedType>(loc,
                                          ast::ParsedType::Kind::Identifier,
                                          name);
  }

  return ctx.make_node<ast::ParsedType>(loc,
                                        ast::ParsedType::Kind::Identifier,
                                        typestr(type));
}

} // namespace bpftrace
