#include <clang-c/Index.h>
#include <iostream>
#include <string.h>

#include "ast.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "types.h"

namespace bpftrace {

static std::string get_clang_string(CXString string)
{
  std::string str = clang_getCString(string);
  clang_disposeString(string);
  return str;
}

static void remove_struct_prefix(std::string &str)
{
  if (strncmp(str.c_str(), "struct ", 7) == 0)
    str.erase(0, 7);
}

static SizedType get_sized_type(CXType clang_type)
{
  auto size = clang_Type_getSizeOf(clang_type);
  auto typestr = get_clang_string(clang_getTypeSpelling(clang_type));
  remove_struct_prefix(typestr);

  switch (clang_type.kind)
  {
    case CXType_Char_S:
    case CXType_SChar:
    case CXType_UChar:
    case CXType_Short:
    case CXType_UShort:
    case CXType_Int:
    case CXType_UInt:
    case CXType_Long:
    case CXType_ULong:
      return SizedType(Type::integer, size);
    case CXType_Record:
      return SizedType(Type::cast, size, typestr);
    case CXType_Pointer:
    {
      auto pointee_type = clang_getPointeeType(clang_type);
      SizedType type;
      if (pointee_type.kind == CXType_Record)
      {
        auto pointee_typestr = get_clang_string(clang_getTypeSpelling(pointee_type));
        remove_struct_prefix(pointee_typestr);
        type = SizedType(Type::cast, sizeof(uintptr_t), pointee_typestr);
      }
      else
      {
        type = SizedType(Type::integer, sizeof(uintptr_t));
      }
      auto pointee_size = clang_Type_getSizeOf(pointee_type);
      type.is_pointer = true;
      type.pointee_size = pointee_size;
      return type;
    }
    case CXType_ConstantArray:
    {
      auto elem_type = clang_getArrayElementType(clang_type);
      auto size = clang_getArraySize(clang_type);
      if (elem_type.kind == CXType_Char_S)
      {
        return SizedType(Type::string, size);
      }
      // TODO add support for arrays
      return SizedType(Type::none, 0);
    }
    default:
      auto unknown_type = get_clang_string(clang_getTypeKindSpelling(clang_type.kind));
      std::cerr << "Error: unknown clang CXType '" << unknown_type << "'" << std::endl;
      abort();
  }
}

void ClangParser::parse(ast::Program *program, StructMap &structs)
{
  CXUnsavedFile input_file
  {
    .Filename = "definitions.h",
    .Contents = program->c_definitions.c_str(),
    .Length = program->c_definitions.size(),
  };

  if (input_file.Length == 0)
    return; // We occasionally get crashes in libclang otherwise

  CXIndex index = clang_createIndex(0, 0);
  CXTranslationUnit translation_unit;
  CXErrorCode error = clang_parseTranslationUnit2(
      index,
      "definitions.h",
      NULL,
      0,
      &input_file,
      1,
      CXTranslationUnit_None,
      &translation_unit);
  if (error)
  {
    std::cerr << "Clang error while parsing C definitions: " << error << std::endl;
    std::cerr << "Input (" << input_file.Length << "): " << input_file.Contents << std::endl;
  }

  CXCursor cursor = clang_getTranslationUnitCursor(translation_unit);

  clang_visitChildren(
      cursor,
      [](CXCursor c, CXCursor parent, CXClientData client_data)
      {
        auto &structs = *static_cast<StructMap*>(client_data);

        if (clang_getCursorKind(parent) != CXCursor_StructDecl) // TODO CXCursor_UnionDecl
          return CXChildVisit_Recurse;

        if (clang_getCursorKind(c) == CXCursor_FieldDecl)
        {
          auto struct_name = get_clang_string(clang_getCursorSpelling(parent));
          auto ident = get_clang_string(clang_getCursorSpelling(c));
          auto offset = clang_Cursor_getOffsetOfField(c) / 8;
          auto type = clang_getCanonicalType(clang_getCursorType(c));

          auto ptype = clang_getCanonicalType(clang_getCursorType(parent));
          auto ptypestr = get_clang_string(clang_getTypeSpelling(ptype));
          auto ptypesize = clang_Type_getSizeOf(ptype);

          if (struct_name == "")
            struct_name = ptypestr;
          remove_struct_prefix(struct_name);

          structs[struct_name].fields[ident].offset = offset;
          structs[struct_name].fields[ident].type = get_sized_type(type);
          structs[struct_name].size = ptypesize;
        }

        return CXChildVisit_Recurse;
      },
      &structs);

  clang_disposeTranslationUnit(translation_unit);
  clang_disposeIndex(index);
}

} // namespace bpftrace
