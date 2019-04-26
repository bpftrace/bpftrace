#include <clang-c/Index.h>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <string.h>

#include "ast.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "types.h"
#include "utils.h"
#include "headers.h"

namespace bpftrace {

std::unordered_map<std::string, CXCursor> indirect_structs;
std::unordered_set<std::string> unvisited_indirect_structs;

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

static CXCursor get_indirect_field_parent_struct(CXCursor c)
{
  CXCursor parent = clang_getCursorSemanticParent(c);

  while (!clang_Cursor_isNull(parent) && indirect_structs.count(get_clang_string(clang_getTypeSpelling(clang_getCanonicalType(clang_getCursorType(parent))))) > 0) {
    parent = clang_getCursorSemanticParent(parent);
  }

  return parent;
}

static std::string get_parent_struct_name(CXCursor c)
{
  CXCursor parent = get_indirect_field_parent_struct(c);

  if (clang_getCursorKind(parent) != CXCursor_StructDecl &&
      clang_getCursorKind(parent) != CXCursor_UnionDecl)
    return "";

  return get_clang_string(clang_getCursorSpelling(parent));
}

static int get_indirect_field_offset(CXCursor c)
{
  int offset = 0;
  CXCursor parent = get_indirect_field_parent_struct(c);
  auto ident = get_clang_string(clang_getCursorSpelling(c));
  offset = clang_Type_getOffsetOf(clang_getCursorType(parent), ident.c_str()) / 8;

  return offset;
}

// NOTE(mmarchini): as suggested in http://clang-developers.42468.n3.nabble.com/Extracting-macro-information-using-libclang-the-C-Interface-to-Clang-td4042648.html#message4042666
static bool translateMacro(CXCursor cursor, std::string &name, std::string &value)
{
  CXToken* tokens    = nullptr;
  unsigned numTokens = 0;
  CXTranslationUnit transUnit = clang_Cursor_getTranslationUnit(cursor);
  CXSourceRange srcRange  = clang_getCursorExtent(cursor);
  clang_tokenize(transUnit, srcRange, &tokens, &numTokens);
  for (unsigned n=0; n<numTokens; n++)
  {
    auto tokenText = clang_getTokenSpelling(transUnit, tokens[n]);
    if (n == 0)
    {
      value.clear();
      name = clang_getCString(tokenText);
      if (name[0] == '_')
        break;
    }
    else
    {
      CXTokenKind tokenKind = clang_getTokenKind(tokens[n]);
      if (tokenKind != CXToken_Comment)
      {
        const char* text = clang_getCString(tokenText);
        if (text)
          value += text;
      }
    }
  }
  clang_disposeTokens(transUnit, tokens, numTokens);
  return value.length() != 0;
}

static SizedType get_sized_type(CXType clang_type)
{
  auto size = clang_Type_getSizeOf(clang_type);
  auto typestr = get_clang_string(clang_getTypeSpelling(clang_type));
  remove_struct_prefix(typestr);

  switch (clang_type.kind)
  {
    case CXType_Bool:
    case CXType_Char_S:
    case CXType_Char_U:
    case CXType_SChar:
    case CXType_UChar:
    case CXType_Short:
    case CXType_UShort:
    case CXType_Int:
    case CXType_UInt:
    case CXType_Long:
    case CXType_ULong:
    case CXType_LongLong:
    case CXType_ULongLong:
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
      if (elem_type.kind == CXType_Char_S || elem_type.kind == CXType_Char_U)
      {
        return SizedType(Type::string, size);
      }

      // Only support one-dimensional arrays for now
      if (elem_type.kind != CXType_ConstantArray)
      {
        auto type = get_sized_type(elem_type);
        auto sized_type = SizedType(Type::array, size);
        sized_type.pointee_size = type.size;
        sized_type.elem_type = type.type;
        return sized_type;
      } else {
        return SizedType(Type::none, 0);
      }
    }
    default:
      return SizedType(Type::none, 0);
  }
}

void ClangParser::parse(ast::Program *program, BPFtrace &bpftrace, std::vector<std::string> extra_flags)
{
  auto input = program->c_definitions;
  if (input.size() == 0)
    return; // We occasionally get crashes in libclang otherwise

  CXUnsavedFile unsaved_files[] =
  {
    {
      .Filename = "definitions.h",
      .Contents = input.c_str(),
      .Length = input.size(),
    },
    {
      .Filename = "/bpftrace/include/__stddef_max_align_t.h",
      .Contents = __stddef_max_align_t_h,
      .Length = __stddef_max_align_t_h_len,
    },
    {
      .Filename = "/bpftrace/include/float.h",
      .Contents = float_h,
      .Length = float_h_len,
    },
    {
      .Filename = "/bpftrace/include/limits.h",
      .Contents = limits_h,
      .Length = limits_h_len,
    },
    {
      .Filename = "/bpftrace/include/stdarg.h",
      .Contents = stdarg_h,
      .Length = stdarg_h_len,
    },
    {
      .Filename = "/bpftrace/include/stddef.h",
      .Contents = stddef_h,
      .Length = stddef_h_len,
    },
    {
      .Filename = "/bpftrace/include/stdint.h",
      .Contents = stdint_h,
      .Length = stdint_h_len,
    },
  };

  std::vector<const char *> args =
  {
    "-I", "/bpftrace/include",
  };
  for (auto &flag : extra_flags)
  {
    args.push_back(flag.c_str());
  }

  CXIndex index = clang_createIndex(1, 1);
  CXTranslationUnit translation_unit;
  CXErrorCode error = clang_parseTranslationUnit2(
      index,
      "definitions.h",
      &args[0], args.size(),
      unsaved_files, sizeof(unsaved_files)/sizeof(CXUnsavedFile),
      CXTranslationUnit_DetailedPreprocessingRecord,
      &translation_unit);
  if (error)
  {
    std::cerr << "Clang error while parsing C definitions: " << error << std::endl;
    std::cerr << "Input (" << input.size() << "): " << input << std::endl;
  }

  indirect_structs.clear();
  unvisited_indirect_structs.clear();

  CXCursor cursor = clang_getTranslationUnitCursor(translation_unit);

  bool iterate = true;

  do {
    clang_visitChildren(
        cursor,
        [](CXCursor c, CXCursor parent, CXClientData client_data)
        {
          if (clang_getCursorKind(c) == CXCursor_MacroDefinition)
          {
            std::string macro_name;
            std::string macro_value;
            if (translateMacro(c, macro_name, macro_value)) {
              auto &macros = static_cast<BPFtrace*>(client_data)->macros_;
              macros[macro_name] = macro_value;
            }
            return CXChildVisit_Recurse;
          }

          if (clang_getCursorKind(parent) == CXCursor_EnumDecl)
          {
            auto &enums = static_cast<BPFtrace*>(client_data)->enums_;
            enums[get_clang_string(clang_getCursorSpelling(c))] = clang_getEnumConstantDeclValue(c);
            return CXChildVisit_Recurse;
          }

          if (clang_getCursorKind(parent) != CXCursor_StructDecl &&
              clang_getCursorKind(parent) != CXCursor_UnionDecl)
            return CXChildVisit_Recurse;

          auto ptype = clang_getCanonicalType(clang_getCursorType(parent));
          auto ptypestr = get_clang_string(clang_getTypeSpelling(ptype));
          auto ptypesize = clang_Type_getSizeOf(ptype);

          if ((clang_getCursorKind(c) == CXCursor_StructDecl ||
              clang_getCursorKind(c) == CXCursor_UnionDecl) && clang_isCursorDefinition(c)) {
            auto struct_name = get_clang_string(clang_getTypeSpelling(clang_getCanonicalType(clang_getCursorType(c))));
            indirect_structs[struct_name] = c;
            unvisited_indirect_structs.insert(struct_name);

            return CXChildVisit_Continue;
          }

          if (clang_getCursorKind(c) == CXCursor_FieldDecl)
          {
            auto &structs = static_cast<BPFtrace*>(client_data)->structs_;
            auto struct_name = get_parent_struct_name(c);
            auto ident = get_clang_string(clang_getCursorSpelling(c));
            auto offset = clang_Cursor_getOffsetOfField(c) / 8;
            auto type = clang_getCanonicalType(clang_getCursorType(c));
            auto typestr = get_clang_string(clang_getTypeSpelling(type));

            if (indirect_structs.count(typestr))
              indirect_structs.erase(typestr);

            if(indirect_structs.count(ptypestr))
              offset = get_indirect_field_offset(c);

            if (struct_name == "")
              struct_name = ptypestr;
            remove_struct_prefix(struct_name);

            structs[struct_name].fields[ident].offset = offset;
            structs[struct_name].fields[ident].type = get_sized_type(type);
            structs[struct_name].size = ptypesize;
          }

          return CXChildVisit_Recurse;
        },
        &bpftrace);
    if (unvisited_indirect_structs.size()) {
      cursor = indirect_structs[*unvisited_indirect_structs.begin()];
      unvisited_indirect_structs.erase(unvisited_indirect_structs.begin());
    } else {
      iterate = false;
    }
  } while (iterate);

  // TODO(mmarchini): validate that a struct doesn't have two fields with the
  // same offset. Mark struct as invalid otherwise

  clang_disposeTranslationUnit(translation_unit);
  clang_disposeIndex(index);
}

} // namespace bpftrace
