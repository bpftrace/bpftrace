#include <iostream>
#include <string.h>

#include "llvm/Config/llvm-config.h"

#include "ast.h"
#include "clang_parser.h"
#include "types.h"
#include "utils.h"
#include "headers.h"

namespace bpftrace {

static std::string get_clang_string(CXString string)
{
  std::string str = clang_getCString(string);
  clang_disposeString(string);
  return str;
}

static void remove_struct_union_prefix(std::string &str)
{
  if (strncmp(str.c_str(), "struct ", 7) == 0)
    str.erase(0, 7);
  else if (strncmp(str.c_str(), "union ", 6) == 0)
    str.erase(0, 6);
}

/*
 * is_anonymous
 *
 * Determine whether the provided cursor points to an anonymous struct.
 *
 * This union is anonymous:
 *   struct { int i; };
 * This is not, although it is marked as such in LLVM 8:
 *   struct { int i; } obj;
 * This is not, and does not actually declare an instance of a struct:
 *   struct X { int i; };
 *
 * The libclang API was changed in LLVM 8 and restored under a different
 * function in LLVM 9. For LLVM 8 there is no way to properly tell if
 * a record declaration is anonymous, so we do some hacks here.
 *
 * LLVM version differences:
 *   https://reviews.llvm.org/D54996
 *   https://reviews.llvm.org/D61232
 */
static bool is_anonymous(CXCursor c)
{
#if LLVM_VERSION_MAJOR <= 7
  return clang_Cursor_isAnonymous(c);
#elif LLVM_VERSION_MAJOR >= 9
  return clang_Cursor_isAnonymousRecordDecl(c);
#else // LLVM 8
  if (!clang_Cursor_isAnonymous(c))
    return false;

  // In LLVM 8, some structs which the above function says are anonymous
  // are actually not. We iterate through the siblings of our struct
  // definition to see if there is a field giving it a name.
  //
  // struct Parent                 struct Parent
  // {                             {
  //   struct                        struct
  //   {                             {
  //     ...                           ...
  //   } name;                       };
  //   int sibling;                  int sibling;
  // };                            };
  //
  // Children of parent:           Children of parent:
  //   Struct: (cursor c)            Struct: (cursor c)
  //   Field:  (Record)name          Field:  (int)sibling
  //   Field:  (int)sibling
  //
  // Record field found after      No record field found after
  // cursor - not anonymous        cursor - anonymous

  auto parent = clang_getCursorSemanticParent(c);
  if (clang_Cursor_isNull(parent))
    return false;

  struct AnonFinderState
  {
    CXCursor struct_to_check;
    bool is_anon;
    bool prev_was_definition;
  } state;

  state.struct_to_check = c;
  state.is_anon = true;
  state.prev_was_definition = false;

  clang_visitChildren(
      parent,
      [](CXCursor c2, CXCursor, CXClientData client_data)
      {
        auto state = static_cast<struct AnonFinderState*>(client_data);
        if (state->prev_was_definition)
        {
          // This is the next child after the definition of the struct we're
          // interested in. If it is a field containing a record, we assume
          // that it must be the field for our struct, so our struct is not
          // anonymous.
          state->prev_was_definition = false;
          auto kind = clang_getCursorKind(c2);
          auto type = clang_getCanonicalType(clang_getCursorType(c2));
          if (kind == CXCursor_FieldDecl && type.kind == CXType_Record)
          {
            state->is_anon = false;
            return CXChildVisit_Break;
          }
        }

        // We've found the definition of the struct we're interested in
        if (memcmp(c2.data, state->struct_to_check.data, 3*sizeof(uintptr_t)) == 0)
          state->prev_was_definition = true;
        return CXChildVisit_Continue;
      },
      &state);

  return state.is_anon;
#endif
}

/*
 * get_named_parent
 *
 * Find the parent struct of the field pointed to by the cursor.
 * Anonymous structs are skipped.
 */
static CXCursor get_named_parent(CXCursor c)
{
  CXCursor parent = clang_getCursorSemanticParent(c);

  while (!clang_Cursor_isNull(parent) && is_anonymous(parent))
  {
    parent = clang_getCursorSemanticParent(parent);
  }

  return parent;
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
  remove_struct_union_prefix(typestr);

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
        remove_struct_union_prefix(pointee_typestr);
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

ClangParser::ClangParserHandler::ClangParserHandler()
{
  index = clang_createIndex(1, 1);
}

ClangParser::ClangParserHandler::~ClangParserHandler()
{
  clang_disposeTranslationUnit(translation_unit);
  clang_disposeIndex(index);
}

CXTranslationUnit ClangParser::ClangParserHandler::get_translation_unit() {
  return translation_unit;
}

CXErrorCode ClangParser::ClangParserHandler::parse_translation_unit(
    const char *source_filename,
    const char *const *command_line_args,
    int num_command_line_args,
    struct CXUnsavedFile *unsaved_files,
    unsigned num_unsaved_files,
    unsigned options)
{
  return clang_parseTranslationUnit2(
      index,
      source_filename,
      command_line_args, num_command_line_args,
      unsaved_files, num_unsaved_files,
      options,
      &translation_unit);
}

CXCursor ClangParser::ClangParserHandler::get_translation_unit_cursor() {
  return clang_getTranslationUnitCursor(translation_unit);
}

bool ClangParser::parse(ast::Program *program, BPFtrace &bpftrace, std::vector<std::string> extra_flags)
{
  auto input = program->c_definitions;
  if (input.size() == 0)
    return true; // We occasionally get crashes in libclang otherwise

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
    "-isystem", "/usr/local/include",
    "-isystem", "/bpftrace/include",
    "-isystem", "/usr/include",
  };
  for (auto &flag : extra_flags)
  {
    args.push_back(flag.c_str());
  }

  ClangParserHandler handler;
  CXErrorCode error = handler.parse_translation_unit(
      "definitions.h",
      &args[0], args.size(),
      unsaved_files, sizeof(unsaved_files)/sizeof(CXUnsavedFile),
      CXTranslationUnit_DetailedPreprocessingRecord);
  if (error)
  {
    if (bt_debug == DebugLevel::kFullDebug) {
      std::cerr << "Clang error while parsing C definitions: " << error << std::endl;
      std::cerr << "Input (" << input.size() << "): " << input << std::endl;
    }
    return false;
  }

  for (unsigned int i=0; i < clang_getNumDiagnostics(handler.get_translation_unit()); i++) {
    CXDiagnostic diag = clang_getDiagnostic(handler.get_translation_unit(), i);
    CXDiagnosticSeverity severity = clang_getDiagnosticSeverity(diag);
    if (severity == CXDiagnostic_Error || severity == CXDiagnostic_Fatal) {
      if (bt_debug >= DebugLevel::kDebug)
        std::cerr << "Input (" << input.size() << "): " << input << std::endl;
      return false;
    }
  }

  CXCursor cursor = handler.get_translation_unit_cursor();

  int err = clang_visitChildren(
      cursor,
      [](CXCursor c, CXCursor parent, CXClientData client_data)
      {
        if (clang_getCursorKind(c) == CXCursor_MacroDefinition)
        {
          std::string macro_name;
          std::string macro_value;
          if (translateMacro(c, macro_name, macro_value))
          {
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

        if (clang_getCursorKind(c) == CXCursor_FieldDecl)
        {
          auto &structs = static_cast<BPFtrace*>(client_data)->structs_;

          auto named_parent = get_named_parent(c);
          auto ptype = clang_getCanonicalType(clang_getCursorType(named_parent));
          auto ptypestr = get_clang_string(clang_getTypeSpelling(ptype));
          auto ptypesize = clang_Type_getSizeOf(ptype);

          auto ident = get_clang_string(clang_getCursorSpelling(c));
          auto offset = clang_Type_getOffsetOf(ptype, ident.c_str()) / 8;
          auto type = clang_getCanonicalType(clang_getCursorType(c));

          auto struct_name = get_clang_string(clang_getCursorSpelling(named_parent));
          if (struct_name == "")
            struct_name = ptypestr;
          remove_struct_union_prefix(struct_name);

          // TODO(mmarchini): re-enable this check once we figure out how to
          // handle flexible array members.
          // if (clang_Type_getSizeOf(type) < 0) {
            // std::cerr << "Can't get size of '" << ptypestr << "::" << ident << "', please provide proper definiton." << std::endl;
            // return CXChildVisit_Break;
          // }

          structs[struct_name].fields[ident].offset = offset;
          structs[struct_name].fields[ident].type = get_sized_type(type);
          structs[struct_name].size = ptypesize;
          // if we find that ident is a data_loc_ dual register it in structs
          // with the data_loc_ prefix removed.
          if(ident.rfind("data_loc_", 0) == 0) {
            auto dl_stripped = ident.substr(9);
            structs[struct_name].fields[dl_stripped].type.is_data_loc = true;
            structs[struct_name].fields[dl_stripped].offset = offset;
            structs[struct_name].fields[dl_stripped].type = get_sized_type(type);
            structs[struct_name].size = ptypesize;
          }
        }

        return CXChildVisit_Recurse;
      },
      &bpftrace);

  // clang_visitChildren returns a non-zero value if the traversal
  // was terminated by the visitor returning CXChildVisit_Break.
  return err == 0;
}

} // namespace bpftrace
