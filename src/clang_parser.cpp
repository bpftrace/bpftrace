#include <cstring>
#include <iostream>
#include <regex>
#include <vector>

#include "llvm/Config/llvm-config.h"

#include "ast.h"
#include "btf.h"
#include "clang_parser.h"
#include "field_analyser.h"
#include "headers.h"
#include "log.h"
#include "types.h"
#include "utils.h"

namespace bpftrace {
namespace {
const std::vector<CXUnsavedFile> &getDefaultHeaders()
{
  static std::vector<CXUnsavedFile> unsaved_files = {
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
    {
        .Filename = "/bpftrace/include/" CLANG_WORKAROUNDS_H,
        .Contents = clang_workarounds_h,
        .Length = clang_workarounds_h_len,
    },
  };

  return unsaved_files;
}

std::vector<CXUnsavedFile> getTranslationUnitFiles(
    const CXUnsavedFile &main_file)
{
  std::vector<CXUnsavedFile> files;
  files.reserve(1 + files.size());

  files.emplace_back(main_file);
  const auto &dfl = getDefaultHeaders();
  files.insert(files.end(), dfl.cbegin(), dfl.cend());

  return files;
}
} // namespace

static std::string get_clang_string(CXString string)
{
  std::string str = clang_getCString(string);
  clang_disposeString(string);
  return str;
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

// @returns true on success, false otherwise
static bool getBitfield(CXCursor c, Bitfield &bitfield)
{
  if (!clang_Cursor_isBitField(c)) {
    return false;
  }

  // Algorithm description:
  // To handle bitfields, we need to give codegen 3 additional pieces
  // of information: `read_bytes`, `access_rshift`, and `mask`.
  //
  // `read_bytes` tells codegen how many bytes to read starting at `Field::offset`.
  // This information is necessary because we can't always issue, for example, a
  // 1 byte read, as the bitfield could be the last 4 bits of the struct. Reading
  // past the end of the struct could cause a page fault. Therefore, we compute the
  // minimum number of bytes necessary to fully read the bitfield. This will always
  // keep the read within the bounds of the struct.
  //
  // `access_rshift` tells codegen how much to shift the masked value so that the
  // LSB of the bitfield is the LSB of the interpreted integer.
  //
  // `mask` tells codegen how to mask out the surrounding bitfields.

  size_t bitfield_offset = clang_Cursor_getOffsetOfField(c) % 8;
  size_t bitfield_bitwidth = clang_getFieldDeclBitWidth(c);

  bitfield.mask = (1 << bitfield_bitwidth) - 1;
  bitfield.access_rshift = bitfield_offset;
  // Round up to nearest byte
  bitfield.read_bytes = (bitfield_offset + bitfield_bitwidth + 7) / 8;

  return true;
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
    clang_disposeString(tokenText);
  }
  clang_disposeTokens(transUnit, tokens, numTokens);
  return value.length() != 0;
}

static std::string remove_qualifiers(std::string &&typestr)
{
  // libclang prints "const" keyword first
  // https://github.com/llvm-mirror/clang/blob/65acf43270ea2894dffa0d0b292b92402f80c8cb/lib/AST/TypePrinter.cpp#L137-L157
  static std::regex re("^(const volatile\\s+)|^(const\\s+)|"
                       "^(volatile\\s+)|\\*(\\s*restrict)$");
  return std::regex_replace(typestr, re, "");
}

static std::string get_unqualified_type_name(CXType clang_type)
{
  return remove_qualifiers(get_clang_string(clang_getTypeSpelling(clang_type)));
}

static SizedType get_sized_type(CXType clang_type)
{
  auto size = 8 * clang_Type_getSizeOf(clang_type);
  auto typestr = get_unqualified_type_name(clang_type);

  switch (clang_type.kind)
  {
    case CXType_Bool:
    case CXType_Char_U:
    case CXType_UChar:
    case CXType_UShort:
    case CXType_UInt:
    case CXType_ULong:
    case CXType_ULongLong:
      return CreateUInt(size);
    case CXType_Record:
      return CreateRecord(size / 8, typestr);
    case CXType_Char_S:
    case CXType_SChar:
    case CXType_Short:
    case CXType_Long:
    case CXType_LongLong:
    case CXType_Int:
      return CreateInt(size);
    case CXType_Enum:
      return CreateUInt(size);
    case CXType_Pointer:
    {
      auto pointee_type = clang_getPointeeType(clang_type);
      return CreatePointer(get_sized_type(pointee_type));
    }
    case CXType_ConstantArray:
    {
      auto elem_type = clang_getArrayElementType(clang_type);
      auto size = clang_getNumElements(clang_type);
      if (elem_type.kind == CXType_Char_S || elem_type.kind == CXType_Char_U)
      {
        return CreateString(size);
      }

      // Only support one-dimensional arrays for now
      if (elem_type.kind != CXType_ConstantArray)
      {
        auto elem_stype = get_sized_type(elem_type);
        return CreateArray(size, elem_stype);
      } else {
        return CreateNone();
      }
    }
    default:
      return CreateNone();
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

bool ClangParser::ClangParserHandler::check_diagnostics(
    const std::string &input,
    std::vector<std::string> &error_msgs,
    bool bail_on_error)
{
  for (unsigned int i=0; i < clang_getNumDiagnostics(get_translation_unit()); i++) {
    CXDiagnostic diag = clang_getDiagnostic(get_translation_unit(), i);
    CXDiagnosticSeverity severity = clang_getDiagnosticSeverity(diag);
    std::string msg = clang_getCString(clang_getDiagnosticSpelling(diag));
    error_msgs.push_back(msg);

    if ((bail_on_error && severity == CXDiagnostic_Error) ||
        severity == CXDiagnostic_Fatal)
    {
      // Do not fail on "too many errors"
      if (!bail_on_error && msg == "too many errors emitted, stopping now")
        return true;
      if (bt_debug >= DebugLevel::kDebug)
        LOG(ERROR) << "Input (" << input.size() << "): " << input;
      return false;
    }
  }
  return true;
}

CXCursor ClangParser::ClangParserHandler::get_translation_unit_cursor() {
  return clang_getTranslationUnitCursor(translation_unit);
}

namespace {
// Get annotation associated with field declaration `c`
std::optional<std::string> get_field_decl_annotation(CXCursor c)
{
  assert(clang_getCursorKind(c) == CXCursor_FieldDecl);

  std::optional<std::string> annotation;
  clang_visitChildren(c,
                      [](CXCursor c,
                         CXCursor __attribute__((unused)) parent,
                         CXClientData data) {
                        // The header generation code can annotate some struct
                        // fields with additional information for us to parse
                        // here. The annotation looks like:
                        //
                        //    struct Foo {
                        //      __attribute__((annotate("tp_data_loc"))) int
                        //      name;
                        //    };
                        //
                        // Currently only the TracepointFormatParser does this.
                        if (clang_getCursorKind(c) == CXCursor_AnnotateAttr)
                        {
                          auto &a = *static_cast<std::optional<std::string> *>(
                              data);
                          a = get_clang_string(clang_getCursorSpelling(c));
                        }

                        return CXChildVisit_Recurse;
                      },
                      &annotation);

  return annotation;
}
} // namespace

bool ClangParser::visit_children(CXCursor &cursor, BPFtrace &bpftrace)
{
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
          auto ptypestr = get_unqualified_type_name(ptype);
          auto ptypesize = clang_Type_getSizeOf(ptype);

          auto ident = get_clang_string(clang_getCursorSpelling(c));
          auto offset = clang_Type_getOffsetOf(ptype, ident.c_str()) / 8;
          auto type = clang_getCanonicalType(clang_getCursorType(c));
          auto sized_type = get_sized_type(type);
          Bitfield bitfield;
          bool is_bitfield = getBitfield(c, bitfield);
          bool is_data_loc = false;

          // Process field annotations
          auto annotation = get_field_decl_annotation(c);
          if (annotation)
          {
            if (*annotation == "tp_data_loc")
            {
              // If the field is a tracepoint __data_loc, we need to rewrite the
              // type as a u64. The reason is that the tracepoint infrastructure
              // exports an encoded 32bit integer that tells us where to find
              // the actual data and how wide it is. However, LLVM freaks out if
              // you try to cast a pointer to a u32 (rightfully so) so we need
              // this field to actually be 64 bits wide.
              sized_type = CreateInt64();
              is_data_loc = true;
            }
          }

          // No need to worry about redefined types b/c we should have already
          // checked clang diagnostics. The diagnostics will tell us if we have
          // duplicated types.
          structs[ptypestr].fields[ident].offset = offset;
          structs[ptypestr].fields[ident].type = sized_type;
          structs[ptypestr].fields[ident].is_bitfield = is_bitfield;
          structs[ptypestr].fields[ident].bitfield = bitfield;
          structs[ptypestr].fields[ident].is_data_loc = is_data_loc;
          structs[ptypestr].size = ptypesize;
        }

        return CXChildVisit_Recurse;
      },
      &bpftrace);

  // clang_visitChildren returns a non-zero value if the traversal
  // was terminated by the visitor returning CXChildVisit_Break.
  return err == 0;
}

std::unordered_set<std::string> ClangParser::get_incomplete_types(
    const std::string &input,
    std::vector<CXUnsavedFile> &unsaved_files,
    const std::vector<const char *> &args,
    const std::unordered_set<std::string> &complete_types)
{
  if (input.empty())
    return {};

  ClangParserHandler handler;
  CXErrorCode error;
  {
    // No need to print warnings/errors twice. We will parse the input again
    // later.
    StderrSilencer silencer;
    silencer.silence();

    error = handler.parse_translation_unit(
        "definitions.h",
        args.data(),
        args.size(),
        unsaved_files.data(),
        unsaved_files.size(),
        CXTranslationUnit_DetailedPreprocessingRecord);
  }

  if (error)
  {
    if (bt_debug == DebugLevel::kFullDebug)
      LOG(ERROR)
          << "Clang error while parsing BTF dependencies in C definitions: "
          << error;

    // We don't need to worry about properly reporting an error here because
    // clang should fail again when we run the parser the second time.
    return {};
  }

  // Don't bail on errors (ie incomplete structs) because our goal is to
  // enumerate all such errors. Instead, collect error messages for later
  // analysis.
  std::vector<std::string> diag_msgs;
  if (!handler.check_diagnostics(input, diag_msgs, false))
    return {};

  struct TypeData
  {
    std::unordered_set<std::string> complete_types;
    std::unordered_set<std::string> incomplete_types;
  } type_data;
  // Initialize to already defined types
  type_data.complete_types = complete_types;

  // Search for error messages of the form:
  //   unknown type name 'type_t'
  // that imply an unresolved typedef of type_t. This cannot be done below in
  // clang_visitChildren since clang does not have the unknown type names.
  for (const auto &msg : diag_msgs)
  {
    auto unknown_type = get_unknown_type(msg);
    if (unknown_type)
      type_data.incomplete_types.emplace(unknown_type.value());
  }

  CXCursor cursor = handler.get_translation_unit_cursor();
  clang_visitChildren(
      cursor,
      [](CXCursor c, CXCursor parent, CXClientData client_data) {
        auto &data = *static_cast<TypeData *>(client_data);

        // We look for field declarations and store the parent
        // as a fully defined type because we know we're looking at a
        // type definition.
        //
        // Then look at the field declaration itself. If it's a record
        // type (ie struct or union), check if we think it's a fully
        // defined type. If not, add it to incomplete types set.
        if (clang_getCursorKind(parent) == CXCursor_EnumDecl ||
            (clang_getCursorKind(c) == CXCursor_FieldDecl &&
             (clang_getCursorKind(parent) == CXCursor_UnionDecl ||
              clang_getCursorKind(parent) == CXCursor_StructDecl)))
        {
          auto parent_type = clang_getCanonicalType(
              clang_getCursorType(parent));
          data.complete_types.emplace(get_unqualified_type_name(parent_type));

          auto cursor_type = clang_getCanonicalType(clang_getCursorType(c));
          // We need layouts of pointee types because users could dereference
          if (cursor_type.kind == CXType_Pointer)
            cursor_type = clang_getPointeeType(cursor_type);
          if (cursor_type.kind == CXType_Record)
          {
            auto type_name = get_unqualified_type_name(cursor_type);
            if (data.complete_types.find(type_name) ==
                data.complete_types.end())
              data.incomplete_types.emplace(std::move(type_name));
          }
        }

        return CXChildVisit_Recurse;
      },
      &type_data);

  return type_data.incomplete_types;
}

bool ClangParser::parse(ast::Program *program, BPFtrace &bpftrace, std::vector<std::string> extra_flags)
{
  auto input = "#include <__btf_generated_header.h>\n" + program->c_definitions;

  auto input_files = getTranslationUnitFiles(CXUnsavedFile{
      .Filename = "definitions.h",
      .Contents = input.c_str(),
      .Length = input.size(),
  });

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

  bool process_btf = program->c_definitions.empty() ||
                     (bpftrace.force_btf_ && bpftrace.btf_.has_data());

  // We set these args early because some systems may not have <linux/types.h>
  // (containers) and fully rely on BTF.
  if (process_btf)
  {
    // Prevent BTF generated header from redefining stuff found
    // in <linux/types.h>
    args.push_back("-D_LINUX_TYPES_H");
    // Since we're omitting <linux/types.h> there's no reason to
    // add the wokarounds for it
    args.push_back("-D__CLANG_WORKAROUNDS_H");
  }

  // The generated BTF header is initially empty
  std::string btf_cdef;
  input_files.emplace_back(CXUnsavedFile{
      .Filename = "/bpftrace/include/__btf_generated_header.h",
      .Contents = btf_cdef.c_str(),
      .Length = btf_cdef.size(),
  });

  ClangParserHandler handler;
  bool check_additional_types = true;
  while (check_additional_types && process_btf)
  {
    auto incomplete_types = get_incomplete_types(
        input, input_files, args, bpftrace.btf_set_);
    size_t types_cnt = bpftrace.btf_set_.size();
    bpftrace.btf_set_.insert(incomplete_types.cbegin(),
                             incomplete_types.cend());

    // Update generated header with current BTF types
    btf_cdef = bpftrace.btf_.c_def(bpftrace.btf_set_);
    input_files.back() = CXUnsavedFile{
      .Filename = "/bpftrace/include/__btf_generated_header.h",
      .Contents = btf_cdef.c_str(),
      .Length = btf_cdef.size(),
    };

    // If additional BTF types were found, we need to repeat the process since
    // that might have introduced some new unresolved typedefs.
    check_additional_types = types_cnt != bpftrace.btf_set_.size();
  }

  CXErrorCode error;
  error = handler.parse_translation_unit(
      "definitions.h",
      args.data(),
      args.size(),
      input_files.data(),
      input_files.size(),
      CXTranslationUnit_DetailedPreprocessingRecord);

  if (error)
  {
    if (bt_debug == DebugLevel::kFullDebug) {
      LOG(ERROR) << "Clang error while parsing C definitions: " << error
                 << "Input (" << input.size() << "): " << input;
    }
    return false;
  }

  std::vector<std::string> error_msgs;
  if (!handler.check_diagnostics(input, error_msgs, true))
  {
    for (auto &msg : error_msgs)
    {
      if (get_unknown_type(msg) != "" && !bpftrace.force_btf_)
      {
        LOG(ERROR) << "Try running with --btf to force BTF processing or "
                      "include headers with missing type definitions";
      }
    }
    return false;
  }

  CXCursor cursor = handler.get_translation_unit_cursor();
  return visit_children(cursor, bpftrace);
}

/*
 * Parse the given Clang diagnostics message and if it has the form:
 *   unknown type name 'type_t'
 * return type_t.
 */
std::optional<std::string> ClangParser::ClangParser::get_unknown_type(
    const std::string &diagnostic_msg)
{
  const std::string unknown_type_msg = "unknown type name \'";
  if (diagnostic_msg.find(unknown_type_msg) == 0)
  {
    return diagnostic_msg.substr(unknown_type_msg.length(),
                                 diagnostic_msg.length() -
                                     unknown_type_msg.length() - 1);
  }
  return {};
}

} // namespace bpftrace
