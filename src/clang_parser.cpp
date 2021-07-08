#include <cstring>
#include <iostream>
#include <regex>
#include <vector>

#include "llvm/Config/llvm-config.h"

#include "ast/ast.h"
#include "ast/field_analyser.h"
#include "btf.h"
#include "clang_parser.h"
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
  size_t bitfield_bitdidth_max = sizeof(uint64_t) * 8;

  if (bitfield_bitwidth > bitfield_bitdidth_max)
  {
    LOG(WARNING) << "bitfiled bitwidth " << bitfield_bitwidth
                 << "is not supporeted."
                 << " Use bitwidth " << bitfield_bitdidth_max;
    bitfield_bitwidth = bitfield_bitdidth_max;
  }
  if (bitfield_bitwidth == bitfield_bitdidth_max)
    bitfield.mask = std::numeric_limits<uint64_t>::max();
  else
    bitfield.mask = (1ULL << bitfield_bitwidth) - 1;
  // Round up to nearest byte
  bitfield.read_bytes = (bitfield_offset + bitfield_bitwidth + 7) / 8;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  bitfield.access_rshift = bitfield_offset;
#else
  bitfield.access_rshift = (bitfield.read_bytes * 8 - bitfield_offset -
                            bitfield_bitwidth);
#endif

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

static SizedType get_sized_type(CXType clang_type, StructManager &structs)
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
    case CXType_Record: {
      // Struct map entry may not exist for forward declared types so we create
      // it now and fill it later
      auto s = structs.LookupOrAdd(typestr, size / 8);
      return CreateRecord(typestr, s);
    }
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
      return CreatePointer(get_sized_type(pointee_type, structs));
    }
    case CXType_ConstantArray:
    {
      auto elem_type = clang_getArrayElementType(clang_type);
      auto size = clang_getNumElements(clang_type);
      if (elem_type.kind == CXType_Char_S || elem_type.kind == CXType_Char_U)
      {
        return CreateString(size);
      }

      auto elem_stype = get_sized_type(elem_type, structs);
      return CreateArray(size, elem_stype);
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
  // Clean up previous translation unit to prevent resource leak
  clang_disposeTranslationUnit(translation_unit);

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

bool ClangParser::ClangParserHandler::parse_file(
    const std::string &filename,
    const std::string &input,
    const std::vector<const char *> &args,
    std::vector<CXUnsavedFile> &unsaved_files,
    bool bail_on_errors)
{
  StderrSilencer silencer;
  if (!bail_on_errors)
    silencer.silence();

  CXErrorCode error = parse_translation_unit(
      filename.c_str(),
      args.data(),
      args.size(),
      unsaved_files.data(),
      unsaved_files.size(),
      CXTranslationUnit_DetailedPreprocessingRecord);

  error_msgs.clear();
  if (error)
  {
    if (bt_debug == DebugLevel::kFullDebug)
      LOG(ERROR) << "Clang error while parsing C definitions: " << error;
    return false;
  }

  return check_diagnostics(input, bail_on_errors);
}

const std::vector<std::string>
    &ClangParser::ClangParserHandler::get_error_messages()
{
  return error_msgs;
}

bool ClangParser::ClangParserHandler::has_redefinition_error()
{
  for (auto &msg : error_msgs)
  {
    if (msg.find("redefinition") != std::string::npos)
      return true;
  }
  return false;
}

bool ClangParser::ClangParserHandler::has_unknown_type_error()
{
  for (auto &msg : error_msgs)
  {
    if (ClangParser::get_unknown_type(msg).has_value())
      return true;
  }
  return false;
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
          auto &structs = static_cast<BPFtrace *>(client_data)->structs;

          auto named_parent = get_named_parent(c);
          auto ptype = clang_getCanonicalType(clang_getCursorType(named_parent));
          auto ptypestr = get_unqualified_type_name(ptype);
          auto ptypesize = clang_Type_getSizeOf(ptype);

          auto ident = get_clang_string(clang_getCursorSpelling(c));
          auto offset = clang_Type_getOffsetOf(ptype, ident.c_str()) / 8;
          auto type = clang_getCanonicalType(clang_getCursorType(c));
          auto sized_type = get_sized_type(type, structs);
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

          // Initialize a new record type if needed
          if (!structs.Has(ptypestr))
            structs.Add(ptypestr, ptypesize);

          // No need to worry about redefined types b/c we should have already
          // checked clang diagnostics. The diagnostics will tell us if we have
          // duplicated types.
          structs.Lookup(ptypestr).lock()->AddField(
              ident, sized_type, offset, is_bitfield, bitfield, is_data_loc);
        }

        return CXChildVisit_Recurse;
      },
      &bpftrace);

  // clang_visitChildren returns a non-zero value if the traversal
  // was terminated by the visitor returning CXChildVisit_Break.
  return err == 0;
}

std::unordered_set<std::string> ClangParser::get_incomplete_types()
{
  if (input.empty())
    return {};

  // Parse without failing on compilation errors (ie incomplete structs) because
  // our goal is to enumerate all such errors.
  ClangParserHandler handler;
  if (!handler.parse_file("definitions.h", input, args, input_files, false))
    return {};

  struct TypeData
  {
    std::unordered_set<std::string> complete_types;
    std::unordered_set<std::string> incomplete_types;
  } type_data;

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

void ClangParser::resolve_incomplete_types_from_btf(
    BPFtrace &bpftrace,
    const ast::ProbeList *probes)
{
  // Resolution of incomplete types must run at least once, maximum should be
  // the number of levels of nested field accesses for tracepoint args.
  // The maximum number of iterations can be also controlled by the
  // BPFTRACE_MAX_TYPE_RES_ITERATIONS env variable (0 is unlimited).
  uint64_t field_lvl = 1;
  for (auto &probe : *probes)
    if (probe->tp_args_structs_level > (int)field_lvl)
      field_lvl = probe->tp_args_structs_level;

  unsigned max_iterations = std::max(bpftrace.max_type_res_iterations,
                                     field_lvl);

  bool check_incomplete_types = true;
  for (unsigned i = 0; i < max_iterations && check_incomplete_types; i++)
  {
    // Collect incomplete types and retrieve their definitions from BTF.
    auto incomplete_types = get_incomplete_types();
    size_t types_cnt = bpftrace.btf_set_.size();
    bpftrace.btf_set_.insert(incomplete_types.cbegin(),
                             incomplete_types.cend());

    input_files.back() = get_btf_generated_header(bpftrace);

    // No need to continue if no more types were added
    check_incomplete_types = types_cnt != bpftrace.btf_set_.size();
  }
}

/*
 * Parse the program using Clang.
 *
 * Type resolution rules:
 *
 * If BTF is available, necessary types are retrieved from there, otherwise we
 * rely on headers and types supplied by the user (we also include linux/types.h
 * in some cases, e.g., for tracepoints).
 *
 * The following types are taken from BTF (if available):
 * 1. Types explicitly used in the program (taken from bpftrace.btf_set_).
 * 2. Types used by some of the defined types (as struct members). This step
 *    is done recursively, however, as it may take long time, there is a
 *    maximal depth set. It is computed as the maximum level of nested field
 *    accesses in the program and can be manually overridden using
 *    the BPFTRACE_MAX_TYPE_RES_ITERATIONS env variable.
 * 3. Typedefs used by some of the defined types. These are also resolved
 *    recursively, however, they must be resolved completely as any unknown
 *    typedef will cause the parser to fail (even if the type is not used in
 *    the program).
 *
 * If any of the above steps retrieves a definition that redefines some existing
 * (user-defined) type, no BTF types are used and all types must be provided.
 * In practice, this means that user may use kernel types without providing
 * their definitions but once he redefines any kernel type, he must provide all
 * necessary definitions.
 */
bool ClangParser::parse(ast::Program *program, BPFtrace &bpftrace, std::vector<std::string> extra_flags)
{
#ifdef FUZZ
  StderrSilencer silencer;
  silencer.silence();
#endif
  input = "#include <__btf_generated_header.h>\n" + program->c_definitions;

  input_files = getTranslationUnitFiles(CXUnsavedFile{
      .Filename = "definitions.h",
      .Contents = input.c_str(),
      .Length = input.size(),
  });

  // clang-format off
  args = {
    "-isystem", "/usr/local/include",
    "-isystem", "/bpftrace/include",
    "-isystem", "/usr/include",
  };
  // clang-format on
  for (auto &flag : extra_flags)
  {
    args.push_back(flag.c_str());
  }

  // Push the generated BTF header into input files.
  // The header must be the last file in the vector since the following methods
  // count on it.
  // If BTF is not available, the header is empty.
  input_files.emplace_back(bpftrace.btf_.has_data()
                               ? get_btf_generated_header(bpftrace)
                               : get_empty_btf_generated_header());

  bool btf_conflict = false;
  ClangParserHandler handler;
  if (bpftrace.btf_.has_data())
  {
    // We set these args early because some systems may not have <linux/types.h>
    // (containers) and fully rely on BTF.

    // Prevent BTF generated header from redefining stuff found
    // in <linux/types.h>
    args.push_back("-D_LINUX_TYPES_H");
    // Since we're omitting <linux/types.h> there's no reason to
    // add the wokarounds for it
    args.push_back("-D__CLANG_WORKAROUNDS_H");

    if (handler.parse_file("definitions.h", input, args, input_files, false) &&
        handler.has_redefinition_error())
      btf_conflict = true;

    if (!btf_conflict)
    {
      resolve_incomplete_types_from_btf(bpftrace, program->probes);

      if (handler.parse_file(
              "definitions.h", input, args, input_files, false) &&
          handler.has_redefinition_error())
        btf_conflict = true;
    }

    if (!btf_conflict)
    {
      resolve_unknown_typedefs_from_btf(bpftrace);

      if (handler.parse_file(
              "definitions.h", input, args, input_files, false) &&
          handler.has_redefinition_error())
        btf_conflict = true;
    }
  }

  if (btf_conflict)
  {
    // There is a conflict (redefinition) between user-supplied types and types
    // taken from BTF. We cannot use BTF in such a case.
    args.pop_back();
    args.pop_back();
    input_files.back() = get_empty_btf_generated_header();
  }

  if (!handler.parse_file("definitions.h", input, args, input_files))
  {
    if (handler.has_redefinition_error())
    {
      LOG(WARNING) << "Cannot take type definitions from BTF since there is "
                      "a redefinition conflict with user-defined types.";
    }
    else if (handler.has_unknown_type_error())
    {
      LOG(ERROR) << "Include headers with missing type definitions or install "
                    "BTF information to your system.";
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

std::unordered_set<std::string> ClangParser::get_unknown_typedefs()
{
  // Parse without failing on compilation errors (ie unknown types) because
  // our goal is to enumerate and analyse all such errors
  ClangParserHandler handler;
  if (!handler.parse_file("definitions.h", input, args, input_files, false))
    return {};

  std::unordered_set<std::string> unknown_typedefs;
  // Search for error messages of the form:
  //   unknown type name 'type_t'
  // that imply an unresolved typedef of type_t. This cannot be done in
  // clang_visitChildren since clang does not have the unknown type names.
  for (const auto &msg : handler.get_error_messages())
  {
    auto unknown_type = get_unknown_type(msg);
    if (unknown_type)
      unknown_typedefs.emplace(unknown_type.value());
  }
  return unknown_typedefs;
}

void ClangParser::resolve_unknown_typedefs_from_btf(BPFtrace &bpftrace)
{
  bool check_unknown_types = true;
  while (check_unknown_types)
  {
    // Collect unknown typedefs and retrieve their definitions from BTF.
    // These must be resolved completely since any unknown typedef will cause
    // the parser to fail (even if that type is not used in the program).
    auto incomplete_types = get_unknown_typedefs();
    size_t types_cnt = bpftrace.btf_set_.size();
    bpftrace.btf_set_.insert(incomplete_types.cbegin(),
                             incomplete_types.cend());

    input_files.back() = get_btf_generated_header(bpftrace);

    // No need to continue if no more types were added
    check_unknown_types = types_cnt != bpftrace.btf_set_.size();
  }
}

CXUnsavedFile ClangParser::get_btf_generated_header(BPFtrace &bpftrace)
{
  btf_cdef = bpftrace.btf_.c_def(bpftrace.btf_set_);
  return CXUnsavedFile{
    .Filename = "/bpftrace/include/__btf_generated_header.h",
    .Contents = btf_cdef.c_str(),
    .Length = btf_cdef.size(),
  };
}

CXUnsavedFile ClangParser::get_empty_btf_generated_header()
{
  btf_cdef = "";
  return CXUnsavedFile{
    .Filename = "/bpftrace/include/__btf_generated_header.h",
    .Contents = btf_cdef.c_str(),
    .Length = btf_cdef.size(),
  };
}

} // namespace bpftrace
