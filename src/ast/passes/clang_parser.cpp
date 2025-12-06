#include <algorithm>
#include <clang-c/Index.h>
#include <clang/Driver/Driver.h>
#include <clang/Frontend/CompilerInstance.h>
#include <cstring>
#include <iostream>
#include <llvm/Config/llvm-config.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/VirtualFileSystem.h>
#include <regex>
#include <sstream>
#include <sys/utsname.h>
#include <unordered_set>
#include <utility>
#include <vector>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/resolve_imports.h"
#include "bpftrace.h"
#include "btf.h"
#include "clang_parser.h"
#include "log.h"
#include "stdlib/stdlib.h"
#include "types.h"
#include "util/io.h"
#include "util/strings.h"
#include "util/system.h"

namespace bpftrace::ast {

char ClangParseError::ID;

void ClangParseError::log(llvm::raw_ostream &OS) const
{
  OS << "Clang parse error";
}

class ClangParser {
public:
  bool parse(ast::Program *program,
             BPFtrace &bpftrace,
             std::vector<std::string> extra_flags = {});

  // Moved out by the pass.
  CDefinitions definitions;

private:
  bool visit_children(CXCursor &cursor, BPFtrace &bpftrace);
  // The user might have written some struct definitions that rely on types
  // supplied by BTF data.
  //
  // This method will pull out any forward-declared / incomplete struct
  // definitions and return the types (in string form) of the unresolved types.
  //
  // Note that this method does not report "errors". This is because the user
  // could have typo'd and actually referenced a non-existent type. Put
  // differently, this method is best effort.
  std::unordered_set<std::string> get_incomplete_types();
  // Iteratively check for incomplete types, pull their definitions from BTF,
  // and update the input files with the definitions.
  void resolve_incomplete_types_from_btf(BPFtrace &bpftrace);

  // Collect names of types defined by typedefs that are in non-included
  // headers as they may pose problems for clang parser.
  std::unordered_set<std::string> get_unknown_typedefs();
  // Iteratively check for unknown typedefs, pull their definitions from BTF,
  // and update the input files with the definitions.
  void resolve_unknown_typedefs_from_btf(BPFtrace &bpftrace);

  static std::optional<std::string> get_unknown_type(
      const std::string &diagnostic_msg);

  CXUnsavedFile get_btf_generated_header(BPFtrace &bpftrace);
  CXUnsavedFile get_empty_btf_generated_header();

  std::string get_arch_include_path();
  std::vector<std::string> system_include_paths();

  std::string input;
  std::vector<const char *> args;
  std::vector<CXUnsavedFile> input_files;
  std::string btf_cdef;

  class ClangParserHandler {
  public:
    ClangParserHandler();

    ~ClangParserHandler();

    bool parse_file(const std::string &filename,
                    const std::vector<const char *> &args,
                    std::vector<CXUnsavedFile> &unsaved_files,
                    bool bail_on_errors = true);

    CXTranslationUnit get_translation_unit();

    CXErrorCode parse_translation_unit(const char *source_filename,
                                       const char *const *command_line_args,
                                       int num_command_line_args,
                                       struct CXUnsavedFile *unsaved_files,
                                       unsigned num_unsaved_files,
                                       unsigned options);

    // Check diagnostics and collect all error messages.
    // Return true if an error occurred. If bail_on_error is false, only fail
    // on fatal errors.
    bool check_diagnostics(bool bail_on_error);

    CXCursor get_translation_unit_cursor();

    const std::vector<std::string> &get_error_messages();

    bool has_redefinition_error();
    bool has_unknown_type_error();

  private:
    CXIndex index;
    CXTranslationUnit translation_unit = nullptr;
    std::vector<std::string> error_msgs;
  };
};

namespace {
const std::vector<CXUnsavedFile> &getDefaultHeaders()
{
  // N.B. the `cached` value here hangs on to a vector of strings, as well as a
  // vector of `CXUnsavedFile` objects. Since the `CXUnsavedFile` objects need
  // a C-style string, this is a `.c_str()` that comes from one of the saved
  // names. It is important that these objects are kept alive, even if they are
  // not returned from this function.
  static auto cached = [] {
    std::vector<std::string> names;
    std::vector<CXUnsavedFile> unsaved_files;
    for (const auto &[name, view] : stdlib::Stdlib::files) {
      if (!name.ends_with(".h")) {
        continue; // Inlucde only headers.
      }
      const auto &n = names.emplace_back("/bpftrace/" + name);
      unsaved_files.push_back(CXUnsavedFile{
          .Filename = n.c_str(),
          .Contents = view.data(),
          .Length = view.length(),
      });
    }
    return std::make_pair(std::move(names), std::move(unsaved_files));
  }();
  return cached.second; // See above.
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

// get_named_parent
//
// Find the parent struct of the field pointed to by the cursor.
// Anonymous structs are skipped.
static CXCursor get_named_parent(CXCursor c)
{
  CXCursor parent = clang_getCursorSemanticParent(c);

  while (!clang_Cursor_isNull(parent) &&
         clang_Cursor_isAnonymousRecordDecl(parent)) {
    parent = clang_getCursorSemanticParent(parent);
  }

  return parent;
}

static std::optional<Bitfield> getBitfield(CXCursor c)
{
  if (!clang_Cursor_isBitField(c)) {
    return std::nullopt;
  }

  return Bitfield(clang_Cursor_getOffsetOfField(c) % 8,
                  clang_getFieldDeclBitWidth(c));
}

// NOTE(mmarchini): as suggested in
// http://clang-developers.42468.n3.nabble.com/Extracting-macro-information-using-libclang-the-C-Interface-to-Clang-td4042648.html#message4042666
static bool translateMacro(CXCursor cursor,
                           std::string &name,
                           std::string &value)
{
  CXToken *tokens = nullptr;
  unsigned numTokens = 0;
  CXTranslationUnit transUnit = clang_Cursor_getTranslationUnit(cursor);
  CXSourceRange srcRange = clang_getCursorExtent(cursor);
  clang_tokenize(transUnit, srcRange, &tokens, &numTokens);
  for (unsigned n = 0; n < numTokens; n++) {
    auto tokenText = clang_getTokenSpelling(transUnit, tokens[n]);
    if (n == 0) {
      value.clear();
      name = clang_getCString(tokenText);
    } else {
      CXTokenKind tokenKind = clang_getTokenKind(tokens[n]);
      if (tokenKind != CXToken_Comment) {
        const char *text = clang_getCString(tokenText);
        if (text)
          value += text;
      }
    }
    clang_disposeString(tokenText);
  }
  clang_disposeTokens(transUnit, tokens, numTokens);
  return !value.empty();
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

  switch (clang_type.kind) {
    case CXType_Bool:
    case CXType_Char_U:
    case CXType_UChar:
    case CXType_UShort:
    case CXType_UInt:
    case CXType_ULong:
    case CXType_ULongLong:
      return CreateUInt(size);
    case CXType_Record: {
      // Struct map entry may not exist for forward declared types so we
      // create it now and fill it later
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
    case CXType_Enum: {
      // The pretty printed type name contains `enum` prefix. That's not
      // helpful for us, so remove it. We have our own metadata.
      static std::regex re("enum ");
      auto enum_name = std::regex_replace(typestr, re, "");
      return CreateEnum(size, enum_name);
    }
    case CXType_Pointer: {
      auto pointee_type = clang_getPointeeType(clang_type);
      return CreatePointer(get_sized_type(pointee_type, structs));
    }
    case CXType_ConstantArray: {
      auto elem_type = clang_getArrayElementType(clang_type);
      auto size = clang_getNumElements(clang_type);
      if (elem_type.kind == CXType_Char_S || elem_type.kind == CXType_Char_U) {
        // See btf.cpp; we need to signal well-formedness.
        return CreateString(size + 1);
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

CXTranslationUnit ClangParser::ClangParserHandler::get_translation_unit()
{
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

  return clang_parseTranslationUnit2(index,
                                     source_filename,
                                     command_line_args,
                                     num_command_line_args,
                                     unsaved_files,
                                     num_unsaved_files,
                                     options,
                                     &translation_unit);
}

bool ClangParser::ClangParserHandler::check_diagnostics(bool bail_on_error)
{
  for (unsigned int i = 0; i < clang_getNumDiagnostics(get_translation_unit());
       i++) {
    CXDiagnostic diag = clang_getDiagnostic(get_translation_unit(), i);
    CXDiagnosticSeverity severity = clang_getDiagnosticSeverity(diag);

    CXString msg_str = clang_getDiagnosticSpelling(diag);
    auto &msg = error_msgs.emplace_back(clang_getCString(msg_str));
    clang_disposeString(msg_str);

    if ((bail_on_error && severity == CXDiagnostic_Error) ||
        severity == CXDiagnostic_Fatal) {
      // Do not fail on "too many errors"
      return !bail_on_error && msg == "too many errors emitted, stopping now";
    }
  }
  return true;
}

CXCursor ClangParser::ClangParserHandler::get_translation_unit_cursor()
{
  return clang_getTranslationUnitCursor(translation_unit);
}

bool ClangParser::ClangParserHandler::parse_file(
    const std::string &filename,
    const std::vector<const char *> &args,
    std::vector<CXUnsavedFile> &unsaved_files,
    bool bail_on_errors)
{
  util::StderrSilencer silencer;
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
  if (error) {
    LOG(V1) << "Clang error while parsing C definitions: " << error;
    return false;
  }

  return check_diagnostics(bail_on_errors);
}

const std::vector<std::string> &ClangParser::ClangParserHandler::
    get_error_messages()
{
  return error_msgs;
}

bool ClangParser::ClangParserHandler::has_redefinition_error()
{
  return std::ranges::any_of(error_msgs, [](const auto &msg) {
    return msg.find("redefinition") != std::string::npos;
  });
}

bool ClangParser::ClangParserHandler::has_unknown_type_error()
{
  return std::ranges::any_of(error_msgs, [](const auto &msg) {
    return ClangParser::get_unknown_type(msg).has_value();
  });
}

namespace {
using visitFn = std::function<CXChildVisitResult(CXCursor, CXCursor)>;
int visitChildren(CXCursor cursor, visitFn fn)
{
  return clang_visitChildren(
      cursor,
      [](CXCursor c, CXCursor parent, CXClientData data) {
        auto *cb = static_cast<visitFn *>(data);
        return (*cb)(c, parent);
      },
      static_cast<void *>(&fn));
}

} // namespace

bool ClangParser::visit_children(CXCursor &cursor, BPFtrace &bpftrace)
{
  int err = visitChildren(cursor, [&](CXCursor c, CXCursor parent) {
    if (clang_getCursorKind(c) == CXCursor_MacroDefinition) {
      std::string macro_name;
      std::string macro_value;
      if (translateMacro(c, macro_name, macro_value)) {
        definitions.macros[macro_name] = macro_value;
      }
      return CXChildVisit_Recurse;
    }

    // Each anon enum must have a unique ID otherwise two variants
    // with different names but same value will clobber each other
    // in enum_defs.
    static uint32_t anon_enum_count = 0;
    if (clang_getCursorKind(c) == CXCursor_EnumDecl)
      anon_enum_count++;

    if (clang_getCursorKind(parent) == CXCursor_EnumDecl) {
      // Store variant name to variant value
      auto enum_name = get_clang_string(clang_getCursorSpelling(parent));
      // Anonymous enums have empty string names in libclang <= 15
      if (enum_name.empty()) {
        std::ostringstream name;
        name << "enum <anon_" << anon_enum_count << ">";
        enum_name = name.str();
      }
      auto variant_name = get_clang_string(clang_getCursorSpelling(c));
      auto variant_value = clang_getEnumConstantDeclValue(c);
      definitions.enums[variant_name] = std::make_pair(variant_value,
                                                       enum_name);

      // Store enum name to variant value to variant name
      definitions.enum_defs[enum_name][variant_value] = variant_name;

      return CXChildVisit_Recurse;
    }

    if (clang_getCursorKind(parent) != CXCursor_StructDecl &&
        clang_getCursorKind(parent) != CXCursor_UnionDecl)
      return CXChildVisit_Recurse;

    if (clang_getCursorKind(c) == CXCursor_FieldDecl) {
      // N.B. In the future this may be moved into the C definitions, but
      // currently this is rather tied in to a lot of other plumbing.
      auto &structs = bpftrace.structs;

      auto named_parent = get_named_parent(c);
      auto ptype = clang_getCanonicalType(clang_getCursorType(named_parent));
      auto ptypestr = get_unqualified_type_name(ptype);
      auto ptypesize = clang_Type_getSizeOf(ptype);

      auto ident = get_clang_string(clang_getCursorSpelling(c));
      auto offset = clang_Type_getOffsetOf(ptype, ident.c_str()) / 8;
      auto type = clang_getCanonicalType(clang_getCursorType(c));
      auto sized_type = get_sized_type(type, structs);
      auto bitfield = getBitfield(c);

      // Initialize a new record type if needed
      if (!structs.Has(ptypestr))
        structs.Add(ptypestr, ptypesize, false);

      auto str = structs.Lookup(ptypestr).lock();
      if (str->allow_override) {
        str->ClearFields();
        str->allow_override = false;
      }

      // No need to worry about redefined types b/c we should have already
      // checked clang diagnostics. The diagnostics will tell us if we have
      // duplicated types.
      str->AddField(ident, sized_type, offset, bitfield);
    }

    return CXChildVisit_Recurse;
  });

  // clang_visitChildren returns a non-zero value if the traversal
  // was terminated by the visitor returning CXChildVisit_Break.
  return err == 0;
}

std::unordered_set<std::string> ClangParser::get_incomplete_types()
{
  if (input.empty())
    return {};

  // Parse without failing on compilation errors (ie incomplete structs)
  // because our goal is to enumerate all such errors.
  ClangParserHandler handler;
  if (!handler.parse_file("definitions.h", args, input_files, false))
    return {};

  struct TypeData {
    std::unordered_set<std::string> complete_types;
    std::unordered_set<std::string> incomplete_types;
  } type_data;

  CXCursor cursor = handler.get_translation_unit_cursor();
  visitChildren(cursor, [&](CXCursor c, CXCursor parent) {
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
          clang_getCursorKind(parent) == CXCursor_StructDecl))) {
      auto parent_type = clang_getCanonicalType(clang_getCursorType(parent));
      type_data.complete_types.emplace(get_unqualified_type_name(parent_type));

      auto cursor_type = clang_getCanonicalType(clang_getCursorType(c));
      // We need layouts of pointee types because users could dereference
      if (cursor_type.kind == CXType_Pointer)
        cursor_type = clang_getPointeeType(cursor_type);
      if (cursor_type.kind == CXType_Record ||
          cursor_type.kind == CXType_Enum) {
        auto type_name = get_unqualified_type_name(cursor_type);
        if (!type_data.complete_types.contains(type_name))
          type_data.incomplete_types.emplace(std::move(type_name));
      }
    }

    return CXChildVisit_Recurse;
  });

  return type_data.incomplete_types;
}

void ClangParser::resolve_incomplete_types_from_btf(BPFtrace &bpftrace)
{
  std::unordered_set<std::string> last_incomplete;
  while (true) {
    // Collect incomplete types and retrieve their definitions from BTF.
    auto incomplete_types = get_incomplete_types();

    // No need to continue if nothing is incomplete.
    if (incomplete_types.empty()) {
      break;
    }
    // It is an error to attempt to continue if we've converge on a set of
    // incomplete types which is not changing.
    if (incomplete_types == last_incomplete) {
      break;
    }

    bpftrace.btf_set_.insert(incomplete_types.cbegin(),
                             incomplete_types.cend());
    input_files.back() = get_btf_generated_header(bpftrace);
    last_incomplete = std::move(incomplete_types);
  }
}

// Parse the program using Clang.
//
// Type resolution rules:
//
// If BTF is available, necessary types are retrieved from there, otherwise we
// rely on headers and types supplied by the user (we also include
// linux/types.h in some cases, e.., for tracepoints).
//
// The following types are taken from BTF (if available):
// 1. Types explicitly used in the program (taken from bpftrace.btf_set_).
// 2. Types used by some of the defined types (as struct members). This step
//    is done recursively, however, as it may take long time, there is a
//    maximal depth set. It is computed as the maximum level of nested field
//    accesses in the program and can be manually overridden using
//    the BPFTRACE_MAX_TYPE_RES_ITERATIONS env variable.
// 3. Typedefs used by some of the defined types. These are also resolved
//    recursively, however, they must be resolved completely as any unknown
//    typedef will cause the parser to fail (even if the type is not used in
//    the program).
//
// If any of the above steps retrieves a definition that redefines some
// existing (user-defined) type, no BTF types are used and all types must be
// provided. In practice, this means that user may use kernel types without
// providing their definitions but once he redefines any kernel type, he must
// provide all necessary definitions.
bool ClangParser::parse(ast::Program *program,
                        BPFtrace &bpftrace,
                        std::vector<std::string> extra_flags)
{
  std::stringstream ss;
  ss << "#include </bpftrace/include/__btf_generated_header.h>\n";
  for (const auto &stmt : program->c_statements) {
    ss << stmt->data << "\n";
  }

  input = ss.str();
  input_files = getTranslationUnitFiles(CXUnsavedFile{
      .Filename = "definitions.h",
      .Contents = input.c_str(),
      .Length = input.size(),
  });

  args = { "-isystem", "/bpftrace/include" };
  auto system_paths = system_include_paths();
  for (auto &path : system_paths) {
    args.push_back("-isystem");
    args.push_back(path.c_str());
  }
  std::string arch_path = get_arch_include_path();
  args.push_back("-isystem");
  args.push_back(arch_path.c_str());

  for (auto &flag : extra_flags) {
    args.push_back(flag.c_str());
  }

  // Push the generated BTF header into input files.
  // The header must be the last file in the vector since the following
  // methods count on it. If BTF is not available, the header is empty.
  input_files.emplace_back(bpftrace.has_btf_data()
                               ? get_btf_generated_header(bpftrace)
                               : get_empty_btf_generated_header());

  bool btf_conflict = false;
  ClangParserHandler handler;
  if (bpftrace.has_btf_data()) {
    // We set these args early because some systems may not have
    // <linux/types.h> (containers) and fully rely on BTF.

    // Prevent BTF generated header from redefining stuff found
    // in <linux/types.h>
    args.push_back("-D_LINUX_TYPES_H");
    // Let script know we have BTF -- this is useful for prewritten tools to
    // conditionally include headers if BTF isn't available.
    args.push_back("-DBPFTRACE_HAVE_BTF");

    if (handler.parse_file("definitions.h", args, input_files, false) &&
        handler.has_redefinition_error())
      btf_conflict = true;

    if (!btf_conflict) {
      resolve_incomplete_types_from_btf(bpftrace);

      if (handler.parse_file("definitions.h", args, input_files, false) &&
          handler.has_redefinition_error())
        btf_conflict = true;
    }

    if (!btf_conflict) {
      resolve_unknown_typedefs_from_btf(bpftrace);

      if (handler.parse_file("definitions.h", args, input_files, false) &&
          handler.has_redefinition_error())
        btf_conflict = true;
    }
  }

  if (btf_conflict) {
    // There is a conflict (redefinition) between user-supplied types and
    // types taken from BTF. We cannot use BTF in such a case.
    args.pop_back();
    args.pop_back();
    input_files.back() = get_empty_btf_generated_header();
  }

  if (!handler.parse_file("definitions.h", args, input_files)) {
    if (handler.has_redefinition_error()) {
      LOG(WARNING) << "Cannot take type definitions from BTF since there is "
                      "a redefinition conflict with user-defined types.";
    } else if (handler.has_unknown_type_error()) {
      LOG(ERROR) << "Include headers with missing type definitions or install "
                    "BTF information to your system.";
      if (bpftrace.btf_->objects_cnt() > 2) {
        LOG(WARNING)
            << "Trying to dump BTF from multiple kernel modules at once. "
            << "This is currently not possible, use probes from a single "
               "module"
            << " (and/or vmlinux) only.";
      }
    }
    return false;
  }

  CXCursor cursor = handler.get_translation_unit_cursor();
  return visit_children(cursor, bpftrace);
}

// Parse the given Clang diagnostics message and if it has one of the forms:
//   unknown type name 'type_t'
//   use of undeclared identifier 'type_t'
// return type_t.
std::optional<std::string> ClangParser::ClangParser::get_unknown_type(
    const std::string &diagnostic_msg)
{
  const std::vector<std::string> unknown_type_msgs = {
    "unknown type name \'", "use of undeclared identifier \'"
  };
  for (const auto &unknown_type_msg : unknown_type_msgs) {
    if (diagnostic_msg.starts_with(unknown_type_msg)) {
      return diagnostic_msg.substr(unknown_type_msg.length(),
                                   diagnostic_msg.length() -
                                       unknown_type_msg.length() - 1);
    }
  }
  return {};
}

std::unordered_set<std::string> ClangParser::get_unknown_typedefs()
{
  // Parse without failing on compilation errors (ie unknown types) because
  // our goal is to enumerate and analyse all such errors
  ClangParserHandler handler;
  if (!handler.parse_file("definitions.h", args, input_files, false))
    return {};

  std::unordered_set<std::string> unknown_typedefs;
  // Search for error messages of the form:
  //   unknown type name 'type_t'
  // that imply an unresolved typedef of type_t. This cannot be done in
  // clang_visitChildren since clang does not have the unknown type names.
  for (const auto &msg : handler.get_error_messages()) {
    auto unknown_type = get_unknown_type(msg);
    if (unknown_type)
      unknown_typedefs.emplace(unknown_type.value());
  }
  return unknown_typedefs;
}

void ClangParser::resolve_unknown_typedefs_from_btf(BPFtrace &bpftrace)
{
  bool check_unknown_types = true;
  while (check_unknown_types) {
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
  // Note that `c_def` will provide the full set of types if an empty set is
  // used here. We only want the types in `btf_set_` or nothing at all, so
  // don't generate anything if this set is empty.
  if (!bpftrace.btf_set_.empty()) {
    btf_cdef = bpftrace.btf_->c_def(bpftrace.btf_set_);
  }
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

std::string ClangParser::get_arch_include_path()
{
  struct utsname utsname;
  uname(&utsname);
  return "/usr/include/" + std::string(utsname.machine) + "-linux-gnu";
}

static void query_clang_include_dirs(std::vector<std::string> &result)
{
  std::vector<std::string> args;
  args.emplace_back("clang-" + std::to_string(LLVM_VERSION_MAJOR));
  args.emplace_back("-Wp,-v");
  args.emplace_back("-x");
  args.emplace_back("c");
  args.emplace_back("-fsyntax-only");
  args.emplace_back("/dev/null");
  auto check = util::exec_system(args);
  if (!check) {
    // Exec failed, ignore and move on.
    return;
  }
  std::istringstream lines(*check);
  std::string line;
  while (std::getline(lines, line) &&
         line != "#include <...> search starts here:") {
  }
  while (std::getline(lines, line) && line != "End of search list.")
    result.push_back(util::trim(line));
}

std::vector<std::string> ClangParser::system_include_paths()
{
  std::vector<std::string> result;
  std::istringstream lines(SYSTEM_INCLUDE_PATHS);
  std::string line;
  while (std::getline(lines, line, ':')) {
    if (line == "auto")
      query_clang_include_dirs(result);
    else
      result.push_back(util::trim(line));
  }

  if (result.empty())
    result = { "/usr/local/include", "/usr/include" };

  return result;
}

ast::Pass CreateClangParsePass(std::vector<std::string> &&extra_flags)
{
  return ast::Pass::create("ClangParser",
                           [extra_flags = std::move(extra_flags)](
                               ast::ASTContext &ast,
                               BPFtrace &b) -> Result<CDefinitions> {
                             ClangParser parser;
                             if (!parser.parse(ast.root, b, extra_flags)) {
                               return make_error<ClangParseError>();
                             }
                             return std::move(parser.definitions);
                           });
}

} // namespace bpftrace::ast
