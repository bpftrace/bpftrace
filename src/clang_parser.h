#pragma once

#include <unordered_set>

#include "bpftrace.h"
#include <clang-c/Index.h>

#define CLANG_WORKAROUNDS_H "clang_workarounds.h"

namespace bpftrace {

namespace ast {
class Program;
}

class ClangParser
{
public:
  bool parse(ast::Program *program,
             BPFtrace &bpftrace,
             std::vector<std::string> extra_flags = {});

private:
  bool visit_children(CXCursor &cursor, BPFtrace &bpftrace);
  /*
   * The user might have written some struct definitions that rely on types
   * supplied by BTF data.
   *
   * This method will pull out any forward-declared / incomplete struct
   * definitions and return the types (in string form) of the unresolved types.
   *
   * Note that this method does not report "errors". This is because the user
   * could have typo'd and actually referenced a non-existent type. Put
   * differently, this method is best effort.
   */
  std::unordered_set<std::string> get_incomplete_types();
  /*
   * Iteratively check for incomplete types, pull their definitions from BTF,
   * and update the input files with the definitions.
   */
  void resolve_incomplete_types_from_btf(BPFtrace &bpftrace,
                                         const ast::ProbeList *probes);

  /*
   * Collect names of types defined by typedefs that are in non-included
   * headers as they may pose problems for clang parser.
   */
  std::unordered_set<std::string> get_unknown_typedefs();
  /*
   * Iteratively check for unknown typedefs, pull their definitions from BTF,
   * and update the input files with the definitions.
   */
  void resolve_unknown_typedefs_from_btf(BPFtrace &bpftrace);

  static std::optional<std::string> get_unknown_type(
      const std::string &diagnostic_msg);

  CXUnsavedFile get_btf_generated_header(BPFtrace &bpftrace);
  CXUnsavedFile get_empty_btf_generated_header();

  std::string input;
  std::vector<const char *> args;
  std::vector<CXUnsavedFile> input_files;
  std::string btf_cdef;

  class ClangParserHandler
  {
  public:
    ClangParserHandler();

    ~ClangParserHandler();

    bool parse_file(const std::string &filename,
                    const std::string &input,
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

    /*
     * Check diagnostics and collect all error messages.
     * Return true if an error occurred. If bail_on_error is false, only fail
     * on fatal errors.
     */
    bool check_diagnostics(const std::string &input, bool bail_on_error);

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

} // namespace bpftrace
