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
   * supplied by BTF data. Also, some types may be defined by typedefs that are
   * in non-included headers, which causes problems to clang.
   *
   * This method will pull out any forward-declared / incomplete struct
   * and typedef definitions and return the types (in string form) of
   * the unresolved types.
   *
   * Note that this method does not report "errors". This is because the user
   * could have typo'd and actually referenced a non-existent type. Put
   * differently, this method is best effort.
   */
  std::unordered_set<std::string> get_incomplete_types(
      const std::string &input,
      std::vector<CXUnsavedFile> &unsaved_files,
      const std::vector<const char *> &args,
      const std::unordered_set<std::string> &complete_types);

  static std::optional<std::string> get_unknown_type(
      const std::string &diagnostic_msg);

  class ClangParserHandler
  {
  public:
    ClangParserHandler();

    ~ClangParserHandler();

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
    bool check_diagnostics(const std::string &input,
                           std::vector<std::string> &error_msgs,
                           bool bail_on_error);

    CXCursor get_translation_unit_cursor();

  private:
    CXIndex index;
    CXTranslationUnit translation_unit;
  };
};

} // namespace bpftrace
