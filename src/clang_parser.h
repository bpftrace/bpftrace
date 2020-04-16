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
   * supplied by BTF data. This method will pull out any forward-declared /
   * incomplete struct definitions and return the types (in string form) of
   * the unresolved types.
   *
   * Note that this method does not report "errors". This is because the user
   * could have typo'd and actually referenced a non-existent type. Put
   * differently, this method is best effort.
   */
  std::unordered_set<std::string> get_incomplete_types(
      const std::string &input,
      std::vector<CXUnsavedFile> &unsaved_files,
      const std::vector<const char *> &args);

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

    bool check_diagnostics(const std::string &input, bool bail_on_error = true);

    CXCursor get_translation_unit_cursor();

  private:
    CXIndex index;
    CXTranslationUnit translation_unit;
  };
};

} // namespace bpftrace
