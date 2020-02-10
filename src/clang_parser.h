#pragma once

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
  bool parse_btf_definitions(BPFtrace &bpftrace);

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

    bool check_diagnostics(const std::string &input);

    CXCursor get_translation_unit_cursor();

  private:
    CXIndex index;
    CXTranslationUnit translation_unit;
  };
};

} // namespace bpftrace
