#pragma once

#include <clang-c/Index.h>
#include "bpftrace.h"

namespace bpftrace {

namespace ast { class Program; }

class ClangParser
{
public:
  bool parse(ast::Program *program, BPFtrace &bpftrace, std::vector<std::string> extra_flags = {});
private:
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

    CXCursor get_translation_unit_cursor();

  private:
    CXIndex index;
    CXTranslationUnit translation_unit;
  };
};

} // namespace bpftrace
