#include <iostream>

#include "ast/attachpoint_parser.h"
#include "driver.h"
#include "log.h"
#include "parser.tab.hh"

struct yy_buffer_state;

extern struct yy_buffer_state *yy_scan_string(const char *yy_str,
                                              yyscan_t yyscanner);
extern int yylex_init(yyscan_t *scanner);
extern int yylex_destroy(yyscan_t yyscanner);
extern bpftrace::location loc;

namespace bpftrace {

void Driver::parse()
{
  // Reset source location info on every pass.
  loc.initialize();

  yyscan_t scanner;
  yylex_init(&scanner);
  Parser parser(*this, scanner);
  if (debug) {
    parser.set_debug_level(1);
  }
  yy_scan_string(ctx.source_->contents.c_str(), scanner);
  parser.parse();
  yylex_destroy(scanner);
}

void Driver::error(const location &l, const std::string &m)
{
  // This path is normally not allowed, however we don't yet have nodes
  // constructed. Therefore, we add diagnostics directly via the private field.
  ctx.diagnostics_->addError(l) << m;
}

} // namespace bpftrace
