#include <iostream>

#include "driver.h"

extern FILE *yyin;
extern void *yy_scan_string(const char *yy_str, yyscan_t yyscanner);
extern void yyset_in(FILE *_in_str, yyscan_t yyscanner);
extern int yylex_init(yyscan_t *scanner);
extern int yylex_destroy (yyscan_t yyscanner);
extern bpftrace::location loc;

namespace bpftrace {

Driver::Driver(BPFtrace &bpftrace, std::ostream &o) : bpftrace_(bpftrace), out_(o)
{
  ast::Expression::getResolve().clear();
  yylex_init(&scanner_);
  parser_ = std::make_unique<Parser>(*this, scanner_);
}

Driver::~Driver()
{
  yylex_destroy(scanner_);
}

int Driver::parse_stdin()
{
  return parser_->parse();
}

void Driver::source(std::string filename, std::string script)
{
  bpftrace_.source(filename, script);
}

// Kept for the test suite
int Driver::parse_str(std::string script)
{
  source("stdin", script);
  return parse();
}

int Driver::parse()
{
  // Reset source location info on every pass
  loc.initialize();
  yy_scan_string(bpftrace_.source().c_str(), scanner_);
  int result = parser_->parse();
  return result;
}

void Driver::error(const location &l, const std::string &m)
{
  bpftrace_.error(out_, l, m);
}

void Driver::error(const std::string &m) { out_ << m << std::endl; }

} // namespace bpftrace
