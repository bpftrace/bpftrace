#include <iostream>

#include "driver.h"

extern void *yy_scan_string(const char *yy_str, yyscan_t yyscanner);
extern int yylex_init(yyscan_t *scanner);
extern int yylex_destroy (yyscan_t yyscanner);
extern bpftrace::location loc;

namespace bpftrace {

Driver::Driver(BPFtrace &bpftrace, std::ostream &o) : bpftrace_(bpftrace), out_(o)
{
}

Driver::~Driver()
{
  delete root_;
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
  // Ensure we free memory allocated the previous parse if we parse
  // more than once
  delete root_;
  root_ = nullptr;

  // Reset source location info on every pass
  loc.initialize();

  yyscan_t scanner;
  yylex_init(&scanner);
  Parser parser(*this, scanner);
  yy_scan_string(bpftrace_.source().c_str(), scanner);
  parser.parse();
  yylex_destroy(scanner);

  // Keep track of errors thrown ourselves, since the result of
  // parser_->parse() doesn't take scanner errors into account,
  // only parser errors.
  return failed_;
}

void Driver::error(const location &l, const std::string &m)
{
  bpftrace_.error(out_, l, m);
  failed_ = true;
}

void Driver::error(const std::string &m)
{
  out_ << m << std::endl;
  failed_ = true;
}

} // namespace bpftrace
