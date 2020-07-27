#include <iostream>

#include "ast/attachpoint_parser.h"
#include "driver.h"
#include "log.h"

extern void *yy_scan_string(const char *yy_str, yyscan_t yyscanner);
extern int yylex_init(yyscan_t *scanner);
extern int yylex_destroy (yyscan_t yyscanner);
extern bpftrace::location loc;

namespace bpftrace {

Driver::Driver(BPFtrace &bpftrace, std::ostream &o) : bpftrace_(bpftrace), out_(o)
{
  yylex_init(&scanner_);
  parser_ = std::make_unique<Parser>(*this, scanner_);
}

Driver::~Driver()
{
  yylex_destroy(scanner_);
}

void Driver::source(std::string filename, std::string script)
{
  bpftrace_.source(filename, script);
  Log::get().set_source(filename, script);
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
  parser_->parse();

  ast::AttachPointParser ap_parser(root_, bpftrace_, out_);
  if (ap_parser.parse())
    failed_ = true;

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
