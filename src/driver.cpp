#include <iostream>

#include "ast/attachpoint_parser.h"
#include "driver.h"
#include "log.h"
#include "parser.tab.hh"

extern void *yy_scan_string(const char *yy_str, yyscan_t yyscanner);
extern int yylex_init(yyscan_t *scanner);
extern int yylex_destroy (yyscan_t yyscanner);
extern bpftrace::location loc;

namespace bpftrace {

Driver::Driver(BPFtrace &bpftrace, std::ostream &o)
    : bpftrace_(bpftrace), out_(o)
{
}

void Driver::source(std::string filename, std::string script)
{
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
  // Reset previous state if we parse more than once
  root.reset();

  // Reset source location info on every pass
  loc.initialize();

  yyscan_t scanner;
  yylex_init(&scanner);
  Parser parser(*this, scanner);
  if (debug_)
  {
    parser.set_debug_level(1);
  }
  yy_scan_string(Log::get().get_source().c_str(), scanner);
  parser.parse();
  yylex_destroy(scanner);

  if (!failed_)
  {
    ast::AttachPointParser ap_parser(root.get(), bpftrace_, out_, listing_);
    if (ap_parser.parse())
      failed_ = true;
  }

  if (failed_)
  {
    root.reset();
  }

  // Keep track of errors thrown ourselves, since the result of
  // parser_->parse() doesn't take scanner errors into account,
  // only parser errors.
  return failed_;
}

void Driver::error(const location &l, const std::string &m)
{
  LOG(ERROR, l, out_) << m;
  failed_ = true;
}

void Driver::error(const std::string &m)
{
  LOG(ERROR, out_) << m;
  failed_ = true;
}

} // namespace bpftrace
