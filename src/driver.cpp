#include <iostream>

#include "driver.h"

extern FILE *yyin;
extern void *yy_scan_string(const char *yy_str, yyscan_t yyscanner);
extern void yyset_in(FILE *_in_str, yyscan_t yyscanner);
extern int yylex_init(yyscan_t *scanner);
extern int yylex_destroy (yyscan_t yyscanner);

namespace bpftrace {

Driver::Driver()
{
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

int Driver::parse_str(const std::string &script)
{
  yy_scan_string(script.c_str(), scanner_);
  int result = parser_->parse();
  return result;
}

int Driver::parse_file(const std::string &f)
{
  FILE *file;
  if (!(file = fopen(f.c_str(), "r"))) {
    std::cerr << "Error: Could not open file '" << f << "'" << std::endl;
    return -1;
  }
  yyset_in(file, scanner_);
  int result = parser_->parse();
  fclose(file);
  return result;
}

void Driver::error(const location &l, const std::string &m)
{
  std::cerr << l << ": " << m << std::endl;
}

void Driver::error(const std::string &m)
{
  std::cerr << m << std::endl;
}

} // namespace bpftrace
