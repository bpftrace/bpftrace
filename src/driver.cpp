#include <iostream>

#include "driver.h"

extern FILE *yyin;
extern void *yy_scan_string(const char *yystr);

namespace bpftrace {

int Driver::parse_stdin()
{
  return parser_.parse();
}

int Driver::parse_str(const std::string &script)
{
  void *buffer = yy_scan_string(script.c_str());
  int result = parser_.parse();
  free(buffer);
  return result;
}

int Driver::parse_file(const std::string &f)
{
  if (!(yyin = fopen(f.c_str(), "r"))) {
    std::cerr << "Error: Could not open file '" << f << "'" << std::endl;
    return -1;
  }
  int result = parser_.parse();
  fclose(yyin);
  return result;
}

} // namespace bpftrace
