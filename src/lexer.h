#pragma once

#include "driver.h"
#include "parser.tab.hh"

#define YY_DECL                                                                \
  bpftrace::Parser::symbol_type yylex(bpftrace::Driver &driver,                \
                                      yyscan_t yyscanner)
YY_DECL;
