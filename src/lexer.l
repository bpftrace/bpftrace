%option yylineno nodefault noyywrap
%option never-interactive
%{
#include "driver.h"
#include "parser.tab.hh"

#undef yywrap
#define yywrap() 1

static ebpf::bpftrace::location loc;

#define YY_USER_ACTION loc.columns(yyleng);
#define yyterminate() return ebpf::bpftrace::Parser::make_END(loc)

using namespace ebpf::bpftrace;
%}

%%

%{
  loc.step();
%}

[ \t]+                  { loc.step(); }
[\n\r]+                 { loc.lines(yyleng); loc.step(); }
"//".*$  // Comments

[_a-zA-Z][_a-zA-Z0-9]*  { return Parser::make_IDENT(yytext, loc); }
[0-9]+                  { return Parser::make_INT(strtoul(yytext, NULL, 0), loc); }
0[xX][0-9a-fA-F]+       { return Parser::make_INT(strtoul(yytext, NULL, 0), loc); }
":"                     { return Parser::make_COLON(loc); }
";"                     { return Parser::make_SEMI(loc); }
"{"                     { return Parser::make_LBRACE(loc); }
"}"                     { return Parser::make_RBRACE(loc); }
"="                     { return Parser::make_ASSIGN(loc); }

.                       { driver.error(loc, std::string("invalid character: ")+std::string(yytext)); exit(1); }

%%
