%option yylineno nodefault noyywrap noinput
%option never-interactive
%option reentrant
%option stack
%{
#include "driver.h"
#include "utils.h"
#include "parser.tab.hh"

static bpftrace::location loc;
static std::string struct_type;
static std::string buffer;

#define YY_USER_ACTION loc.columns(yyleng);
#define yyterminate() return bpftrace::Parser::make_END(loc)

using namespace bpftrace;
%}

ident  [_a-zA-Z][_a-zA-Z0-9]*
map    @{ident}|@
var    ${ident}
int    [0-9]+|0[xX][0-9a-fA-F]+
hspace [ \t]
vspace [\n\r]
space  {hspace}|{vspace}
path   :(\\.|[_\-\./a-zA-Z0-9])*:
%x STR
%x STRUCT
%x ENUM
%x BRACE
%x COMMENT

%%

%{
  loc.step();
%}

{hspace}+               { loc.step(); }
{vspace}+               { loc.lines(yyleng); loc.step(); }

^"#!".*$                // executable line
"//".*$                 // single-line comments
"/*"                    yy_push_state(COMMENT, yyscanner);
<COMMENT>{
  "*/"                  yy_pop_state(yyscanner);
  [^*\n]+|"*"           {}
  \n                    loc.lines(1); loc.step();
  <<EOF>>               yy_pop_state(yyscanner); driver.error(loc, "end of file during comment");
}

pid|tid|cgroup|uid|gid|nsecs|cpu|comm|kstack|stack|ustack|arg[0-9]|retval|func|probe|curtask|rand|ctx|username|args|elapsed {
                          return Parser::make_BUILTIN(yytext, loc); }
bpftrace|perf {
                          return Parser::make_STACK_MODE(yytext, loc); }
{path}                  { return Parser::make_PATH(yytext, loc); }
{map}                   { return Parser::make_MAP(yytext, loc); }
{var}                   { return Parser::make_VAR(yytext, loc); }
{int}                   { return Parser::make_INT(strtoll(yytext, NULL, 0), loc); }
":"                     { return Parser::make_COLON(loc); }
";"                     { return Parser::make_SEMI(loc); }
"{"                     { return Parser::make_LBRACE(loc); }
"}"                     { return Parser::make_RBRACE(loc); }
"["                     { return Parser::make_LBRACKET(loc); }
"]"                     { return Parser::make_RBRACKET(loc); }
"("                     { return Parser::make_LPAREN(loc); }
")"                     { return Parser::make_RPAREN(loc); }
\//{space}*[\/\{]       { return Parser::make_ENDPRED(loc); } /* If "/" is followed by "/" or "{", choose ENDPRED, otherwise DIV */
","                     { return Parser::make_COMMA(loc); }
"="                     { return Parser::make_ASSIGN(loc); }
"=="                    { return Parser::make_EQ(loc); }
"!="                    { return Parser::make_NE(loc); }
"<="                    { return Parser::make_LE(loc); }
">="                    { return Parser::make_GE(loc); }
"<<"                    { return Parser::make_LEFT(loc); }
">>"                    { return Parser::make_RIGHT(loc); }
"<"                     { return Parser::make_LT(loc); }
">"                     { return Parser::make_GT(loc); }
"&&"                    { return Parser::make_LAND(loc); }
"||"                    { return Parser::make_LOR(loc); }
"+"                     { return Parser::make_PLUS(loc); }
"-"                     { return Parser::make_MINUS(loc); }
"++"                    { return Parser::make_PLUSPLUS(loc); }
"--"                    { return Parser::make_MINUSMINUS(loc); }
"$"                     { return Parser::make_DOLLAR(loc); }
"*"                     { return Parser::make_MUL(loc); }
"/"                     { return Parser::make_DIV(loc); }
"%"                     { return Parser::make_MOD(loc); }
"&"                     { return Parser::make_BAND(loc); }
"|"                     { return Parser::make_BOR(loc); }
"^"                     { return Parser::make_BXOR(loc); }
"!"                     { return Parser::make_LNOT(loc); }
"~"                     { return Parser::make_BNOT(loc); }
"."                     { return Parser::make_DOT(loc); }
"->"                    { return Parser::make_PTR(loc); }
"#"[^!].*               { return Parser::make_CPREPROC(yytext, loc); }
"if"                    { return Parser::make_IF(yytext, loc); }
"else"                  { return Parser::make_ELSE(yytext, loc); }
"?"                     { return Parser::make_QUES(loc); }
"unroll"                { return Parser::make_UNROLL(yytext, loc); }

\"                      { yy_push_state(STR, yyscanner); buffer.clear(); }
<STR>{
  \"                    { yy_pop_state(yyscanner); return Parser::make_STRING(buffer, loc); }
  [^\\\n\"]+            buffer += yytext;
  \\n                   buffer += '\n';
  \\t                   buffer += '\t';
  \\r                   buffer += '\r';
  \\\"                  buffer += '\"';
  \\\\                  buffer += '\\';
  \n                    driver.error(loc, "unterminated string"); yy_pop_state(yyscanner); loc.lines(1); loc.step();
  <<EOF>>               driver.error(loc, "unterminated string"); yy_pop_state(yyscanner);
  \\.                   { driver.error(loc, std::string("invalid escape character '") +
                                            yytext + "'"); }
  .                     driver.error(loc, "invalid character"); yy_pop_state(yyscanner);
}

struct|union            yy_push_state(STRUCT, yyscanner); buffer.clear(); struct_type = yytext;
enum                    yy_push_state(ENUM, yyscanner); buffer.clear();
<STRUCT,BRACE,ENUM>{
  "*"|")"               { if (YY_START == STRUCT) {
                            yy_pop_state(yyscanner);
                            unput(yytext[0]);
                            return Parser::make_IDENT(trim(buffer), loc);
                          }
                          buffer += yytext[0];
                        }
  "{"                   yy_push_state(BRACE, yyscanner); buffer += '{';
  "}"|"};"              { buffer += yytext;
                          yy_pop_state(yyscanner);
                          if (YY_START == STRUCT) {
                            yy_pop_state(yyscanner);
                            return Parser::make_STRUCT(struct_type + buffer, loc);
                          }
                          if (YY_START == ENUM) {
                            yy_pop_state(yyscanner);
                            return Parser::make_ENUM("enum " + buffer, loc);
                          }
                        }
  .                     buffer += yytext[0];
  \n                    buffer += '\n'; loc.lines(1); loc.step();
}

{ident}                 {
                          if (driver.bpftrace_.macros_.count(yytext) != 0) {
                            const char *s = driver.bpftrace_.macros_[yytext].c_str();
                            int z;
                            // NOTE(mmarchini) workaround for simple recursive
                            // macros. More complex recursive macros (for
                            // example, with operators) will go into an
                            // infinite loop. Yes, we should fix that in the
                            // future.
                            if (strcmp(s, yytext) == 0) {
                              return Parser::make_IDENT(yytext, loc);
                            } else {
                              for (z=strlen(s) - 1; z >= 0; z--)
                                unput(s[z]);
                            }
                          } else {
                            return Parser::make_IDENT(yytext, loc);
                          }
                        }
.                       { driver.error(loc, std::string("invalid character '") +
                                            std::string(yytext) + std::string("'")); }

%%
