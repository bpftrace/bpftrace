%option yylineno noyywrap noinput
%option never-interactive
%option reentrant
%option stack

%{
#include <climits>
#include "driver.h"
#include "parser.tab.hh"
#include "util/int_parser.h"
#include "util/strings.h"

#define YY_USER_ACTION driver.loc.advance_columns(yyleng);
#define yyterminate() return bpftrace::Parser::make_END(driver.loc)
#define ECHO

using namespace bpftrace;

// Since `YY_INPUT` cannot access the `driver` variable, `source` and `curr`
// are defined as global variables. They are marked as thread_local to
// ensure thread safety during lexical analysis.
static thread_local const std::string *source;
static thread_local size_t curr;

void set_source_string(const std::string *s);
static int read_from_source(char* buf, size_t max_size);

#define YY_INPUT(buf,result,max_size) \
  result = read_from_source(buf, max_size);
%}

/* https://en.cppreference.com/w/cpp/language/integer_literal#The_type_of_the_literal */
int_size (([uU])|([uU]?[lL]?[lL])|(ns)|(us)|(ms)|(s)|(m)|(h)|(d))

/* Number with underscores in it, e.g. 1_000_000 */
int      [0-9]([0-9_]*[0-9])?{int_size}?
bool     true|false
hex      0[xX][0-9a-fA-F]+
/* scientific notation, e.g. 2e4 or 1e6 */
exponent {int}[eE]{int}

ident    [_a-zA-Z][_a-zA-Z0-9]*
map      @{ident}|@
var      ${ident}
hspace   [ \t]
vspace   \n
path     :(\\.|[_\-\./a-zA-Z0-9#$+\*])+
/* Most of the builtins are prefixed with __builtin_ as they are exposed to users via macros e.g. macro cpu() { __builtin_cpu } */
builtin  arg[0-9]+|args|ctx|kstack|nsecs|pid|sarg[0-9]|tid|ustack|__builtin_cgroup|__builtin_comm|__builtin_cpid|__builtin_cpu|__builtin_curtask|__builtin_elapsed|__builtin_func|__builtin_gid|__builtin_jiffies|__builtin_ncpus|__builtin_probe|__builtin_rand|__builtin_retval|__builtin_uid|__builtin_usermode|__builtin_username

int_type        bool|(u)?int(8|16|32|64)
builtin_type    void|(u)?(min|max|sum|avg|stats)_t|count_t|probe_t|username_t|lhist_t|hist_t|usym_t|ksym_t|timestamp|macaddr_t|cgroup_path_t|kstack_t|ustack_t|tseries_t
sized_type      inet|buffer|string
subprog         fn
macro           macro

/* escape sequences in strings */
hex_esc  (x|X)[0-9a-fA-F]{1,2}
oct_esc  [0-7]{1,3}

%x SCRIPT
%x STR
%x STRUCT
%x ENUM
%x BRACE
%x CCOMMENT
%x CCOMMENTNL
%x CPPCOMMENT
%x CPPCOMMENTNL
%x AFTER_DIV
%x AFTER_COLON
%x STRUCT_AFTER_COLON

%%

%{
  if (driver.token) {
    auto t = *driver.token;
    driver.token.reset();
    return t;
  }
%}

^"#!"[^\n]*\n           {
                          driver.loc.trim();
                          yy_push_state(SCRIPT, yyscanner);
                          auto v = Parser::make_HEADER(yytext, driver.loc);
                          driver.loc.advance_lines(1);
                          return v;
                        }
{vspace}+               {
                          driver.loc.advance_lines(yyleng);
                          driver.ctx.add_vspace(driver.loc, yyleng);
                        }
.                       {
                          driver.loc.rewind_columns();
                          unput(yytext[0]);
                          yy_push_state(SCRIPT, yyscanner);
                        }

<CCOMMENT>{
  "*/"                  yy_pop_state(yyscanner);
  \n                    {
                          driver.loc.advance_lines(1);
                          yy_pop_state(yyscanner);
                          yy_push_state(CCOMMENTNL, yyscanner);
                        }
  ([^*\n]|[*][^/\n])+   { driver.ctx.add_comment(driver.loc); }
  <<EOF>>               {
                           yy_pop_state(yyscanner);
                           driver.error(driver.loc, "end of file during comment");
                        }
}
<CCOMMENTNL>{
  [*][/]\n              { driver.loc.advance_lines(1); yy_pop_state(yyscanner); }
  "*/"                  { yy_pop_state(yyscanner); }
  [*]+[ ]*\n            {
                          driver.loc.advance_lines(1);
                          driver.ctx.add_comment(driver.loc); // Empty.
                        }
  [*]+[ ]?              { yy_pop_state(yyscanner); yy_push_state(CCOMMENT, yyscanner); }
  {hspace}+             { }
  \n                    {
                          driver.loc.advance_lines(1);
                          driver.ctx.add_comment(driver.loc); // Empty.
                        }
  .                     {
                           driver.loc.rewind_columns();
                           unput(yytext[0]);
                           yy_pop_state(yyscanner);
                           yy_push_state(CCOMMENT, yyscanner);
                        }
  <<EOF>>               {
                           yy_pop_state(yyscanner);
                           driver.error(driver.loc, "end of file during comment");
                        }
}
<CPPCOMMENT>{
  [^\n]+                { driver.ctx.add_comment(driver.loc); }
  \n                    {
                          driver.loc.advance_lines(1);
                          yy_pop_state(yyscanner);
                          yy_push_state(CPPCOMMENTNL, yyscanner);
                        }
  <<EOF>>               yy_pop_state(yyscanner);
}
<CPPCOMMENTNL>{
  {hspace}+             { }
  [/][/][ ]\n           {
                          driver.loc.advance_lines(1);
                          driver.ctx.add_comment(driver.loc); // Empty.
                        }
  [/][/]\n              {
                          driver.loc.advance_lines(1);
                          driver.ctx.add_comment(driver.loc); // Empty.
                        }
  "// "                 {
                          yy_pop_state(yyscanner);
                          yy_push_state(CPPCOMMENT, yyscanner);
                        }
  "//"                  {
                          yy_pop_state(yyscanner);
                          yy_push_state(CPPCOMMENT, yyscanner);
                        }
  \n                    {
                          driver.loc.advance_lines(1);
                          driver.ctx.add_vspace(driver.loc, 1);
                          yy_pop_state(yyscanner);
                        }
  .                     {
                          driver.loc.rewind_columns();
                          unput(yytext[0]);
                          yy_pop_state(yyscanner);
                        }
  <<EOF>>               yy_pop_state(yyscanner);
}

<SCRIPT>{
  {hspace}+               { }
  {vspace}+               {
                            driver.loc.advance_lines(yyleng);
                            driver.ctx.add_vspace(driver.loc, yyleng);
                          }
  \r                      { driver.loc.reset_column(); }
  "/** "                  { yy_push_state(CCOMMENT, yyscanner); }
  "/**"                   { yy_push_state(CCOMMENT, yyscanner); }
  "/* "                   { yy_push_state(CCOMMENT, yyscanner); }
  "/*"                    { yy_push_state(CCOMMENT, yyscanner); }
  "// "                   { yy_push_state(CPPCOMMENT, yyscanner); }
  "//"                    { yy_push_state(CPPCOMMENT, yyscanner); }

  {builtin}               { return Parser::make_BUILTIN(yytext, driver.loc); }
  {subprog}               { return Parser::make_SUBPROG(yytext, driver.loc); }
  {macro}                 { return Parser::make_MACRO(yytext, driver.loc); }
  {int}|{hex}|{exponent}  { return Parser::make_UNSIGNED_INT(yytext, driver.loc); }
  {bool}                  {
                            if (std::string(yytext) == "true") {
                              return Parser::make_BOOL(true, driver.loc);
                            }
                            return Parser::make_BOOL(false, driver.loc);
                          }
  {path}                  { return Parser::make_PATH(yytext, driver.loc); }
  {map}                   { return Parser::make_MAP(yytext, driver.loc); }
  {var}                   { return Parser::make_VAR(yytext, driver.loc); }
  ":"                     {
                            /* For handling "struct x" in "fn name(...): struct x {  }" as a type rather than
                              a beginning of a struct definition; see AFTER_COLON rules below */
                            yy_push_state(AFTER_COLON, yyscanner);
                            return Parser::make_COLON(driver.loc);
                          }
  /* N.B. The newline following semi-colons and braces does not count as explicit vspace. */
  [;]\n                   { driver.loc.trim(); auto v = Parser::make_SEMI(driver.loc); driver.loc.advance_lines(1); return v; }
  [{]\n                   { driver.loc.trim(); auto v = Parser::make_LBRACE(driver.loc); driver.loc.advance_lines(1); return v; }
  [}]\n                   { driver.loc.trim(); auto v = Parser::make_RBRACE(driver.loc); driver.loc.advance_lines(1); return v; }
  ";"                     { return Parser::make_SEMI(driver.loc); }
  "{"                     { return Parser::make_LBRACE(driver.loc); }
  "}"                     { return Parser::make_RBRACE(driver.loc); }
  "["                     { return Parser::make_LBRACKET(driver.loc); }
  "]"                     { return Parser::make_RBRACKET(driver.loc); }
  "("                     { return Parser::make_LPAREN(driver.loc); }
  ")"                     { return Parser::make_RPAREN(driver.loc); }
  ","                     { return Parser::make_COMMA(driver.loc); }
  "="                     { return Parser::make_ASSIGN(driver.loc); }
  "<<="                   { return Parser::make_LEFTASSIGN(driver.loc); }
  ">>="                   { return Parser::make_RIGHTASSIGN(driver.loc); }
  "+="                    { return Parser::make_PLUSASSIGN(driver.loc); }
  "-="                    { return Parser::make_MINUSASSIGN(driver.loc); }
  "*="                    { return Parser::make_MULASSIGN(driver.loc); }
  "/="                    { return Parser::make_DIVASSIGN(driver.loc); }
  "%="                    { return Parser::make_MODASSIGN(driver.loc); }
  "&="                    { return Parser::make_BANDASSIGN(driver.loc); }
  "|="                    { return Parser::make_BORASSIGN(driver.loc); }
  "^="                    { return Parser::make_BXORASSIGN(driver.loc); }
  "=="                    { return Parser::make_EQ(driver.loc); }
  "!="                    { return Parser::make_NE(driver.loc); }
  "<="                    { return Parser::make_LE(driver.loc); }
  ">="                    { return Parser::make_GE(driver.loc); }
  "<<"                    { return Parser::make_LEFT(driver.loc); }
  ">>"                    { return Parser::make_RIGHT(driver.loc); }
  "<"                     { return Parser::make_LT(driver.loc); }
  ">"                     { return Parser::make_GT(driver.loc); }
  "&&"                    { return Parser::make_LAND(driver.loc); }
  "||"                    { return Parser::make_LOR(driver.loc); }
  "+"                     { return Parser::make_PLUS(driver.loc); }
  "-"                     { return Parser::make_MINUS(driver.loc); }
  "++"                    { return Parser::make_INCREMENT(driver.loc); }
  "--"                    { return Parser::make_DECREMENT(driver.loc); }
  "*"                     { return Parser::make_MUL(driver.loc); }
  "/"                     { driver.orig_loc = driver.loc; yy_push_state(AFTER_DIV, yyscanner); }
  "%"                     { return Parser::make_MOD(driver.loc); }
  "&"                     { return Parser::make_BAND(driver.loc); }
  "|"                     { return Parser::make_BOR(driver.loc); }
  "^"                     { return Parser::make_BXOR(driver.loc); }
  "!"                     { return Parser::make_LNOT(driver.loc); }
  "~"                     { return Parser::make_BNOT(driver.loc); }
  "."                     { return Parser::make_DOT(driver.loc); }
  "->"                    { return Parser::make_PTR(driver.loc); }
  "_"                     { return Parser::make_UNDERSCORE(driver.loc); }
  "$"[0-9]+               { return Parser::make_PARAM(yytext, driver.loc); }
  "$"#                    { return Parser::make_PARAMCOUNT(driver.loc); }
  /* N.B. The C preprocessor directives also span the line. */
  [#][^!][^\n]*\n         { driver.loc.trim(); auto v = Parser::make_CPREPROC(yytext, driver.loc); driver.loc.advance_lines(1); return v; }
  "if"                    { return Parser::make_IF(yytext, driver.loc); }
  "else"                  { return Parser::make_ELSE(yytext, driver.loc); }
  "?"                     { return Parser::make_QUES(driver.loc); }
  "unroll"                { return Parser::make_UNROLL(yytext, driver.loc); }
  "while"                 { return Parser::make_WHILE(yytext, driver.loc); }
  "config"                { return Parser::make_CONFIG(yytext, driver.loc); }
  "for"                   { return Parser::make_FOR(yytext, driver.loc); }
  "return"                { return Parser::make_RETURN(yytext, driver.loc); }
  "continue"              { return Parser::make_CONTINUE(yytext, driver.loc); }
  "break"                 { return Parser::make_BREAK(yytext, driver.loc); }
  "sizeof"                { return Parser::make_SIZEOF(yytext, driver.loc); }
  "offsetof"              { return Parser::make_OFFSETOF(yytext, driver.loc); }
  "typeof"                { return Parser::make_TYPEOF(yytext, driver.loc); }
  "typeinfo"              { return Parser::make_TYPEINFO(yytext, driver.loc); }
  "let"                   { return Parser::make_LET(yytext, driver.loc); }
  "import"                { return Parser::make_IMPORT(yytext, driver.loc); }
  "comptime"              { return Parser::make_COMPTIME(yytext, driver.loc); }

  {int_type}              { return Parser::make_INT_TYPE(yytext, driver.loc); }
  {builtin_type}          { return Parser::make_BUILTIN_TYPE(yytext, driver.loc); }
  {sized_type}            { return Parser::make_SIZED_TYPE(yytext, driver.loc); }


  \"                      { yy_push_state(STR, yyscanner); driver.buffer.clear(); }
  struct|union|enum       {
                            yy_push_state(STRUCT, yyscanner);
                            driver.buffer.clear();
                            driver.struct_type = yytext;
                            return Parser::make_STRUCT(driver.loc);
                          }
  {ident}                 { return Parser::make_IDENT(yytext, driver.loc); }
  .                       { driver.error(driver.loc, std::string("invalid character '") +
                                              std::string(yytext) + std::string("'")); }
  <<EOF>>                 yy_pop_state(yyscanner);
}

<STR>{
  \"                    { yy_pop_state(yyscanner); return Parser::make_STRING(driver.buffer, driver.loc); }
  [^\\\n\"]+            driver.buffer += yytext;
  \\n                   driver.buffer += '\n';
  \\t                   driver.buffer += '\t';
  \\r                   driver.buffer += '\r';
  \\\"                  driver.buffer += '\"';
  \\\\                  driver.buffer += '\\';
  \\{oct_esc}           {
                            long value = strtol(yytext+1, NULL, 8);
                            if (value > UCHAR_MAX)
                              driver.error(driver.loc, std::string("octal escape sequence out of range '") +
                                                yytext + "'");
                            driver.buffer += value;
                        }
  \\{hex_esc}           driver.buffer += strtol(yytext+2, NULL, 16);
  \n                    driver.error(driver.loc, "unterminated string"); yy_pop_state(yyscanner); driver.loc.advance_lines(1);
  <<EOF>>               driver.error(driver.loc, "unterminated string"); yy_pop_state(yyscanner);
  \\.                   { driver.error(driver.loc, std::string("invalid escape character '") +
                                            yytext + "'"); }
  .                     driver.error(driver.loc, "invalid character"); yy_pop_state(yyscanner);
}

<AFTER_DIV>{
  {hspace}+             { }
  {vspace}+             { driver.loc.advance_lines(yyleng); }
  "{"                   {
                          driver.loc.rewind_columns();
                          unput(yytext[0]);
                          yy_pop_state(yyscanner);
                          return Parser::make_ENDPRED(driver.orig_loc);
                        }
  .                     {
                          driver.loc.rewind_columns();
                          unput(yytext[0]);
                          yy_pop_state(yyscanner);
                          return Parser::make_DIV(driver.orig_loc);
                        }
}

<AFTER_COLON>{
  {hspace}+             { }
  {vspace}+             { driver.loc.advance_lines(yyleng); }
  \r                    { driver.loc.reset_column(); }
  struct|union|enum     {
                          yy_pop_state(yyscanner);
                          yy_push_state(STRUCT_AFTER_COLON, yyscanner);
                          driver.buffer.clear();
                          driver.struct_type = yytext;
                          return Parser::make_STRUCT(driver.loc);
                        }
  .                     { driver.loc.rewind_columns(); unput(yytext[0]); yy_pop_state(yyscanner); }
}

<STRUCT_AFTER_COLON>{
  {hspace}+             { }
  {vspace}+             { driver.loc.advance_lines(yyleng); }
  \r                    { driver.loc.reset_column(); }
  {ident}               {
                          driver.buffer = yytext;
                          yy_pop_state(yyscanner);
                          return Parser::make_IDENT(driver.struct_type + " " + util::trim(driver.buffer), driver.loc);
                        }
}

<STRUCT,BRACE>{
  "*"|")"|","           {
                          if (YY_START == STRUCT)
                          {
                            // Finished parsing the typename of a cast or a call arg
                            // Put the cast type into a canonical form by trimming
                            // and then inserting a single space.
                            yy_pop_state(yyscanner);
                            for (int i = yyleng - 1; i >= 0; i--) {
                              driver.loc.rewind_columns();
                              unput(yytext[i]);
                            }
                            return Parser::make_IDENT(driver.struct_type + " " + util::trim(driver.buffer), driver.loc);
                          }
                          driver.buffer += yytext[0];
                        }
  "{"                   yy_push_state(BRACE, yyscanner); driver.buffer += '{';
  [}][;]?[\n]?          {
                          driver.buffer += yytext;
                          if (yytext[yyleng-1] == '\n') {
                            driver.loc.trim();
                          }
                          auto loc = driver.loc;
                          if (yytext[yyleng-1] == '\n') {
                            driver.loc.advance_lines(1);
                          }
                          yy_pop_state(yyscanner);
                          if (YY_START == STRUCT)
                          {
                            // Finished parsing a struct definition
                            // Trimming isn't needed here since the typenames
                            // will go through Clang before we get them back
                            // anyway.
                            yy_pop_state(yyscanner);
                            return Parser::make_STRUCT_DEFN(driver.struct_type + driver.buffer, loc);
                          }
                        }
  .                     driver.buffer += yytext[0];
  \n                    driver.buffer += '\n'; driver.loc.advance_lines(1);
}
%%

void set_source_string(const std::string *s) {
  source = s;
  curr = 0;
}

// Here we replaced the original YY_INPUT with the read_from_source() function,
// allowing flex to read the source code from a string rather than a file. In
// this case, flex uses a buffer size of YY_BUF_SIZE (16384) and reads up to
// YY_READ_BUF_SIZE (8192) at a time. This gives us enough space for macro
// expansion. Additionally, just like reading from a file, flex's internal
// buffer management can handle cases where the string size exceeds YY_BUF_SIZE.
int read_from_source(char* buf, size_t max_size) {
  size_t num_to_copy = std::min(source->size() - curr, max_size);
  source->copy(buf, num_to_copy, curr);
  curr += num_to_copy;
  return num_to_copy;
}
