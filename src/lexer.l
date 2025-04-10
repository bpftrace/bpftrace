%option yylineno noyywrap noinput
%option never-interactive
%option reentrant
%option stack

%{
#include <climits>
#include "driver.h"
#include "parser.tab.hh"
#include "util/int_parser.h"
#include "util/format.h"

#define YY_USER_ACTION driver.loc.columns(yyleng);
#define yyterminate() return bpftrace::Parser::make_END(driver.loc)

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
int_size (([uU])|([uU]?[lL]?[lL]))

/* Number with underscores in it, e.g. 1_000_000 */
int      -?[0-9]([0-9_]*[0-9])?{int_size}?
hex      0[xX][0-9a-fA-F]+
/* scientific notation, e.g. 2e4 or 1e6 */
exponent {int}[eE]{int}

ident    [_a-zA-Z][_a-zA-Z0-9]*
map      @{ident}|@
var      ${ident}
hspace   [ \t]
vspace   [\n\r]
space    {hspace}|{vspace}
path     :(\\.|[_\-\./a-zA-Z0-9#$+\*])+
builtin  arg[0-9]|args|cgroup|comm|cpid|numaid|cpu|ctx|curtask|elapsed|func|gid|pid|probe|rand|retval|sarg[0-9]|tid|uid|username|jiffies
call     avg|buf|cat|cgroupid|clear|count|delete|exit|hist|join|kaddr|kptr|ksym|len|lhist|macaddr|max|min|ntop|override|print|printf|cgroup_path|reg|signal|stats|str|strerror|strftime|strncmp|strcontains|sum|system|time|uaddr|uptr|usym|zero|path|unwatch|bswap|skboutput|pton|debugf|has_key|percpu_kaddr

int_type        bool|(u)?int(8|16|32|64)
builtin_type    void|(u)?(min|max|sum|count|avg|stats)_t|probe_t|username|lhist_t|hist_t|usym_t|ksym_t|timestamp|macaddr_t|cgroup_path_t|strerror_t|kstack_t|ustack_t
sized_type      string|inet|buffer
subprog         fn

/* Don't add to this! Use builtin OR call not both */
call_and_builtin kstack|ustack|nsecs

/* escape sequences in strings */
hex_esc  (x|X)[0-9a-fA-F]{1,2}
oct_esc  [0-7]{1,3}

%x STR
%x STRUCT
%x ENUM
%x BRACE
%x COMMENT
%x AFTER_COLON
%x STRUCT_AFTER_COLON

%%

{hspace}+               { driver.loc.step(); }
{vspace}+               { driver.loc.lines(yyleng); driver.loc.step(); }

^"#!".*$                // executable line
"//".*$                 // single-line comments
"/*"                    yy_push_state(COMMENT, yyscanner);
<COMMENT>{
  "*/"                  yy_pop_state(yyscanner);
  [^*\n]+|"*"           {}
  \n                    driver.loc.lines(1); driver.loc.step();
  <<EOF>>               yy_pop_state(yyscanner); driver.error(driver.loc, "end of file during comment");
}

{builtin}               { return Parser::make_BUILTIN(yytext, driver.loc); }
{call}                  { return Parser::make_CALL(yytext, driver.loc); }
{call_and_builtin}      { return Parser::make_CALL_BUILTIN(yytext, driver.loc); }
{subprog}               { return Parser::make_SUBPROG(yytext, driver.loc); }
{int}|{hex}|{exponent}  {
                          try
                          {
                            if (yytext[0] == '-') {
                              auto res = util::to_int(yytext, 0);
                              return Parser::make_SIGNED_INT(res, driver.loc);
                            } else {
                              auto res = util::to_uint(yytext, 0);
                              return Parser::make_UNSIGNED_INT(res, driver.loc);
                            }
                          }
                          catch (const std::exception &e)
                          {
                            driver.error(driver.loc, e.what());
                          }
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
";"                     { return Parser::make_SEMI(driver.loc); }
"{"                     { return Parser::make_LBRACE(driver.loc); }
"}"                     { return Parser::make_RBRACE(driver.loc); }
"["                     { return Parser::make_LBRACKET(driver.loc); }
"]"                     { return Parser::make_RBRACKET(driver.loc); }
"("                     { return Parser::make_LPAREN(driver.loc); }
")"                     { return Parser::make_RPAREN(driver.loc); }
\//{space}*[\/\{]       { return Parser::make_ENDPRED(driver.loc); } /* If "/" is followed by "/" or "{", choose ENDPRED, otherwise DIV */
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
"/"                     { return Parser::make_DIV(driver.loc); }
"%"                     { return Parser::make_MOD(driver.loc); }
"&"                     { return Parser::make_BAND(driver.loc); }
"|"                     { return Parser::make_BOR(driver.loc); }
"^"                     { return Parser::make_BXOR(driver.loc); }
"!"                     { return Parser::make_LNOT(driver.loc); }
"~"                     { return Parser::make_BNOT(driver.loc); }
"."                     { return Parser::make_DOT(driver.loc); }
"->"                    { return Parser::make_PTR(driver.loc); }
"$"[0-9]+               { return Parser::make_PARAM(yytext, driver.loc); }
"$"#                    { return Parser::make_PARAMCOUNT(driver.loc); }
"#"[^!].*               { return Parser::make_CPREPROC(yytext, driver.loc); }
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
"let"                   { return Parser::make_LET(yytext, driver.loc); }
"import"                { return Parser::make_IMPORT(yytext, driver.loc); }

{int_type}              { return Parser::make_INT_TYPE(yytext, driver.loc); }
{builtin_type}          { return Parser::make_BUILTIN_TYPE(yytext, driver.loc); }
{sized_type}            { return Parser::make_SIZED_TYPE(yytext, driver.loc); }


\"                      { yy_push_state(STR, yyscanner); driver.buffer.clear(); }
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
  \n                    driver.error(driver.loc, "unterminated string"); yy_pop_state(yyscanner); driver.loc.lines(1); driver.loc.step();
  <<EOF>>               driver.error(driver.loc, "unterminated string"); yy_pop_state(yyscanner);
  \\.                   { driver.error(driver.loc, std::string("invalid escape character '") +
                                            yytext + "'"); }
  .                     driver.error(driver.loc, "invalid character"); yy_pop_state(yyscanner);
}

struct|union|enum       {
                            yy_push_state(STRUCT, yyscanner);
                            driver.buffer.clear();
                            driver.struct_type = yytext;
                            return Parser::make_STRUCT(driver.loc);
                        }
<AFTER_COLON>{
  {hspace}+             { driver.loc.step(); }
  {vspace}+             { driver.loc.lines(yyleng); driver.loc.step(); }
  struct|union|enum     {
                          yy_pop_state(yyscanner);
                          yy_push_state(STRUCT_AFTER_COLON, yyscanner);
                          driver.buffer.clear();
                          driver.struct_type = yytext;
                          return Parser::make_STRUCT(driver.loc);
                        }
  .                     { unput(yytext[0]); yy_pop_state(yyscanner); }
}
<STRUCT_AFTER_COLON>{
  {hspace}+             { driver.loc.step(); }
  {vspace}+             { driver.loc.lines(yyleng); driver.loc.step(); }
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
                            for (int i = yyleng - 1; i >= 0; i--)
                              unput(yytext[i]);
                            return Parser::make_IDENT(driver.struct_type + " " + util::trim(driver.buffer), driver.loc);
                          }
                          driver.buffer += yytext[0];
                        }
  "{"                   yy_push_state(BRACE, yyscanner); driver.buffer += '{';
  "}"|"};"              {
                          driver.buffer += yytext;
                          yy_pop_state(yyscanner);
                          if (YY_START == STRUCT)
                          {
                            // Finished parsing a struct definition
                            // Trimming isn't needed here since the typenames
                            // will go through Clang before we get them back
                            // anyway.
                            yy_pop_state(yyscanner);
                            return Parser::make_STRUCT_DEFN(driver.struct_type + driver.buffer, driver.loc);
                          }
                        }
  .                     driver.buffer += yytext[0];
  \n                    driver.buffer += '\n'; driver.loc.lines(1); driver.loc.step();
}

{ident}                 {
                          static int unput_count = 0;
                          if (driver.bpftrace.macros_.count(yytext) != 0)
                          {
                            const char *s = driver.bpftrace.macros_.find(yytext)->second.c_str();
                            int z;
                            // NOTE(mmarchini) workaround for simple recursive
                            // macros. More complex recursive macros (for
                            // example, with operators) will go into an
                            // infinite loop. Yes, we should fix that in the
                            // future.
                            if (strcmp(s, yytext) == 0)
                            {
                              unput_count = 0;
                              return Parser::make_IDENT(yytext, driver.loc);
                            }
                            else
                            {
                              std::string original_s(s);
                              std::string original_yytext(yytext);
                              for (z=strlen(s) - 1; z >= 0; z--) {
                                if (unput_count >= 1000) {
                                  driver.error(driver.loc, std::string("Macro recursion limit reached: ")
                                                    + original_yytext + ", " + original_s);
                                  yyterminate();
                                }
                                unput(s[z]);
                                unput_count++;
                              }
                            }
                          } else {
                            unput_count = 0;
                            return Parser::make_IDENT(yytext, driver.loc);
                          }
                        }

.                       { driver.error(driver.loc, std::string("invalid character '") +
                                            std::string(yytext) + std::string("'")); }

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
