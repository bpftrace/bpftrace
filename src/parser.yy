%skeleton "lalr1.cc"
%require "3.0.4"
%defines
%define api.namespace { bpftrace }
// Pretend like the following %define is uncommented. We set the actual
// definition from cmake to handle older versions of bison.
// %define api.parser.class { Parser }
%define api.token.constructor
%define api.value.type variant
%define parse.assert
%define parse.trace
%expect 5

%define parse.error verbose

%param { bpftrace::Driver &driver }
%param { void *yyscanner }
%locations

// Forward declarations of classes referenced in the parser
%code requires
{
#include <cstdint>
#include <limits>
#include <regex>

namespace bpftrace {
class Driver;
namespace ast {
class Node;
} // namespace ast
} // namespace bpftrace
#include "ast/ast.h"
}

%{
#include <iostream>

#include "driver.h"
#include "lexer.h"

void yyerror(bpftrace::Driver &driver, const char *s);
%}

%token
  END 0      "end of file"
  COLON      ":"
  SEMI       ";"
  LBRACE     "{"
  RBRACE     "}"
  LBRACKET   "["
  RBRACKET   "]"
  LPAREN     "("
  RPAREN     ")"
  QUES       "?"
  ENDPRED    "end predicate"
  COMMA      ","
  PARAMCOUNT "$#"
  ASSIGN     "="
  EQ         "=="
  NE         "!="
  LE         "<="
  GE         ">="
  LEFT       "<<"
  RIGHT      ">>"
  LT         "<"
  GT         ">"
  LAND       "&&"
  LOR        "||"
  PLUS       "+"
  INCREMENT  "++"

  LEFTASSIGN   "<<="
  RIGHTASSIGN  ">>="
  PLUSASSIGN  "+="
  MINUSASSIGN "-="
  MULASSIGN   "*="
  DIVASSIGN   "/="
  MODASSIGN   "%="
  BANDASSIGN  "&="
  BORASSIGN   "|="
  BXORASSIGN  "^="

  MINUS      "-"
  DECREMENT  "--"
  MUL        "*"
  DIV        "/"
  MOD        "%"
  BAND       "&"
  BOR        "|"
  BXOR       "^"
  LNOT       "!"
  BNOT       "~"
  DOT        "."
  PTR        "->"
  IF         "if"
  ELSE       "else"
  UNROLL     "unroll"
  STRUCT     "struct"
  UNION      "union"
  WHILE      "while"
  CONFIG     "config"
  FOR        "for"
  RETURN     "return"
  CONTINUE   "continue"
  BREAK      "break"
  SIZEOF     "sizeof"
  OFFSETOF   "offsetof"
;

%token <std::string> BUILTIN "builtin"
%token <std::string> CALL "call"
%token <std::string> CALL_BUILTIN "call_builtin"
%token <std::string> INT_TYPE "integer type"
%token <std::string> BUILTIN_TYPE "builtin type"
%token <std::string> SIZED_TYPE "sized type"
%token <std::string> IDENT "identifier"
%token <std::string> PATH "path"
%token <std::string> CPREPROC "preprocessor directive"
%token <std::string> STRUCT_DEFN "struct definition"
%token <std::string> ENUM "enum"
%token <std::string> STRING "string"
%token <std::string> MAP "map"
%token <std::string> VAR "variable"
%token <std::string> PARAM "positional parameter"
%token <int64_t> INT "integer"
%token <std::string> STACK_MODE "stack_mode"


%type <ast::Operator> unary_op compound_op
%type <std::string> attach_point_def c_definitions ident

%type <ast::AttachPoint *> attach_point
%type <ast::AttachPointList *> attach_points
%type <ast::Call *> call
%type <ast::Sizeof *> sizeof_expr
%type <ast::Offsetof *> offsetof_expr
%type <ast::Expression *> and_expr addi_expr primary_expr cast_expr conditional_expr equality_expr expr logical_and_expr muli_expr
%type <ast::Expression *> logical_or_expr map_or_var or_expr postfix_expr relational_expr shift_expr tuple_access_expr unary_expr xor_expr
%type <ast::ExpressionList *> vargs
%type <ast::Integer *> int
%type <ast::Map *> map
%type <ast::PositionalParameter *> param
%type <ast::Predicate *> pred
%type <ast::Probe *> probe
%type <ast::ProbeList *> probes
%type <ast::Config *> config
%type <ast::Statement *> assign_stmt block_stmt expr_stmt if_stmt jump_stmt loop_stmt config_assign_stmt
%type <ast::StatementList *> block block_or_if stmt_list config_block config_assign_stmt_list
%type <SizedType> type int_type pointer_type struct_type
%type <ast::Variable *> var


%left COMMA
%right ASSIGN LEFTASSIGN RIGHTASSIGN PLUSASSIGN MINUSASSIGN MULASSIGN DIVASSIGN MODASSIGN BANDASSIGN BORASSIGN BXORASSIGN
%left QUES COLON
%left LOR
%left LAND
%left BOR
%left BXOR
%left BAND
%left EQ NE
%left LE GE LT GT
%left LEFT RIGHT
%left PLUS MINUS
%left MUL DIV MOD
%right LNOT BNOT
%left LPAREN RPAREN LBRACKET RBRACKET DOT PTR

%start program

%%

program:
                c_definitions config probes END { driver.root = std::make_unique<ast::Program>($1, $2, $3); }
                ;

c_definitions:
                CPREPROC c_definitions           { $$ = $1 + "\n" + $2; }
        |       STRUCT STRUCT_DEFN c_definitions { $$ = $2 + ";\n" + $3; }
        |       STRUCT ENUM c_definitions        { $$ = $2 + ";\n" + $3; }
        |       %empty                           { $$ = std::string(); }
                ;

type:
                int_type { $$ = $1; }
        |       BUILTIN_TYPE {
                    static std::unordered_map<std::string, SizedType> type_map = {
                        {"min_t", CreateMin(true)},
                        {"max_t", CreateMax(true)},
                        {"sum_t", CreateSum(true)},
                        {"count_t", CreateCount(true)},
                        {"avg_t", CreateAvg(true)},
                        {"stats_t", CreateStats(true)},
                        {"umin_t", CreateMin(false)},
                        {"umax_t", CreateMax(false)},
                        {"usum_t", CreateSum(false)},
                        {"ucount_t", CreateCount(false)},
                        {"uavg_t", CreateAvg(false)},
                        {"ustats_t", CreateStats(false)},
                        {"timestamp_t", CreateTimestamp()},
                        {"macaddr_t", CreateMacAddress()},
                        {"cgroup_path_t", CreateCgroupPath()},
                        {"strerror_t", CreateStrerror()},
                    };
                    $$ = type_map[$1];
                }
        |       SIZED_TYPE "[" INT "]" {
                    if ($1 == "str_t") {
                        $$ = CreateString($3);
                    } else if ($1 == "inet_t") {
                        $$ = CreateInet($3);
                    } else if ($1 == "buf_t") {
                        $$ = CreateBuffer($3);
                    }
                }
        |       int_type "[" INT "]" {
                  $$ = CreateArray($3, $1);
                }
        |       int_type "[" "]" {
                  $$ = CreateArray(0, $1);
                }
        |       pointer_type { $$ = $1; }
        |       struct_type { $$ = $1; }
                ;

int_type:
                INT_TYPE {
                    static std::unordered_map<std::string, SizedType> type_map = {
                        {"bool", CreateBool()},
                        {"uint8", CreateUInt(8)},
                        {"uint16", CreateUInt(16)},
                        {"uint32", CreateUInt(32)},
                        {"uint64", CreateUInt(64)},
                        {"int8", CreateInt(8)},
                        {"int16", CreateInt(16)},
                        {"int32", CreateInt(32)},
                        {"int64", CreateInt(64)},
                    };
                    $$ = type_map[$1];
                }
                ;

pointer_type:
                type "*" { $$ = CreatePointer($1); }
                ;
struct_type:
                STRUCT IDENT { $$ = ast::ident_to_record($2); }
                ;
                
config:
                CONFIG ASSIGN config_block     { $$ = new ast::Config($3); }
        |        %empty                        { $$ = nullptr; }
                ;

probes:
                probes probe { $$ = $1; $1->push_back($2); }
        |       probe        { $$ = new ast::ProbeList; $$->push_back($1); }
                ;

probe:
                attach_points pred block
                {
                  if (!driver.listing_)
                    $$ = new ast::Probe($1, $2, $3);
                  else
                  {
                    error(@$, "unexpected listing query format");
                    YYERROR;
                  }
                }
        |       attach_points END
                {
                  if (driver.listing_)
                    $$ = new ast::Probe($1, nullptr, nullptr);
                  else
                  {
                    error(@$, "unexpected end of file, expected {");
                    YYERROR;
                  }
                }
                ;

attach_points:
                attach_points "," attach_point { $$ = $1; $1->push_back($3); }
        |       attach_point                   { $$ = new ast::AttachPointList; $$->push_back($1); }
                ;

attach_point:
                attach_point_def                { $$ = new ast::AttachPoint($1, @$); }
                ;

attach_point_def:
                attach_point_def ident    { $$ = $1 + $2; }
                // Since we're double quoting the STRING for the benefit of the
                // AttachPointParser, we have to make sure we re-escape any double
                // quotes.
        |       attach_point_def STRING   { $$ = $1 + "\"" + std::regex_replace($2, std::regex("\""), "\\\"") + "\""; }
        |       attach_point_def PATH     { $$ = $1 + $2; }
        |       attach_point_def INT      { $$ = $1 + std::to_string($2); }
        |       attach_point_def COLON    { $$ = $1 + ":"; }
        |       attach_point_def DOT      { $$ = $1 + "."; }
        |       attach_point_def PLUS     { $$ = $1 + "+"; }
        |       attach_point_def MUL      { $$ = $1 + "*"; }
        |       attach_point_def LBRACKET { $$ = $1 + "["; }
        |       attach_point_def RBRACKET { $$ = $1 + "]"; }
        |       attach_point_def param
                {
                  if ($2->ptype != PositionalParameterType::positional)
                  {
                    error(@$, "Not a positional parameter");
                    YYERROR;
                  }
                  // "Un-parse" the positional parameter back into text so
                  // we can give it to the AttachPointParser. This is kind of
                  // a hack but there doesn't look to be any other way.
                  $$ = $1 + "$" + std::to_string($2->n);
                  delete $2;
                }
        |       %empty                    { $$ = ""; }
                ;

pred:
                DIV expr ENDPRED { $$ = new ast::Predicate($2, @$); }
        |        %empty           { $$ = nullptr; }
                ;


param:
                PARAM {
                        try {
                          long n = std::stol($1.substr(1, $1.size()-1));
                          if (n == 0) throw std::exception();
                          $$ = new ast::PositionalParameter(PositionalParameterType::positional, n, @$);
                        } catch (std::exception const& e) {
                          error(@1, "param " + $1 + " is out of integer range [1, " +
                                std::to_string(std::numeric_limits<long>::max()) + "]");
                          YYERROR;
                        }
                      }
        |       PARAMCOUNT { $$ = new ast::PositionalParameter(PositionalParameterType::count, 0, @$); }
                ;

block:
                "{" stmt_list "}"     { $$ = $2; }
                ;
                
config_block:   "{" config_assign_stmt_list "}"     { $$ = $2; }
                ;

stmt_list:
/*
 * expressions must be followed by a semicolon _unless_ its the last one
 */
                expr_stmt ";" stmt_list { $$ = $3; $3->insert($3->begin(), $1); }
        |       expr_stmt               { $$ = new ast::StatementList; $$->push_back($1); }
/*
 * blocks can't be followed by semicolon
 */
        |       block_stmt stmt_list    { $$ = $2; $2->insert($2->begin(), $1); }
        |       %empty                  { $$ = new ast::StatementList; }
                ;
                
config_assign_stmt_list:
                config_assign_stmt ";" config_assign_stmt_list { $$ = $3; $3->insert($3->begin(), $1); }
        |       config_assign_stmt                             { $$ = new ast::StatementList; $$->push_back($1); }
                ;

block_stmt:
                loop_stmt    { $$ = $1; }
        |       if_stmt      { $$ = $1; }
                ;

expr_stmt:
                expr               { $$ = new ast::ExprStatement($1, @1); }
        |       jump_stmt          { $$ = $1; }
/*
 * quirk. Assignment is not an expression but the AssignMapStatement makes it difficult
 * this avoids a r/r conflict
 */
        |       assign_stmt        { $$ = $1; }
                ;

jump_stmt:
                BREAK    { $$ = new ast::Jump(ast::JumpType::BREAK, @$); }
        |       CONTINUE { $$ = new ast::Jump(ast::JumpType::CONTINUE, @$); }
        |       RETURN   { $$ = new ast::Jump(ast::JumpType::RETURN, @$); }
                ;

loop_stmt:
                UNROLL "(" int ")" block             { $$ = new ast::Unroll($3, $5, @1 + @4); }
        |       UNROLL "(" param ")" block           { $$ = new ast::Unroll($3, $5, @1 + @4); }
        |       WHILE  "(" expr ")" block            { $$ = new ast::While($3, $5, @1); }
                ;

if_stmt:
                IF "(" expr ")" block                  { $$ = new ast::If($3, $5); }
        |       IF "(" expr ")" block ELSE block_or_if { $$ = new ast::If($3, $5, $7); }
                ;

block_or_if:
                block        { $$ = $1; }
        |       if_stmt      { $$ = new ast::StatementList; $$->emplace_back($1); }
                ;
                
config_assign_stmt:
                IDENT ASSIGN expr   { $$ = new ast::AssignConfigVarStatement($1, $3, @2); }

assign_stmt:
                tuple_access_expr ASSIGN expr
                {
                  error(@1 + @3, "Tuples are immutable once created. Consider creating a new tuple and assigning it instead.");
                  YYERROR;
                }
        |       map ASSIGN expr      { $$ = new ast::AssignMapStatement($1, $3, false, @2); }
        |       var ASSIGN expr      { $$ = new ast::AssignVarStatement($1, $3, false, @2); }
        |       map compound_op expr
                {
                  auto b = new ast::Binop($1, $2, $3, @2);
                  $$ = new ast::AssignMapStatement($1, b, true, @$);
                }
        |       var compound_op expr
                {
                  auto b = new ast::Binop($1, $2, $3, @2);
                  $$ = new ast::AssignVarStatement($1, b, true, @$);
                }
        ;

primary_expr:
                IDENT              { $$ = new ast::Identifier($1, @$); }
        |       int                { $$ = $1; }
        |       STRING             { $$ = new ast::String($1, @$); }
        |       STACK_MODE         { $$ = new ast::StackMode($1, @$); }
        |       BUILTIN            { $$ = new ast::Builtin($1, @$); }
        |       CALL_BUILTIN       { $$ = new ast::Builtin($1, @$); }
        |       LPAREN expr RPAREN { $$ = $2; }
        |       param              { $$ = $1; }
        |       map_or_var         { $$ = $1; }
        |       "("expr "," vargs ")"
                {
                  auto args = new ast::ExpressionList;
                  args->emplace_back($2);
                  args->insert(args->end(), $4->begin(), $4->end());
                  $$ = new ast::Tuple(args, @$);
                }
                ;

postfix_expr:
                primary_expr                { $$ = $1; }
/* pointer  */
        |       postfix_expr DOT ident    { $$ = new ast::FieldAccess($1, $3, @2); }
        |       postfix_expr PTR ident    { $$ = new ast::FieldAccess(new ast::Unop(ast::Operator::MUL, $1, @2), $3, @$); }
/* tuple  */
        |       tuple_access_expr         { $$ = $1; }
/* array  */
        |       postfix_expr "[" expr "]" { $$ = new ast::ArrayAccess($1, $3, @2 + @4); }
        |       call                      { $$ = $1; }
        |       sizeof_expr               { $$ = $1; }
        |       offsetof_expr             { $$ = $1; }
        |       map_or_var INCREMENT      { $$ = new ast::Unop(ast::Operator::INCREMENT, $1, true, @2); }
        |       map_or_var DECREMENT      { $$ = new ast::Unop(ast::Operator::DECREMENT, $1, true, @2); }
/* errors */
        |       INCREMENT ident           { error(@1, "The ++ operator must be applied to a map or variable"); YYERROR; }
        |       DECREMENT ident           { error(@1, "The -- operator must be applied to a map or variable"); YYERROR; }
                ;

/* Tuple factored out so we can use it in the tuple field assignment error */
tuple_access_expr:
                postfix_expr DOT INT      { $$ = new ast::FieldAccess($1, $3, @3); }
                ;



unary_expr:
                unary_op cast_expr   { $$ = new ast::Unop($1, $2, @1); }
        |       postfix_expr         { $$ = $1; }
        |       INCREMENT map_or_var { $$ = new ast::Unop(ast::Operator::INCREMENT, $2, @1); }
        |       DECREMENT map_or_var { $$ = new ast::Unop(ast::Operator::DECREMENT, $2, @1); }
/* errors */
        |       ident DECREMENT      { error(@1, "The -- operator must be applied to a map or variable"); YYERROR; }
        |       ident INCREMENT      { error(@1, "The ++ operator must be applied to a map or variable"); YYERROR; }
                ;

unary_op:
                MUL    { $$ = ast::Operator::MUL; }
        |       BNOT   { $$ = ast::Operator::BNOT; }
        |       LNOT   { $$ = ast::Operator::LNOT; }
        |       MINUS  { $$ = ast::Operator::MINUS; }
                ;

expr:
                conditional_expr    { $$ = $1; }
                ;

conditional_expr:
                logical_or_expr                                  { $$ = $1; }
        |       logical_or_expr QUES expr COLON conditional_expr { $$ = new ast::Ternary($1, $3, $5, @$); }
                ;


logical_or_expr:
                logical_and_expr                     { $$ = $1; }
        |       logical_or_expr LOR logical_and_expr { $$ = new ast::Binop($1, ast::Operator::LOR, $3, @2); }
                ;

logical_and_expr:
                or_expr                       { $$ = $1; }
        |       logical_and_expr LAND or_expr { $$ = new ast::Binop($1, ast::Operator::LAND, $3, @2); }
                ;

or_expr:
                xor_expr             { $$ = $1; }
        |       or_expr BOR xor_expr { $$ = new ast::Binop($1, ast::Operator::BOR, $3, @2); }
                ;

xor_expr:
                and_expr               { $$ = $1; }
        |       xor_expr BXOR and_expr { $$ = new ast::Binop($1, ast::Operator::BXOR, $3, @2); }
                ;


and_expr:
                equality_expr               { $$ = $1; }
        |       and_expr BAND equality_expr { $$ = new ast::Binop($1, ast::Operator::BAND, $3, @2); }
                ;

equality_expr:
                relational_expr                  { $$ = $1; }
        |       equality_expr EQ relational_expr { $$ = new ast::Binop($1, ast::Operator::EQ, $3, @2); }
        |       equality_expr NE relational_expr { $$ = new ast::Binop($1, ast::Operator::NE, $3, @2); }
                ;

relational_expr:
                shift_expr                    { $$ = $1; }
        |       relational_expr LE shift_expr { $$ = new ast::Binop($1, ast::Operator::LE, $3, @2); }
        |       relational_expr GE shift_expr { $$ = new ast::Binop($1, ast::Operator::GE, $3, @2); }
        |       relational_expr LT shift_expr { $$ = new ast::Binop($1, ast::Operator::LT, $3, @2); }
        |       relational_expr GT shift_expr { $$ = new ast::Binop($1, ast::Operator::GT, $3, @2); }
                ;

shift_expr:
                addi_expr                  { $$ = $1; }
        |       shift_expr LEFT addi_expr  { $$ = new ast::Binop($1, ast::Operator::LEFT, $3, @2); }
        |       shift_expr RIGHT addi_expr { $$ = new ast::Binop($1, ast::Operator::RIGHT, $3, @2); }
                ;

muli_expr:
                cast_expr                  { $$ = $1; }
        |       muli_expr MUL cast_expr    { $$ = new ast::Binop($1, ast::Operator::MUL, $3, @2); }
        |       muli_expr DIV cast_expr    { $$ = new ast::Binop($1, ast::Operator::DIV, $3, @2); }
        |       muli_expr MOD cast_expr    { $$ = new ast::Binop($1, ast::Operator::MOD, $3, @2); }
                ;

addi_expr:
                muli_expr                  { $$ = $1; }
        |       addi_expr PLUS muli_expr   { $$ = new ast::Binop($1, ast::Operator::PLUS, $3, @2); }
        |       addi_expr MINUS muli_expr  { $$ = new ast::Binop($1, ast::Operator::MINUS, $3, @2); }
                ;

cast_expr:
                unary_expr                                  { $$ = $1; }
        |       LPAREN type RPAREN cast_expr                { $$ = new ast::Cast($2, $4, @1 + @3); }
/* workaround for typedef types, see https://github.com/bpftrace/bpftrace/pull/2560#issuecomment-1521783935 */
        |       LPAREN IDENT RPAREN cast_expr               { $$ = new ast::Cast(ast::ident_to_record($2, 0), $4, @1 + @3); }
        |       LPAREN IDENT "*" RPAREN cast_expr           { $$ = new ast::Cast(ast::ident_to_record($2, 1), $5, @1 + @4); }
        |       LPAREN IDENT "*" "*" RPAREN cast_expr       { $$ = new ast::Cast(ast::ident_to_record($2, 2), $6, @1 + @5); }
                ;

sizeof_expr:
                SIZEOF "(" type ")"                         { $$ = new ast::Sizeof($3, @$); }
        |       SIZEOF "(" expr ")"                         { $$ = new ast::Sizeof($3, @$); }
                ;

offsetof_expr:
                OFFSETOF "(" struct_type "," ident ")"      { $$ = new ast::Offsetof($3, $5, @$); }
/* For example: offsetof(*curtask, comm) */
        |       OFFSETOF "(" expr "," ident ")"             { $$ = new ast::Offsetof($3, $5, @$); }
                ;

int:
                MINUS INT    { $$ = new ast::Integer((int64_t)(~(uint64_t)($2) + 1), @$); }
        |       INT          { $$ = new ast::Integer($1, @$); }
                ;

ident:
                IDENT         { $$ = $1; }
        |       BUILTIN       { $$ = $1; }
        |       CALL          { $$ = $1; }
        |       CALL_BUILTIN  { $$ = $1; }
        |       STACK_MODE    { $$ = $1; }
                ;

call:
                CALL "(" ")"                 { $$ = new ast::Call($1, @$); }
        |       CALL "(" vargs ")"           { $$ = new ast::Call($1, $3, @$); }
        |       CALL_BUILTIN  "(" ")"        { $$ = new ast::Call($1, @$); }
        |       CALL_BUILTIN "(" vargs ")"   { $$ = new ast::Call($1, $3, @$); }
        |       IDENT "(" ")"                { error(@1, "Unknown function: " + $1); YYERROR;  }
        |       IDENT "(" vargs ")"          { error(@1, "Unknown function: " + $1); YYERROR;  }
        |       BUILTIN "(" ")"              { error(@1, "Unknown function: " + $1); YYERROR;  }
        |       BUILTIN "(" vargs ")"        { error(@1, "Unknown function: " + $1); YYERROR;  }
        |       STACK_MODE "(" ")"           { error(@1, "Unknown function: " + $1); YYERROR;  }
        |       STACK_MODE "(" vargs ")"     { error(@1, "Unknown function: " + $1); YYERROR;  }
                ;

map:
                MAP               { $$ = new ast::Map($1, @$); }
        |       MAP "[" vargs "]" { $$ = new ast::Map($1, $3, @$); }
                ;

var:
                VAR { $$ = new ast::Variable($1, @$); }
                ;

map_or_var:
                var { $$ = $1; }
        |       map { $$ = $1; }
                ;

vargs:
                vargs "," expr { $$ = $1; $1->push_back($3); }
        |       expr           { $$ = new ast::ExpressionList; $$->push_back($1); }
                ;

compound_op:
                LEFTASSIGN   { $$ = ast::Operator::LEFT; }
        |       BANDASSIGN   { $$ = ast::Operator::BAND; }
        |       BORASSIGN    { $$ = ast::Operator::BOR; }
        |       BXORASSIGN   { $$ = ast::Operator::BXOR; }
        |       DIVASSIGN    { $$ = ast::Operator::DIV; }
        |       MINUSASSIGN  { $$ = ast::Operator::MINUS; }
        |       MODASSIGN    { $$ = ast::Operator::MOD; }
        |       MULASSIGN    { $$ = ast::Operator::MUL; }
        |       PLUSASSIGN   { $$ = ast::Operator::PLUS; }
        |       RIGHTASSIGN  { $$ = ast::Operator::RIGHT; }
                ;

%%

void bpftrace::Parser::error(const location &l, const std::string &m)
{
  driver.error(l, m);
}
