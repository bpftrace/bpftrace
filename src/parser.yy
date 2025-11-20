%skeleton "lalr1.cc"
%require "3.0.4"
%defines
%define api.namespace { bpftrace }
// Pretend like the following %define is uncommented. We set the actual
// definition from cmake to handle older versions of bison.
// %define api.parser.class { Parser }
%define api.location.type { ast::SourceLocation }
%define api.token.constructor
%define api.value.type variant
%define parse.assert
%define parse.trace
%expect 0

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
#include "ast/context.h"
#include "ast/location.h"
#include "util/int_parser.h"
#include "util/strings.h"
}

%{
#include <iostream>

#include "driver.h"
#include "parser.tab.hh"

YY_DECL;

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
  STRUCT     "struct"
  UNION      "union"
  UNDERSCORE "_"

  // Pseudo token; see below.
  LOW "low-precedence"
;

%token <std::string> BUILTIN "builtin"
%token <std::string> INT_TYPE "integer type"
%token <std::string> BUILTIN_TYPE "builtin type"
%token <std::string> SUBPROG "subprog"
%token <std::string> MACRO "macro"
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
%token <std::string> UNSIGNED_INT "integer"
%token <std::string> CONFIG "config"
%token <std::string> UNROLL "unroll"
%token <std::string> WHILE "while"
%token <std::string> FOR "for"
%token <std::string> RETURN "return"
%token <std::string> IF "if"
%token <std::string> ELSE "else"
%token <std::string> CONTINUE "continue"
%token <std::string> BREAK "break"
%token <std::string> SIZEOF "sizeof"
%token <std::string> OFFSETOF "offsetof"
%token <std::string> TYPEOF "typeof"
%token <std::string> TYPEINFO "typeinfo"
%token <std::string> COMPTIME "comptime"
%token <std::string> LET "let"
%token <std::string> IMPORT "import"
%token <std::string> HEADER "header"
%token <bool> BOOL "bool"

%type <ast::Operator> unary_op compound_op
%type <std::string> attach_point_def attach_point_elem ident keyword external_name
%type <std::vector<std::string>> struct_field

%type <ast::ArrayAccess *> array_access_expr
%type <ast::AttachPoint *> attach_point
%type <ast::AttachPointList> attach_points
%type <ast::BlockExpr *> none_block bare_block block_expr
%type <ast::Call *> call_expr
%type <ast::Cast *> cast_expr
%type <ast::Comptime *> comptime_expr
%type <ast::CStatementList> c_definitions
%type <ast::Sizeof *> sizeof_expr
%type <ast::Offsetof *> offsetof_expr
%type <ast::Typeof *> typeof_expr any_type
%type <ast::Expression> expr non_if_expr cond_expr unary_expr primary_expr prefix_expr postfix_expr
%type <ast::ExpressionList> vargs
%type <ast::FieldAccess *> field_access_expr
%type <ast::SubprogArg *> subprog_arg
%type <ast::SubprogArgList> subprog_args
%type <ast::ExpressionList> macro_args
%type <ast::Map *> map
%type <ast::MapAccess *> map_expr
%type <ast::PositionalParameter *> param
%type <ast::PositionalParameterCount *> param_count
%type <std::optional<ast::Expression>> pred
%type <ast::Config *> config
%type <ast::Integer *> integer
%type <ast::Import *> import_stmt
%type <ast::ImportList> imports
%type <ast::Statement> assign_stmt block_stmt expr_stmt nonexpr_stmt jump_stmt while_stmt for_stmt
%type <ast::StatementList> stmt_list
%type <ast::IfExpr *> if_stmt if_expr
%type <ast::RootStatement> root_stmt macro map_decl_stmt subprog probe
%type <ast::RootStatements> root_stmts
%type <ast::Range *> range
%type <ast::Typeinfo *> typeinfo_expr
%type <ast::Tuple *> tuple_expr
%type <ast::TupleAccess *> tuple_access_expr
%type <ast::VarDeclStatement *> var_decl_stmt
%type <ast::AssignConfigVarStatement *> config_assign_stmt
%type <ast::ConfigStatementList> config_assign_stmt_list config_block
%type <SizedType> type int_type pointer_type struct_type
%type <ast::Variable *> var
%type <ast::VariableAddr *> var_addr
%type <ast::MapAddr *> map_addr
%type <ast::Program *> program
%type <std::string> header c_struct


// A pseudo token, which is the lowest precedence among all tokens.
//
// This helps us explicitly lower the precedence of a given rule to force shift
// vs. reduce, and make the grammar explicit (still ambiguous, but explicitly
// ambiguous). For example, consider the inherently ambiguous `@foo[..]`, which
// could be interpreted as accessing the `@foo` non-scalar map, or indexing
// into the value of the `@foo` scalar map, e.g. `(@foo)[...]`. We lower the
// precedence of the associated rules to ensure that this is shifted, and the
// longer `map_expr` rule will match over the `map` rule in this case.
%left LOW

%left COMPTIME
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
%left DOT PTR
%right PAREN RPAREN
%right LBRACKET RBRACKET

// In order to support the parsing of full programs and the parsing of just
// expressions (used while expanding C macros, for example), use the trick
// described in Bison's FAQ [1].
// [1] https://www.gnu.org/software/bison/manual/html_node/Multiple-start_002dsymbols.html
%token START_PROGRAM "program"
%token START_EXPR "expression"
%start start

%%

start:          START_PROGRAM program { driver.result = $2; }
        |       START_EXPR expr END   { driver.result = $2; }
                ;

header:
                HEADER { auto s = $1; $$ = util::rtrim(s); }
        |       %empty { $$ = ""; }

program:
                header c_definitions config imports root_stmts END {
                    $$ = driver.ctx.make_node<ast::Program>(@$, std::move($2), $3, std::move($4), std::move($5), $1);
                }
                ;

c_struct:       STRUCT STRUCT_DEFN { $$ = $2; }
        |       STRUCT ENUM        { $$ = $2; }
                ;

c_definitions:
                c_definitions CPREPROC
                {
                    $$ = std::move($1);
                    auto s = util::rtrim($2);
                    $$.push_back(driver.ctx.make_node<ast::CStatement>(driver.loc, s));
                }
        |       c_definitions c_struct  {
                    $$ = std::move($1);
                    auto s = util::rtrim($2);
                    if (!s.empty() && s.back() != ';') {
                      s += ";";
                    }
                    $$.push_back(driver.ctx.make_node<ast::CStatement>(driver.loc, s));
                }
        |       %empty { $$ = ast::CStatementList(); }
                ;

imports:
                imports import_stmt { $$ = std::move($1); $$.push_back($2); }
        |       %empty              { $$ = ast::ImportList{}; }
                ;

import_stmt:
                IMPORT STRING ";" { $$ = driver.ctx.make_node<ast::Import>(@$, $2); }
                ;

type:
                int_type { $$ = $1; }
        |       BUILTIN_TYPE {
                    static std::unordered_map<std::string, SizedType> type_map = {
                        {"void", CreateVoid()},
                        {"min_t", CreateMin(true)},
                        {"max_t", CreateMax(true)},
                        {"sum_t", CreateSum(true)},
                        {"count_t", CreateCount()},
                        {"avg_t", CreateAvg(true)},
                        {"stats_t", CreateStats(true)},
                        {"umin_t", CreateMin(false)},
                        {"umax_t", CreateMax(false)},
                        {"usum_t", CreateSum(false)},
                        {"uavg_t", CreateAvg(false)},
                        {"ustats_t", CreateStats(false)},
                        {"timestamp", CreateTimestamp()},
                        {"macaddr_t", CreateMacAddress()},
                        {"cgroup_path_t", CreateCgroupPath()},
                    };
                    $$ = type_map[$1];
                }
        |       SIZED_TYPE {
                    if ($1 == "inet") {
                        $$ = CreateInet(0);
                    } else if ($1 == "buffer") {
                        $$ = CreateBuffer(0);
                    } else if ($1 == "string") {
                        $$ = CreateString(0);
                    }
                }
        |       SIZED_TYPE "[" integer "]" {
                    if ($1 == "inet") {
                        $$ = CreateInet($3->value);
                    } else if ($1 == "buffer") {
                        $$ = CreateBuffer($3->value);
                    } else if ($1 == "string") {
                        $$ = CreateString($3->value);
                    }
                }
        |       int_type "[" integer "]" {
                  $$ = CreateArray($3->value, $1);
                }
        |       struct_type "[" integer "]" {
                  $$ = CreateArray($3->value, $1);
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
                STRUCT IDENT { $$ = ast::ident_to_sized_type($2); }
                ;

config:
                CONFIG ASSIGN config_block     { $$ = driver.ctx.make_node<ast::Config>(@$, std::move($3)); }
        |       %empty                         { $$ = nullptr; }
                ;

/*
 * The last statement in a config_block does not require a trailing semicolon.
 */
config_block:   "{" config_assign_stmt_list "}"                    { $$ = std::move($2); }
            |   "{" config_assign_stmt_list config_assign_stmt "}" { $$ = std::move($2); $$.push_back($3); }
                ;

config_assign_stmt_list:
                config_assign_stmt_list config_assign_stmt ";" { $$ = std::move($1); $$.push_back($2); }
        |       %empty                                         { $$ = ast::ConfigStatementList{}; }
                ;

config_assign_stmt:
                IDENT ASSIGN integer { $$ = driver.ctx.make_node<ast::AssignConfigVarStatement>(@$, $1, $3->value); }
        |       IDENT ASSIGN IDENT   { $$ = driver.ctx.make_node<ast::AssignConfigVarStatement>(@$, $1, $3); }
        |       IDENT ASSIGN STRING  { $$ = driver.ctx.make_node<ast::AssignConfigVarStatement>(@$, $1, $3); }
        |       IDENT ASSIGN BOOL    { $$ = driver.ctx.make_node<ast::AssignConfigVarStatement>(@$, $1, $3); }
                ;

subprog:
                SUBPROG IDENT "(" subprog_args ")" ":" any_type none_block {
                    $$ = driver.ctx.make_node<ast::Subprog>(@1+@2, $2, $7, std::move($4), std::move($8));
                }
        |       SUBPROG IDENT "(" ")" ":" any_type none_block {
                    $$ = driver.ctx.make_node<ast::Subprog>(@1+@2, $2, $6, ast::SubprogArgList(), std::move($7));
                }
                ;

subprog_args:
                subprog_args "," subprog_arg { $$ = std::move($1); $$.push_back($3); }
        |       subprog_arg                  { $$ = ast::SubprogArgList{$1}; }
                ;

subprog_arg:
                var ":" any_type { $$ = driver.ctx.make_node<ast::SubprogArg>(@$, $1, $3); }
                ;

macro:
                MACRO IDENT "(" macro_args ")" block_expr { $$ = driver.ctx.make_node<ast::Macro>(@1+@2, $2, std::move($4), $6); }
        |       MACRO IDENT "(" macro_args ")" bare_block { $$ = driver.ctx.make_node<ast::Macro>(@1+@2, $2, std::move($4), $6); }
                ;

macro_args:
                macro_args "," map   { $$ = std::move($1); $$.push_back($3); }
        |       macro_args "," var   { $$ = std::move($1); $$.push_back($3); }
        |       macro_args "," ident { $$ = std::move($1); $$.push_back(driver.ctx.make_node<ast::Identifier>(@$, $3)); }
        |       map                  { $$ = ast::ExpressionList{$1}; }
        |       var                  { $$ = ast::ExpressionList{$1}; }
        |       ident                { $$ = ast::ExpressionList{driver.ctx.make_node<ast::Identifier>(@$, $1)}; }
        |       %empty               { $$ = ast::ExpressionList{}; }
                ;

root_stmts:
                root_stmts root_stmt { $$ = std::move($1); $$.push_back($2); }
        |       %empty               { $$ = ast::RootStatements{}; }

root_stmt:
                macro         { $$ = $1; }
        |       map_decl_stmt { $$ = $1; }
        |       subprog       { $$ = $1; }
        |       probe         { $$ = $1; }
                ;

probe:
                attach_points pred none_block
                {
                  auto *block = $3;
                  if ($2.has_value()) {
                    // If there a predicate, consider this as an `if` statement
                    // over the full block. This simplifies all later steps, and
                    // the predicate may still be folded, eliminating the probe.
                    auto *none = driver.ctx.make_node<ast::None>(@2);
                    auto *cond = driver.ctx.make_node<ast::IfExpr>(@2, $2.value(), block, none);
                    block = driver.ctx.make_node<ast::BlockExpr>(@2+@3, ast::StatementList{}, cond);
                  }
                  $$ = driver.ctx.make_node<ast::Probe>(@1, std::move($1), block);
                }
                ;

attach_points:
                attach_points "," attach_point { $$ = std::move($1); $$.push_back($3); }
        |       attach_points ","              { $$ = std::move($1); }
        |       attach_point                   { $$ = ast::AttachPointList{$1}; }
                ;

attach_point:
                attach_point_def               { $$ = driver.ctx.make_node<ast::AttachPoint>(@$, $1, false); }
                ;

attach_point_def:
                attach_point_elem                  { $$ = $1; }
        |       attach_point_def attach_point_elem { $$ = $1 + $2; }
                ;

attach_point_elem:
                ident        { $$ = $1; }
                // Since we're double quoting the STRING for the benefit of the
                // AttachPointParser, we have to make sure we re-escape any double
                // quotes. Note that this is a general escape hatch for many cases,
                // since we can't handle the general parsing and unparsing of e.g.
                // integer types that use `_` separators, or exponential notation,
                // or hex vs. non-hex representation etc.
        |       STRING       { $$ = "\"" + std::regex_replace($1, std::regex("\""), "\\\"") + "\""; }
        |       UNSIGNED_INT { $$ = $1; }
        |       PATH         { $$ = $1; }
        |       COLON        { $$ = ":"; }
        |       DOT          { $$ = "."; }
        |       PLUS         { $$ = "+"; }
        |       MUL          { $$ = "*"; }
        |       LBRACKET     { $$ = "["; }
        |       RBRACKET     { $$ = "]"; }
        |       EQ           { $$ = "="; }
        |       param
                {
                  // "Un-parse" the positional parameter back into text so
                  // we can give it to the AttachPointParser. This is kind of
                  // a hack but there doesn't look to be any other way.
                  $$ = "$" + std::to_string($1->n);
                }
                ;

pred:
                DIV expr ENDPRED { $$ = $2; }
        |       %empty           { $$ = std::nullopt; }
                ;


param:
                PARAM {
                        try {
                          long n = std::stol($1.substr(1, $1.size()-1));
                          if (n == 0) throw std::exception();
                          $$ = driver.ctx.make_node<ast::PositionalParameter>(@$, n);
                        } catch (std::exception const& e) {
                          error(@1, "param " + $1 + " is out of integer range [1, " +
                                std::to_string(std::numeric_limits<long>::max()) + "]");
                          YYERROR;
                        }
                      }
                ;

param_count:
                PARAMCOUNT { $$ = driver.ctx.make_node<ast::PositionalParameterCount>(@$); }
                ;

stmt_list:
                stmt_list expr_stmt ";"     { $$ = std::move($1); $$.push_back($2); }
        |       stmt_list nonexpr_stmt ";"  { $$ = std::move($1); $$.push_back($2); }
        |       stmt_list block_stmt        { $$ = std::move($1); $$.push_back($2); }
        |       stmt_list import_stmt       { $$ = std::move($1); $$.push_back($2); }
        |       %empty                      { $$ = ast::StatementList{}; }
                ;

block_stmt:
                while_stmt { $$ = $1; }
        |       if_stmt    { $$ = driver.ctx.make_node<ast::ExprStatement>(@$, $1); }
        |       for_stmt   { $$ = $1; }
        |       bare_block { $$ = driver.ctx.make_node<ast::ExprStatement>(@$, $1); }
                ;

expr_stmt:
                // We do not accept a top-level if for the statement, as we parse using
                // `if_stmt` to avoid ambiguity. The `expr` node itself will accept an
                // `if_expr`, which is used for any other expression except the statement.
                non_if_expr { $$ = driver.ctx.make_node<ast::ExprStatement>(@1, $1); }
                ;

nonexpr_stmt:
                jump_stmt        { $$ = $1; }
        |       assign_stmt      { $$ = $1; }
        |       var_decl_stmt    { $$ = $1; }
                ;

jump_stmt:
                BREAK       { $$ = driver.ctx.make_node<ast::Jump>(@$, ast::JumpType::BREAK); }
        |       CONTINUE    { $$ = driver.ctx.make_node<ast::Jump>(@$, ast::JumpType::CONTINUE); }
        |       RETURN      { $$ = driver.ctx.make_node<ast::Jump>(@$, ast::JumpType::RETURN); }
        |       RETURN expr { $$ = driver.ctx.make_node<ast::Jump>(@$, ast::JumpType::RETURN, $2); }
                ;

cond_expr:
                unary_expr { $$ = $1; }
        |       comptime_expr { $$ = $1; }
                ;

while_stmt:
                UNROLL cond_expr none_block { $$ = driver.ctx.make_node<ast::Unroll>(@1 + @2, $2, $3); }
        |       WHILE  cond_expr none_block { $$ = driver.ctx.make_node<ast::While>(@1, $2, $3); }
                ;

for_stmt:
                FOR "(" var ":" map ")" none_block   { $$ = driver.ctx.make_node<ast::For>(@1, $3, $5, std::move($7)); }
        |       FOR var ":" map none_block           { $$ = driver.ctx.make_node<ast::For>(@1, $2, $4, std::move($5)); }
        |       FOR "(" var ":" range ")" none_block { $$ = driver.ctx.make_node<ast::For>(@1, $3, $5, std::move($7)); }
        |       FOR var ":" range none_block         { $$ = driver.ctx.make_node<ast::For>(@1, $2, $4, std::move($5)); }
                ;

range:
                primary_expr DOT DOT primary_expr { $$ = driver.ctx.make_node<ast::Range>(@$, $1, $4); }
                ;

if_stmt:
                IF cond_expr none_block                 { $$ = driver.ctx.make_node<ast::IfExpr>(@$, $2, $3, driver.ctx.make_node<ast::None>(@1)); }
        |       IF cond_expr bare_block ELSE none_block { $$ = driver.ctx.make_node<ast::IfExpr>(@$, $2, $3, $5); }
        |       IF cond_expr bare_block ELSE if_stmt    { $$ = driver.ctx.make_node<ast::IfExpr>(@$, $2, $3, $5); }
        |       IF cond_expr bare_block ELSE if_expr
                {
                  // This is a pure statement; override the value with `none`.
                  auto *stmt = driver.ctx.make_node<ast::ExprStatement>(@5, $5);
                  auto *none = driver.ctx.make_node<ast::None>(@4);
                  auto *block = driver.ctx.make_node<ast::BlockExpr>(@5, ast::StatementList{ stmt }, none);
                  $$ = driver.ctx.make_node<ast::IfExpr>(@$, $2, $3, block);
                }
                ;

if_expr:
                IF cond_expr block_expr ELSE if_expr    { $$ = driver.ctx.make_node<ast::IfExpr>(@$, $2, $3, $5); }
        |       IF cond_expr block_expr ELSE block_expr { $$ = driver.ctx.make_node<ast::IfExpr>(@$, $2, $3, $5); }
                ;

assign_stmt:
                tuple_access_expr ASSIGN expr
                {
                  error(@1 + @3, "Tuples are immutable once created. Consider creating a new tuple and assigning it instead.");
                  YYERROR;
                }
        |       map ASSIGN expr           { $$ = driver.ctx.make_node<ast::AssignScalarMapStatement>(@$, $1, $3); }
        |       map_expr ASSIGN expr      { $$ = driver.ctx.make_node<ast::AssignMapStatement>(@$, $1, $3); }
        |       var_decl_stmt ASSIGN expr { $$ = driver.ctx.make_node<ast::AssignVarStatement>(@$, $1, $3); }
        |       var ASSIGN expr           { $$ = driver.ctx.make_node<ast::AssignVarStatement>(@$, $1, $3); }
        |       UNDERSCORE ASSIGN expr    { $$ = driver.ctx.make_node<ast::DiscardExpr>(@$, $3); }
        |       map compound_op expr
                {
                  auto b = driver.ctx.make_node<ast::Binop>(@2, $1, $2, $3);
                  $$ = driver.ctx.make_node<ast::AssignScalarMapStatement>(@$, $1, b);
                }
        |       map_expr compound_op expr
                {
                  auto b = driver.ctx.make_node<ast::Binop>(@2, $1, $2, $3);
                  $$ = driver.ctx.make_node<ast::AssignMapStatement>(@$, $1, b);
                }
        |       var compound_op expr
                {
                  auto b = driver.ctx.make_node<ast::Binop>(@2, $1, $2, $3);
                  $$ = driver.ctx.make_node<ast::AssignVarStatement>(@$, $1, b);
                }
        ;

map_decl_stmt:
                LET MAP ASSIGN IDENT LPAREN integer RPAREN ";" { $$ = driver.ctx.make_node<ast::MapDeclStatement>(@$, $2, $4, $6->value); }
        ;

var_decl_stmt:
                 LET var                {  $$ = driver.ctx.make_node<ast::VarDeclStatement>(@$, $2); }
        |        LET var COLON any_type {  $$ = driver.ctx.make_node<ast::VarDeclStatement>(@$, $2, $4); }
        ;

tuple_expr:
                "(" vargs "," expr ")"
                {
                  auto &args = $2;
                  args.push_back($4);
                  $$ = driver.ctx.make_node<ast::Tuple>(@$, std::move(args));
                }
        |       "(" vargs "," ")"
                {
                  // Tuple with a single element (possibly).
                  $$ = driver.ctx.make_node<ast::Tuple>(@$, std::move($2));
                }
        |       "(" ")"
                {
                  // Empty tuple.
                  $$ = driver.ctx.make_node<ast::Tuple>(@$, ast::ExpressionList({}));
                }
                ;

integer:
                UNSIGNED_INT
                {
                  auto res = util::to_uint($1, 0);
                  if (!res) {
                    std::stringstream ss;
                    ss << res.takeError();
                    error(@1, ss.str());
                    YYERROR;
                  } else {
                    // Construct with the original string, which will be preserved.
                    $$ = driver.ctx.make_node<ast::Integer>(@1, *res, std::move($1));
                  }
                }
                ;

primary_expr:
                LPAREN expr RPAREN { $$ = $2; }
        |       integer            { $$ = $1; }
        |       BOOL               { $$ = driver.ctx.make_node<ast::Boolean>(@$, $1); }
        |       STRING             { $$ = driver.ctx.make_node<ast::String>(@$, $1); }
        |       BUILTIN            { $$ = driver.ctx.make_node<ast::Builtin>(@$, $1); }
        |       param              { $$ = $1; }
        |       param_count        { $$ = $1; }
        |       var                { $$ = $1; }
        |       var_addr           { $$ = $1; }
        |       map_addr           { $$ = $1; }
        |       map_expr           { $$ = $1; }
        |       tuple_expr         { $$ = $1; }
        |       tuple_access_expr  { $$ = $1; }
        |       array_access_expr  { $$ = $1; }
        |       field_access_expr  { $$ = $1; }
        |       call_expr          { $$ = $1; }
        |       sizeof_expr        { $$ = $1; }
        |       offsetof_expr      { $$ = $1; }
        |       typeinfo_expr      { $$ = $1; }
        |       map %prec LOW      { $$ = $1; }
        |       IDENT %prec LOW    { $$ = driver.ctx.make_node<ast::Identifier>(@$, $1); }
                ;

prefix_expr:
                INCREMENT var        { $$ = driver.ctx.make_node<ast::Unop>(@1, $2, ast::Operator::PRE_INCREMENT); }
        |       DECREMENT var        { $$ = driver.ctx.make_node<ast::Unop>(@1, $2, ast::Operator::PRE_DECREMENT); }
        |       INCREMENT map        { $$ = driver.ctx.make_node<ast::Unop>(@1, $2, ast::Operator::PRE_INCREMENT); }
        |       DECREMENT map        { $$ = driver.ctx.make_node<ast::Unop>(@1, $2, ast::Operator::PRE_DECREMENT); }
        |       INCREMENT map_expr   { $$ = driver.ctx.make_node<ast::Unop>(@1, $2, ast::Operator::PRE_INCREMENT); }
        |       DECREMENT map_expr   { $$ = driver.ctx.make_node<ast::Unop>(@1, $2, ast::Operator::PRE_DECREMENT); }
/* errors */
        |       INCREMENT ident      { error(@1, "The ++ operator must be applied to a map or variable"); YYERROR; }
        |       DECREMENT ident      { error(@1, "The -- operator must be applied to a map or variable"); YYERROR; }
                ;

postfix_expr:
                var INCREMENT        { $$ = driver.ctx.make_node<ast::Unop>(@2, $1, ast::Operator::POST_INCREMENT); }
        |       var DECREMENT        { $$ = driver.ctx.make_node<ast::Unop>(@2, $1, ast::Operator::POST_DECREMENT); }
        |       map      INCREMENT   { $$ = driver.ctx.make_node<ast::Unop>(@2, $1, ast::Operator::POST_INCREMENT); }
        |       map      DECREMENT   { $$ = driver.ctx.make_node<ast::Unop>(@2, $1, ast::Operator::POST_DECREMENT); }
        |       map_expr INCREMENT   { $$ = driver.ctx.make_node<ast::Unop>(@2, $1, ast::Operator::POST_INCREMENT); }
        |       map_expr DECREMENT   { $$ = driver.ctx.make_node<ast::Unop>(@2, $1, ast::Operator::POST_DECREMENT); }
/* errors */
        |       ident DECREMENT      { error(@1, "The -- operator must be applied to a map or variable"); YYERROR; }
        |       ident INCREMENT      { error(@1, "The ++ operator must be applied to a map or variable"); YYERROR; }
                ;

tuple_access_expr:
                primary_expr DOT integer { $$ = driver.ctx.make_node<ast::TupleAccess>(@3, $1, $3->value); }
                ;

array_access_expr:
                primary_expr "[" expr "]" { $$ = driver.ctx.make_node<ast::ArrayAccess>(@2 + @4, $1, $3); }
                ;

field_access_expr:
                primary_expr DOT external_name { $$ = driver.ctx.make_node<ast::FieldAccess>(@2, $1, $3); }
        |       primary_expr PTR external_name { $$ = driver.ctx.make_node<ast::FieldAccess>(@2, $1, $3); }
                ;

block_expr:
                "{" stmt_list expr "}" { $$ = driver.ctx.make_node<ast::BlockExpr>(@$, std::move($2), $3); }
                ;

// This block is a bare list of statements, but it allows for a final statement
// without a trailing semi-colon, simply for convenience.
//
// For this rule, we can only accept a `nonexpr_stmt` since otherwise it would
// conflict with `block_expr`. The `none_block` rule merges `block_expr` and
// `bare_block` together (avoiding reduce conflicts) and ensuring that 1) any
// trailing statement is accepted without a semi-colon and 2) the expression
// and type of the block is always none.
bare_block:
                "{" stmt_list "}"
                {
                  auto *none = driver.ctx.make_node<ast::None>(@3);
                  $$ = driver.ctx.make_node<ast::BlockExpr>(@$, std::move($2), none);
                }
        |       "{" stmt_list nonexpr_stmt "}"
                {
                  auto stmts = std::move($2);
                  stmts.push_back($3);
                  auto *none = driver.ctx.make_node<ast::None>(@4);
                  $$ = driver.ctx.make_node<ast::BlockExpr>(@$, std::move(stmts), none);
                }
                ;

// See `bare_block` above. Note that this rule will always be have no
// expression and no type, but *allows* for a valid `block_expr` during
// parsing. It has to be factored to use the same grammar rule to avoid a
// reduce conflict.
none_block:
                bare_block { $$ = $1; }
        |       block_expr
                {
                  auto *none = driver.ctx.make_node<ast::None>(@1);
                  auto *stmt = driver.ctx.make_node<ast::ExprStatement>(@$, $1->expr);
                  $1->stmts.push_back(stmt);
                  $1->expr.value = none;
                  $$ = $1;
                }

cast_expr:
                LPAREN any_type RPAREN cast_expr           { $$ = driver.ctx.make_node<ast::Cast>(@1 + @3, $2, $4); }
        |       LPAREN any_type RPAREN unary_expr          { $$ = driver.ctx.make_node<ast::Cast>(@1 + @3, $2, $4); }
/* workaround for typedef types, see https://github.com/bpftrace/bpftrace/pull/2560#issuecomment-1521783935 */
        |       LPAREN IDENT RPAREN cast_expr          { $$ = driver.ctx.make_node<ast::Cast>(@1 + @3, driver.ctx.make_node<ast::Typeof>(@2, ast::ident_to_record($2, 0)), $4); }
        |       LPAREN IDENT RPAREN unary_expr         { $$ = driver.ctx.make_node<ast::Cast>(@1 + @3, driver.ctx.make_node<ast::Typeof>(@2, ast::ident_to_record($2, 0)), $4); }
        |       LPAREN IDENT "*" RPAREN cast_expr      { $$ = driver.ctx.make_node<ast::Cast>(@1 + @4, driver.ctx.make_node<ast::Typeof>(@2, ast::ident_to_record($2, 1)), $5); }
        |       LPAREN IDENT "*" RPAREN unary_expr     { $$ = driver.ctx.make_node<ast::Cast>(@1 + @4, driver.ctx.make_node<ast::Typeof>(@2, ast::ident_to_record($2, 1)), $5); }
        |       LPAREN IDENT "*" "*" RPAREN cast_expr  { $$ = driver.ctx.make_node<ast::Cast>(@1 + @5, driver.ctx.make_node<ast::Typeof>(@2, ast::ident_to_record($2, 2)), $6); }
        |       LPAREN IDENT "*" "*" RPAREN unary_expr { $$ = driver.ctx.make_node<ast::Cast>(@1 + @5, driver.ctx.make_node<ast::Typeof>(@2, ast::ident_to_record($2, 2)), $6); }
                ;

unary_expr:
                unary_op unary_expr    { $$ = driver.ctx.make_node<ast::Unop>(@1, $2, $1); }
        |       unary_op cast_expr     { $$ = driver.ctx.make_node<ast::Unop>(@1, $2, $1); }
        |       primary_expr           { $$ = $1; }
        |       prefix_expr            { $$ = $1; }
        |       postfix_expr           { $$ = $1; }
                ;

unary_op:
                MUL    { $$ = ast::Operator::MUL; }
        |       BNOT   { $$ = ast::Operator::BNOT; }
        |       LNOT   { $$ = ast::Operator::LNOT; }
        |       MINUS  { $$ = ast::Operator::MINUS; }
                ;

expr:
                non_if_expr { $$ = $1; }
        |       if_expr     { $$ = $1; }
                ;

non_if_expr:
                block_expr                { $$ = $1; }
        |       cast_expr                 { $$ = $1; }
        |       unary_expr                { $$ = $1; }
        |       comptime_expr             { $$ = $1; }
        |       expr QUES expr COLON expr { $$ = driver.ctx.make_node<ast::IfExpr>(@$, $1, $3, $5); }
        |       expr LOR expr             { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::LOR, $3); }
        |       expr LAND expr            { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::LAND, $3); }
        |       expr BOR expr             { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::BOR, $3); }
        |       expr BXOR expr            { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::BXOR, $3); }
        |       expr BAND expr            { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::BAND, $3); }
        |       expr EQ expr              { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::EQ, $3); }
        |       expr NE expr              { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::NE, $3); }
        |       expr LE expr              { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::LE, $3); }
        |       expr GE expr              { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::GE, $3); }
        |       expr LT expr              { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::LT, $3); }
        |       expr GT expr              { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::GT, $3); }
        |       expr LEFT expr            { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::LEFT, $3); }
        |       expr RIGHT expr           { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::RIGHT, $3); }
        |       expr PLUS expr            { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::PLUS, $3); }
        |       expr MINUS expr           { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::MINUS, $3); }
        |       expr MUL expr             { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::MUL, $3); }
        |       expr DIV expr             { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::DIV, $3); }
        |       expr MOD expr             { $$ = driver.ctx.make_node<ast::Binop>(@2, $1, ast::Operator::MOD, $3); }
                ;

sizeof_expr:
                SIZEOF "(" type ")"                         { $$ = driver.ctx.make_node<ast::Sizeof>(@$, $3); }
        |       SIZEOF "(" expr ")"                         { $$ = driver.ctx.make_node<ast::Sizeof>(@$, $3); }
                ;

offsetof_expr:
                OFFSETOF "(" struct_type "," struct_field ")"      { $$ = driver.ctx.make_node<ast::Offsetof>(@$, $3, $5); }
                /* For example: offsetof(*curtask, comm) */
        |       OFFSETOF "(" expr "," struct_field ")"             { $$ = driver.ctx.make_node<ast::Offsetof>(@$, $3, $5); }
                ;

typeof_expr:
                TYPEOF "(" type ")"  { $$ = driver.ctx.make_node<ast::Typeof>(@$, $3); }
        |       TYPEOF "(" IDENT "*" ")"  { $$ = driver.ctx.make_node<ast::Typeof>(@$, ast::ident_to_record($3, 1)); }
        |       TYPEOF "(" IDENT "*" "*" ")"  { $$ = driver.ctx.make_node<ast::Typeof>(@$, ast::ident_to_record($3, 2)); }
        |       TYPEOF "(" expr ")"  { $$ = driver.ctx.make_node<ast::Typeof>(@$, $3); }
                ;

typeinfo_expr:
                TYPEINFO "(" type ")"  { $$ = driver.ctx.make_node<ast::Typeinfo>(@$, driver.ctx.make_node<ast::Typeof>(@$, $3)); }
        |       TYPEINFO "(" expr ")"  { $$ = driver.ctx.make_node<ast::Typeinfo>(@$, driver.ctx.make_node<ast::Typeof>(@$, $3)); }
                ;

comptime_expr:
                COMPTIME unary_expr { $$ = driver.ctx.make_node<ast::Comptime>(@$, $2); }
                ;

any_type:
                type        { $$ = driver.ctx.make_node<ast::Typeof>(@$, $1); }
        |       typeof_expr { $$ = $1; }
                ;

keyword:
                BREAK         { $$ = $1; }
        |       CONFIG        { $$ = $1; }
        |       CONTINUE      { $$ = $1; }
        |       ELSE          { $$ = $1; }
        |       FOR           { $$ = $1; }
        |       IF            { $$ = $1; }
        |       LET           { $$ = $1; }
        |       OFFSETOF      { $$ = $1; }
        |       RETURN        { $$ = $1; }
        |       SIZEOF        { $$ = $1; }
        |       UNROLL        { $$ = $1; }
        |       WHILE         { $$ = $1; }
        |       SUBPROG       { $$ = $1; }
        |       TYPEOF        { $$ = $1; }
        |       TYPEINFO      { $$ = $1; }
        |       COMPTIME      { $$ = $1; }
                ;

ident:
                IDENT         { $$ = $1; }
        |       BUILTIN       { $$ = $1; }
        |       BUILTIN_TYPE  { $$ = $1; }
        |       SIZED_TYPE    { $$ = $1; }
                ;

struct_field:
                external_name                       { $$.push_back($1); }
        |       struct_field DOT external_name      { $$ = std::move($1); $$.push_back($3); }
                ;

external_name:
                keyword       { $$ = $1; }
        |       ident         { $$ = $1; }
                ;

call_expr:
                IDENT "(" ")"                 { $$ = driver.ctx.make_node<ast::Call>(@$, $1, ast::ExpressionList({})); }
        |       BUILTIN "(" ")"               { $$ = driver.ctx.make_node<ast::Call>(@$, $1, ast::ExpressionList({})); }
        |       IDENT "(" vargs ")"           { $$ = driver.ctx.make_node<ast::Call>(@$, $1, std::move($3)); }
        |       BUILTIN "(" vargs ")"         { $$ = driver.ctx.make_node<ast::Call>(@$, $1, std::move($3)); }
                ;

map:
                MAP { $$ = driver.ctx.make_node<ast::Map>(@$, $1); }
                ;

map_expr:
                map "[" vargs "]" {
                        if ($3.size() > 1) {
                          auto t = driver.ctx.make_node<ast::Tuple>(@$, std::move($3));
                          $$ = driver.ctx.make_node<ast::MapAccess>(@$, $1, t);
                        } else {
                          $$ = driver.ctx.make_node<ast::MapAccess>(@$, $1, $3.back());
                        }
                }
                ;

var:
                VAR { $$ = driver.ctx.make_node<ast::Variable>(@$, $1); }
                ;

var_addr:
                BAND var { $$ = driver.ctx.make_node<ast::VariableAddr>(@$, $2); }
                ;

map_addr:
                BAND map { $$ = driver.ctx.make_node<ast::MapAddr>(@$, $2); }
                ;

vargs:
                vargs "," expr { $$ = std::move($1); $$.push_back($3); }
        |       expr           { $$ = ast::ExpressionList{$1}; }
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

void bpftrace::Parser::error(const ast::SourceLocation &l, const std::string &m)
{
  driver.error(l, m);
}
