%skeleton "lalr1.cc"
%require "3.0.4"
%defines
%define api.namespace { bpftrace }
%define parser_class_name { Parser }

%define api.token.constructor
%define api.value.type variant
%define parse.assert

%define parse.error verbose

%param { bpftrace::Driver &driver }
%param { void *yyscanner }
%locations

// Forward declarations of classes referenced in the parser
%code requires
{
#include <regex>

namespace bpftrace {
class Driver;
namespace ast {
class Node;
} // namespace ast
} // namespace bpftrace
#include "ast.h"
}

%{
#include <iostream>

#include "driver.h"

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
  FOR        "for"
  RETURN     "return"
  CONTINUE   "continue"
  BREAK      "break"
;

%token <std::string> BUILTIN "builtin"
%token <std::string> CALL "call"
%token <std::string> CALL_BUILTIN "call_builtin"
%token <std::string> IDENT "identifier"
%token <std::string> PATH "path"
%token <std::string> CPREPROC "preprocessor directive"
%token <std::string> STRUCT_DEFN "struct definition"
%token <std::string> ENUM "enum"
%token <std::string> STRING "string"
%token <std::string> MAP "map"
%token <std::string> VAR "variable"
%token <std::string> PARAM "positional parameter"
%token <long> INT "integer"
%token <std::string> STACK_MODE "stack_mode"

%type <std::string> c_definitions
%type <ast::ProbeList *> probes
%type <ast::Probe *> probe
%type <ast::Predicate *> pred
%type <ast::Ternary *> ternary
%type <ast::StatementList *> block stmts block_or_if
%type <ast::Statement *> if_stmt block_stmt stmt semicolon_ended_stmt compound_assignment jump_stmt loop_stmt
%type <ast::Expression *> expr
%type <ast::Call *> call
%type <ast::Map *> map
%type <ast::Variable *> var
%type <ast::ExpressionList *> vargs
%type <ast::AttachPointList *> attach_points
%type <ast::AttachPoint *> attach_point
%type <std::string> attach_point_def
%type <ast::PositionalParameter *> param
%type <std::string> ident
%type <ast::Expression *> map_or_var
%type <ast::Expression *> pre_post_op
%type <ast::Integer *> int

%right ASSIGN
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
%right LNOT BNOT DEREF CAST
%left DOT PTR

%start program

%%

program : c_definitions probes { driver.root_ = new ast::Program($1, $2); }
        ;

c_definitions : CPREPROC c_definitions    { $$ = $1 + "\n" + $2; }
              | STRUCT_DEFN c_definitions { $$ = $1 + ";\n" + $2; }
              | ENUM c_definitions        { $$ = $1 + ";\n" + $2; }
              |                           { $$ = std::string(); }
              ;

probes : probes probe { $$ = $1; $1->push_back($2); }
       | probe        { $$ = new ast::ProbeList; $$->push_back($1); }
       ;

probe : attach_points pred block { $$ = new ast::Probe($1, $2, $3); }
      ;

attach_points : attach_points "," attach_point { $$ = $1; $1->push_back($3); }
              | attach_point                   { $$ = new ast::AttachPointList; $$->push_back($1); }
              ;

attach_point : attach_point_def                { $$ = new ast::AttachPoint($1, @$); }
             ;

attach_point_def : attach_point_def ident    { $$ = $1 + $2; }
                 // Since we're double quoting the STRING for the benefit of the
                 // AttachPointParser, we have to make sure we re-escape any double
                 // quotes.
                 | attach_point_def STRING   { $$ = $1 + "\"" + std::regex_replace($2, std::regex("\""), "\\\"") + "\""; }
                 | attach_point_def PATH     { $$ = $1 + $2; }
                 | attach_point_def INT      { $$ = $1 + std::to_string($2); }
                 | attach_point_def COLON    { $$ = $1 + ":"; }
                 | attach_point_def DOT      { $$ = $1 + "."; }
                 | attach_point_def PLUS     { $$ = $1 + "+"; }
                 | attach_point_def MUL      { $$ = $1 + "*"; }
                 | attach_point_def LBRACKET { $$ = $1 + "["; }
                 | attach_point_def RBRACKET { $$ = $1 + "]"; }
                 | attach_point_def param    {
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
                 |                           { $$ = ""; }
                 ;

pred : DIV expr ENDPRED { $$ = new ast::Predicate($2, @$); }
     |                  { $$ = nullptr; }
     ;

ternary : expr QUES expr COLON expr { $$ = new ast::Ternary($1, $3, $5, @$); }
        ;

param : PARAM      {
                     try {
                       $$ = new ast::PositionalParameter(PositionalParameterType::positional, std::stol($1.substr(1, $1.size()-1)), @$);
                     } catch (std::exception const& e) {
                       error(@1, "param " + $1 + " is out of integer range [1, " +
                             std::to_string(std::numeric_limits<long>::max()) + "]");
                       YYERROR;
                     }
                   }
      | PARAMCOUNT { $$ = new ast::PositionalParameter(PositionalParameterType::count, 0, @$); }
      ;

block : "{" stmts "}"     { $$ = $2; }
      ;

semicolon_ended_stmt: stmt ";"  { $$ = $1; }
                    ;

stmts : semicolon_ended_stmt stmts { $$ = $2; $2->insert($2->begin(), $1); }
      | block_stmt stmts           { $$ = $2; $2->insert($2->begin(), $1); }
      | stmt                       { $$ = new ast::StatementList; $$->push_back($1); }
      |                            { $$ = new ast::StatementList; }
      ;

block_stmt : if_stmt                  { $$ = $1; }
           | jump_stmt                { $$ = $1; }
           | loop_stmt                { $$ = $1; }
           ;

jump_stmt  : BREAK    { $$ = new ast::Jump(token::BREAK, @$); }
           | CONTINUE { $$ = new ast::Jump(token::CONTINUE, @$); }
           | RETURN   { $$ = new ast::Jump(token::RETURN, @$); }
           ;

loop_stmt  : UNROLL "(" int ")" block             { $$ = new ast::Unroll($3, $5, @1 + @4); }
           | UNROLL "(" param ")" block           { $$ = new ast::Unroll($3, $5, @1 + @4); }
           | WHILE  "(" expr ")" block            { $$ = new ast::While($3, $5, @1); }
           ;

if_stmt : IF "(" expr ")" block                  { $$ = new ast::If($3, $5); }
        | IF "(" expr ")" block ELSE block_or_if { $$ = new ast::If($3, $5, $7); }
        ;

block_or_if : block        { $$ = $1; }
            | if_stmt      { $$ = new ast::StatementList; $$->emplace_back($1); }
            ;

stmt : expr                { $$ = new ast::ExprStatement($1); }
     | compound_assignment { $$ = $1; }
     | jump_stmt           { $$ = $1; }
     | map "=" expr        { $$ = new ast::AssignMapStatement($1, $3, @2); }
     | var "=" expr        { $$ = new ast::AssignVarStatement($1, $3, @2); }
     ;

compound_assignment : map LEFTASSIGN expr  { $$ = new ast::AssignMapStatement($1, new ast::Binop($1, token::LEFT,  $3, @2)); }
                    | var LEFTASSIGN expr  { $$ = new ast::AssignVarStatement($1, new ast::Binop($1, token::LEFT,  $3, @2)); }
                    | map RIGHTASSIGN expr { $$ = new ast::AssignMapStatement($1, new ast::Binop($1, token::RIGHT, $3, @2)); }
                    | var RIGHTASSIGN expr { $$ = new ast::AssignVarStatement($1, new ast::Binop($1, token::RIGHT, $3, @2)); }
                    | map PLUSASSIGN expr  { $$ = new ast::AssignMapStatement($1, new ast::Binop($1, token::PLUS,  $3, @2)); }
                    | var PLUSASSIGN expr  { $$ = new ast::AssignVarStatement($1, new ast::Binop($1, token::PLUS,  $3, @2)); }
                    | map MINUSASSIGN expr { $$ = new ast::AssignMapStatement($1, new ast::Binop($1, token::MINUS, $3, @2)); }
                    | var MINUSASSIGN expr { $$ = new ast::AssignVarStatement($1, new ast::Binop($1, token::MINUS, $3, @2)); }
                    | map MULASSIGN expr   { $$ = new ast::AssignMapStatement($1, new ast::Binop($1, token::MUL,   $3, @2)); }
                    | var MULASSIGN expr   { $$ = new ast::AssignVarStatement($1, new ast::Binop($1, token::MUL,   $3, @2)); }
                    | map DIVASSIGN expr   { $$ = new ast::AssignMapStatement($1, new ast::Binop($1, token::DIV,   $3, @2)); }
                    | var DIVASSIGN expr   { $$ = new ast::AssignVarStatement($1, new ast::Binop($1, token::DIV,   $3, @2)); }
                    | map MODASSIGN expr   { $$ = new ast::AssignMapStatement($1, new ast::Binop($1, token::MOD,   $3, @2)); }
                    | var MODASSIGN expr   { $$ = new ast::AssignVarStatement($1, new ast::Binop($1, token::MOD,   $3, @2)); }
                    | map BANDASSIGN expr  { $$ = new ast::AssignMapStatement($1, new ast::Binop($1, token::BAND,  $3, @2)); }
                    | var BANDASSIGN expr  { $$ = new ast::AssignVarStatement($1, new ast::Binop($1, token::BAND,  $3, @2)); }
                    | map BORASSIGN expr   { $$ = new ast::AssignMapStatement($1, new ast::Binop($1, token::BOR,   $3, @2)); }
                    | var BORASSIGN expr   { $$ = new ast::AssignVarStatement($1, new ast::Binop($1, token::BOR,   $3, @2)); }
                    | map BXORASSIGN expr  { $$ = new ast::AssignMapStatement($1, new ast::Binop($1, token::BXOR,  $3, @2)); }
                    | var BXORASSIGN expr  { $$ = new ast::AssignVarStatement($1, new ast::Binop($1, token::BXOR,  $3, @2)); }
                    ;

int : MINUS INT    { $$ = new ast::Integer(-1 * $2, @$); }
    | INT          { $$ = new ast::Integer($1, @$); }
    ;

expr : int                                      { $$ = $1; }
     | STRING                                   { $$ = new ast::String($1, @$); }
     | BUILTIN                                  { $$ = new ast::Builtin($1, @$); }
     | CALL_BUILTIN                             { $$ = new ast::Builtin($1, @$); }
     | IDENT                                    { $$ = new ast::Identifier($1, @$); }
     | STACK_MODE                               { $$ = new ast::StackMode($1, @$); }
     | ternary                                  { $$ = $1; }
     | param                                    { $$ = $1; }
     | map_or_var                               { $$ = $1; }
     | call                                     { $$ = $1; }
     | "(" expr ")"                             { $$ = $2; }
     | expr EQ expr                             { $$ = new ast::Binop($1, token::EQ, $3, @2); }
     | expr NE expr                             { $$ = new ast::Binop($1, token::NE, $3, @2); }
     | expr LE expr                             { $$ = new ast::Binop($1, token::LE, $3, @2); }
     | expr GE expr                             { $$ = new ast::Binop($1, token::GE, $3, @2); }
     | expr LT expr                             { $$ = new ast::Binop($1, token::LT, $3, @2); }
     | expr GT expr                             { $$ = new ast::Binop($1, token::GT, $3, @2); }
     | expr LAND expr                           { $$ = new ast::Binop($1, token::LAND,  $3, @2); }
     | expr LOR expr                            { $$ = new ast::Binop($1, token::LOR,   $3, @2); }
     | expr LEFT expr                           { $$ = new ast::Binop($1, token::LEFT,  $3, @2); }
     | expr RIGHT expr                          { $$ = new ast::Binop($1, token::RIGHT, $3, @2); }
     | expr PLUS expr                           { $$ = new ast::Binop($1, token::PLUS,  $3, @2); }
     | expr MINUS expr                          { $$ = new ast::Binop($1, token::MINUS, $3, @2); }
     | expr MUL expr                            { $$ = new ast::Binop($1, token::MUL,   $3, @2); }
     | expr DIV expr                            { $$ = new ast::Binop($1, token::DIV,   $3, @2); }
     | expr MOD expr                            { $$ = new ast::Binop($1, token::MOD,   $3, @2); }
     | expr BAND expr                           { $$ = new ast::Binop($1, token::BAND,  $3, @2); }
     | expr BOR expr                            { $$ = new ast::Binop($1, token::BOR,   $3, @2); }
     | expr BXOR expr                           { $$ = new ast::Binop($1, token::BXOR,  $3, @2); }
     | LNOT expr                                { $$ = new ast::Unop(token::LNOT, $2, @1); }
     | BNOT expr                                { $$ = new ast::Unop(token::BNOT, $2, @1); }
     | MINUS expr                               { $$ = new ast::Unop(token::MINUS, $2, @1); }
     | MUL  expr %prec DEREF                    { $$ = new ast::Unop(token::MUL,  $2, @1); }
     | expr DOT ident                           { $$ = new ast::FieldAccess($1, $3, @2); }
     | expr PTR ident                           { $$ = new ast::FieldAccess(new ast::Unop(token::MUL, $1, @2), $3, @$); }
     | expr "[" expr "]"                        { $$ = new ast::ArrayAccess($1, $3, @2 + @4); }
     | "(" IDENT ")" expr %prec CAST            { $$ = new ast::Cast($2, false, $4, @1 + @3); }
     | "(" IDENT MUL ")" expr %prec CAST        { $$ = new ast::Cast($2, true, $5, @1 + @4); }
     | "(" expr "," vargs ")"                   {
                                                  auto args = new ast::ExpressionList;
                                                  args->emplace_back($2);
                                                  args->insert(args->end(), $4->begin(), $4->end());
                                                  $$ = new ast::Tuple(args, @$);
                                                }
     | pre_post_op                              { $$ = $1; }
     ;

pre_post_op : map_or_var INCREMENT   { $$ = new ast::Unop(token::INCREMENT, $1, true, @2); }
            | map_or_var DECREMENT   { $$ = new ast::Unop(token::DECREMENT, $1, true, @2); }
            | INCREMENT map_or_var   { $$ = new ast::Unop(token::INCREMENT, $2, @1); }
            | DECREMENT map_or_var   { $$ = new ast::Unop(token::DECREMENT, $2, @1); }
            | ident INCREMENT      { error(@1, "The ++ operator must be applied to a map or variable"); YYERROR; }
            | INCREMENT ident      { error(@1, "The ++ operator must be applied to a map or variable"); YYERROR; }
            | ident DECREMENT      { error(@1, "The -- operator must be applied to a map or variable"); YYERROR; }
            | DECREMENT ident      { error(@1, "The -- operator must be applied to a map or variable"); YYERROR; }
            ;

ident : IDENT         { $$ = $1; }
      | BUILTIN       { $$ = $1; }
      | CALL          { $$ = $1; }
      | CALL_BUILTIN  { $$ = $1; }
      | STACK_MODE    { $$ = $1; }
      ;

call : CALL "(" ")"                 { $$ = new ast::Call($1, @$); }
     | CALL "(" vargs ")"           { $$ = new ast::Call($1, $3, @$); }
     | CALL_BUILTIN  "(" ")"        { $$ = new ast::Call($1, @$); }
     | CALL_BUILTIN "(" vargs ")"   { $$ = new ast::Call($1, $3, @$); }
     | IDENT "(" ")"                { error(@1, "Unknown function: " + $1); YYERROR;  }
     | IDENT "(" vargs ")"          { error(@1, "Unknown function: " + $1); YYERROR;  }
     | BUILTIN "(" ")"              { error(@1, "Unknown function: " + $1); YYERROR;  }
     | BUILTIN "(" vargs ")"        { error(@1, "Unknown function: " + $1); YYERROR;  }
     | STACK_MODE "(" ")"           { error(@1, "Unknown function: " + $1); YYERROR;  }
     | STACK_MODE "(" vargs ")"     { error(@1, "Unknown function: " + $1); YYERROR;  }
     ;

map : MAP               { $$ = new ast::Map($1, @$); }
    | MAP "[" vargs "]" { $$ = new ast::Map($1, $3, @$); }
    ;

var : VAR { $$ = new ast::Variable($1, @$); }
    ;

map_or_var : var { $$ = $1; }
           | map { $$ = $1; }
           ;

vargs : vargs "," expr { $$ = $1; $1->push_back($3); }
      | expr           { $$ = new ast::ExpressionList; $$->push_back($1); }
      ;

%%

void bpftrace::Parser::error(const location &l, const std::string &m)
{
  driver.error(l, m);
}
