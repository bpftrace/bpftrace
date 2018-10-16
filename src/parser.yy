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
  END 0    "end of file"
  COLON    ":"
  SEMI     ";"
  LBRACE   "{"
  RBRACE   "}"
  LBRACKET "["
  RBRACKET "]"
  LPAREN   "("
  RPAREN   ")"
  QUES     "?"
  ENDPRED  "end predicate"
  COMMA    ","
  ASSIGN   "="
  EQ       "=="
  NE       "!="
  LE       "<="
  GE       ">="
  LEFT     "<<"
  RIGHT    ">>"
  LT       "<"
  GT       ">"
  LAND     "&&"
  LOR      "||"
  PLUS     "+"
  MINUS    "-"
  MUL      "*"
  DIV      "/"
  MOD      "%"
  BAND     "&"
  BOR      "|"
  BXOR     "^"
  LNOT     "!"
  BNOT     "~"
  DOT      "."
  PTR      "->"
;

%token <std::string> BUILTIN "builtin"
%token <std::string> IDENT "identifier"
%token <std::string> PATH "path"
%token <std::string> CPREPROC "preprocessor directive"
%token <std::string> STRUCT "struct"
%token <std::string> STRING "string"
%token <std::string> MAP "map"
%token <std::string> VAR "variable"
%token <long> INT "integer"
%nonassoc <std::string> IF "if"
%nonassoc <std::string> ELSE "else"
%nonassoc <std::string> UNROLL "unroll"

%type <std::string> c_definitions
%type <ast::ProbeList *> probes
%type <ast::Probe *> probe
%type <ast::Predicate *> pred
%type <ast::Ternary *> ternary
%type <ast::StatementList *> block stmts
%type <ast::Statement *> stmt
%type <ast::Expression *> expr
%type <ast::Call *> call
%type <ast::Map *> map
%type <ast::Variable *> var
%type <ast::ExpressionList *> vargs
%type <ast::AttachPointList *> attach_points
%type <ast::AttachPoint *> attach_point
%type <std::string> wildcard
%type <std::string> ident

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

c_definitions : CPREPROC c_definitions { $$ = $1 + "\n" + $2; }
              | STRUCT c_definitions   { $$ = $1 + ";\n" + $2; }
              |                        { $$ = std::string(); }
              ;

probes : probes probe { $$ = $1; $1->push_back($2); }
       | probe        { $$ = new ast::ProbeList; $$->push_back($1); }
       ;

probe : attach_points pred block { $$ = new ast::Probe($1, $2, $3); }
      ;

attach_points : attach_points "," attach_point { $$ = $1; $1->push_back($3); }
              | attach_point                   { $$ = new ast::AttachPointList; $$->push_back($1); }
              ;

attach_point : ident               { $$ = new ast::AttachPoint($1); }
             | ident ":" wildcard  { $$ = new ast::AttachPoint($1, $3); }
             | ident PATH STRING   { $$ = new ast::AttachPoint($1, $2.substr(1, $2.size()-2), $3, false); }
             | ident PATH wildcard { $$ = new ast::AttachPoint($1, $2.substr(1, $2.size()-2), $3, true); }
             | ident PATH INT      { $$ = new ast::AttachPoint($1, $2.substr(1, $2.size()-2), $3); }
             ;

wildcard : wildcard ident    { $$ = $1 + $2; }
         | wildcard MUL      { $$ = $1 + "*"; }
         | wildcard LBRACKET { $$ = $1 + "["; }
         | wildcard RBRACKET { $$ = $1 + "]"; }
         |                   { $$ = ""; }
         ;

pred : DIV expr ENDPRED { $$ = new ast::Predicate($2); }
     |                  { $$ = nullptr; }
     ;

ternary : expr QUES expr COLON expr { $$ = new ast::Ternary($1, $3, $5); }
     ;

block : "{" stmts "}"     { $$ = $2; }
      | "{" stmts ";" "}" { $$ = $2; }
      ;

stmts : stmts ";" stmt { $$ = $1; $1->push_back($3); }
      | stmt           { $$ = new ast::StatementList; $$->push_back($1); }
      ;

stmt : expr         { $$ = new ast::ExprStatement($1); }
     | map "=" expr { $$ = new ast::AssignMapStatement($1, $3); }
     | var "=" expr { $$ = new ast::AssignVarStatement($1, $3); }
     | IF "(" expr ")" block  { $$ = new ast::If($3, $5); }
     | IF "(" expr ")" block ELSE block { $$ = new ast::If($3, $5, $7); }
     | UNROLL "(" INT ")" block { $$ = new ast::Unroll($3, $5); }
     ;

expr : INT             { $$ = new ast::Integer($1); }
     | STRING          { $$ = new ast::String($1); }
     | BUILTIN         { $$ = new ast::Builtin($1); }
     | ternary         { $$ = $1; }
     | map             { $$ = $1; }
     | var             { $$ = $1; }
     | call            { $$ = $1; }
     | "(" expr ")"    { $$ = $2; }
     | expr EQ expr    { $$ = new ast::Binop($1, token::EQ, $3); }
     | expr NE expr    { $$ = new ast::Binop($1, token::NE, $3); }
     | expr LE expr    { $$ = new ast::Binop($1, token::LE, $3); }
     | expr GE expr    { $$ = new ast::Binop($1, token::GE, $3); }
     | expr LT expr    { $$ = new ast::Binop($1, token::LT, $3); }
     | expr GT expr    { $$ = new ast::Binop($1, token::GT, $3); }
     | expr LAND expr  { $$ = new ast::Binop($1, token::LAND,  $3); }
     | expr LOR expr   { $$ = new ast::Binop($1, token::LOR,   $3); }
     | expr LEFT expr  { $$ = new ast::Binop($1, token::LEFT,  $3); }
     | expr RIGHT expr { $$ = new ast::Binop($1, token::RIGHT, $3); }
     | expr PLUS expr  { $$ = new ast::Binop($1, token::PLUS,  $3); }
     | expr MINUS expr { $$ = new ast::Binop($1, token::MINUS, $3); }
     | expr MUL expr   { $$ = new ast::Binop($1, token::MUL,   $3); }
     | expr DIV expr   { $$ = new ast::Binop($1, token::DIV,   $3); }
     | expr MOD expr   { $$ = new ast::Binop($1, token::MOD,   $3); }
     | expr BAND expr  { $$ = new ast::Binop($1, token::BAND,  $3); }
     | expr BOR expr   { $$ = new ast::Binop($1, token::BOR,   $3); }
     | expr BXOR expr  { $$ = new ast::Binop($1, token::BXOR,  $3); }
     | LNOT expr       { $$ = new ast::Unop(token::LNOT, $2); }
     | BNOT expr       { $$ = new ast::Unop(token::BNOT, $2); }
     | MINUS expr       { $$ = new ast::Unop(token::MINUS, $2); }
     | MUL  expr %prec DEREF { $$ = new ast::Unop(token::MUL,  $2); }
     | expr DOT ident  { $$ = new ast::FieldAccess($1, $3); }
     | expr PTR ident  { $$ = new ast::FieldAccess(new ast::Unop(token::MUL, $1), $3); }
     | "(" IDENT ")" expr %prec CAST  { $$ = new ast::Cast($2, false, $4); }
     | "(" IDENT MUL ")" expr %prec CAST  { $$ = new ast::Cast($2, true, $5); }
     ;

ident : IDENT   { $$ = $1; }
      | BUILTIN { $$ = $1; }
      ;

call : ident "(" ")"       { $$ = new ast::Call($1); }
     | ident "(" vargs ")" { $$ = new ast::Call($1, $3); }
     ;

map : MAP               { $$ = new ast::Map($1); }
    | MAP "[" vargs "]" { $$ = new ast::Map($1, $3); }
    ;

var : VAR { $$ = new ast::Variable($1); }
    ;

vargs : vargs "," expr { $$ = $1; $1->push_back($3); }
      | expr           { $$ = new ast::ExpressionList; $$->push_back($1); }
      ;

%%

void bpftrace::Parser::error(const location &l, const std::string &m)
{
  driver.error(l, m);
}
