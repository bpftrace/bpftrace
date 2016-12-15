%skeleton "lalr1.cc"
%require "3.0.4"
%defines
%define api.namespace { ebpf::bpftrace }
%define parser_class_name { Parser }

%define api.token.constructor
%define api.value.type variant
%define parse.assert

%define parse.error verbose

%param { ebpf::bpftrace::Driver &driver }
%locations

// Forward declarations of classes referenced in the parser
%code requires
{
namespace ebpf {
namespace bpftrace {
class Driver;
namespace ast {
class Node;
} // namespace ast
} // namespace bpftrace
} // namespace ebpf
#include "ast.h"
}

%{
#include <iostream>

#include "driver.h"

void yyerror(ebpf::bpftrace::Driver &driver, const char *s);
%}

%define api.token.prefix {TOK_}
%token
  END 0   "end of file"
  COLON   ":"
  SEMI    ";"
  LBRACE  "{"
  RBRACE  "}"
  ASSIGN  "="
;

%token <std::string> IDENT "identifier"
%token <int> INT "integer"

%type <ast::ProbeList *> probes
%type <ast::StatementList *> block stmts
%type <ast::Probe *> probe
%type <ast::Statement *> stmt
%type <ast::Expression *> expr
%type <ast::Variable *> var
%type <ast::ExpressionList *> vargs

%printer { yyoutput << %%; } <*>;

%start program

%%

program : probes { driver.root_ = new ast::Program($1); }
        ;

probes : probes probe { $$ = $1; $1->push_back($2); }
       | probe        { $$ = new ast::ProbeList; $$->push_back($1); }
       ;

probe : IDENT ":" IDENT block { $$ = new ast::Probe($1, $3, $4); }
      ;

block : "{" stmts "}"     { $$ = $2; }
      | "{" stmts ";" "}" { $$ = $2; }

stmts : stmts ";" stmt { $$ = $1; $1->push_back($3); }
      | stmt           { $$ = new ast::StatementList; $$->push_back($1); }
      ;

stmt : expr         { $$ = new ast::ExprStatement($1); }
     | var "=" expr { $$ = new ast::AssignStatement($1, $3); }
     ;

expr : INT   { $$ = new ast::Integer($1); }
     | var   { $$ = $1; }
     ;

var : IDENT               { $$ = new ast::Variable($1); }
    | IDENT "[" vargs "]" { $$ = new ast::Variable($1, $3); }
    ;

vargs : vargs "," expr { $$ = $1; $1->push_back($3); }
      | expr           { $$ = new ast::ExpressionList; $$->push_back($1); }
      ;

%%

void ebpf::bpftrace::Parser::error(const location &l, const std::string &m)
{
  driver.error(l, m);
}
