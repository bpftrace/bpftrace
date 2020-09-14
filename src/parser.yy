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
%type <std::unique_ptr<ast::ProbeList>> probes
%type <std::unique_ptr<ast::Probe>> probe
%type <std::unique_ptr<ast::Predicate>> pred
%type <std::unique_ptr<ast::Expression>> ternary
%type <std::unique_ptr<ast::StatementList>> block stmts block_or_if
%type <std::unique_ptr<ast::Statement>> if_stmt block_stmt stmt semicolon_ended_stmt compound_assignment jump_stmt loop_stmt
%type <std::unique_ptr<ast::Expression>> expr
%type <std::unique_ptr<ast::Expression>> call
%type <std::unique_ptr<ast::Map>> map
%type <std::unique_ptr<ast::Variable>> var
%type <std::unique_ptr<ast::ExpressionList>> vargs
%type <std::unique_ptr<ast::AttachPointList>> attach_points
%type <std::unique_ptr<ast::AttachPoint>> attach_point
%type <std::string> attach_point_def
%type <std::unique_ptr<ast::Expression>> param
%type <std::string> ident
%type <std::unique_ptr<ast::Expression>> map_or_var
%type <std::unique_ptr<ast::Expression>> pre_post_op
%type <std::unique_ptr<ast::Expression>> int

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

program : c_definitions probes { driver.root_ = std::make_unique<ast::Program>($1, std::move($2)); }
        ;

c_definitions : CPREPROC c_definitions    { $$ = $1 + "\n" + $2; }
              | STRUCT_DEFN c_definitions { $$ = $1 + ";\n" + $2; }
              | ENUM c_definitions        { $$ = $1 + ";\n" + $2; }
              |                           { $$ = std::string(); }
              ;

probes : probes probe { $1->push_back(std::move($2)); $$ = std::move($1); }
       | probe        { $$ = std::make_unique<ast::ProbeList>(); $$->push_back(std::move($1)); }
       ;

probe : attach_points pred block { $$ = std::make_unique<ast::Probe>(std::move($1), std::move($2), std::move($3)); }
      ;

attach_points : attach_points "," attach_point { $1->push_back(std::move($3)); $$ = std::move($1); }
              | attach_point                   { $$ = std::make_unique<ast::AttachPointList>(); $$->push_back(std::move($1)); }
              ;

attach_point : attach_point_def                { $$ = std::make_unique<ast::AttachPoint>($1, @$); }
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
                                               if (static_cast<ast::PositionalParameter*>($2.get())->ptype != PositionalParameterType::positional)
                                               {
                                                  error(@$, "Not a positional parameter");
                                                  YYERROR;
                                               }

                                               // "Un-parse" the positional parameter back into text so
                                               // we can give it to the AttachPointParser. This is kind of
                                               // a hack but there doesn't look to be any other way.
                                               $$ = $1 + "$" + std::to_string(static_cast<ast::PositionalParameter*>($2.get())->n);
                                             }
                 |                           { $$ = ""; }
                 ;

pred : DIV expr ENDPRED { $$ = std::make_unique<ast::Predicate>(std::move($2), @$); }
     |                  { $$ = nullptr; }
     ;

ternary : expr QUES expr COLON expr { $$ = std::unique_ptr<ast::Expression>(new ast::Ternary(std::move($1), std::move($3), std::move($5), @$)); }
        ;

param : PARAM      {
                     try {
                       $$ = std::unique_ptr<ast::Expression>(new ast::PositionalParameter(PositionalParameterType::positional, std::stol($1.substr(1, $1.size()-1)), @$));
                     } catch (std::exception const& e) {
                       error(@1, "param " + $1 + " is out of integer range [1, " +
                             std::to_string(std::numeric_limits<long>::max()) + "]");
                       YYERROR;
                     }
                   }
      | PARAMCOUNT { $$ = std::unique_ptr<ast::Expression>(new ast::PositionalParameter(PositionalParameterType::count, 0, @$)); }
      ;

block : "{" stmts "}"     { $$ = std::move($2); }
      ;

semicolon_ended_stmt: stmt ";"  { $$ = std::move($1); }
                    ;

stmts : semicolon_ended_stmt stmts { $2->insert($2->begin(), std::move($1)); $$ = std::move($2); }
      | block_stmt stmts           { $2->insert($2->begin(), std::move($1)); $$ = std::move($2); }
      | stmt                       { $$ = std::make_unique<ast::StatementList>(); $$->push_back(std::move($1)); }
      |                            { $$ = std::make_unique<ast::StatementList>(); }
      ;

block_stmt : if_stmt                  { $$ = std::move($1); }
           | jump_stmt                { $$ = std::move($1); }
           | loop_stmt                { $$ = std::move($1); }
           ;

jump_stmt  : BREAK    { $$ = std::unique_ptr<ast::Statement>(new ast::Jump(token::BREAK, @$)); }
           | CONTINUE { $$ = std::unique_ptr<ast::Statement>(new ast::Jump(token::CONTINUE, @$)); }
           | RETURN   { $$ = std::unique_ptr<ast::Statement>(new ast::Jump(token::RETURN, @$)); }
           ;

loop_stmt  : UNROLL "(" int ")" block             { $$ = std::unique_ptr<ast::Statement>(new ast::Unroll(std::move($3), std::move($5), @1 + @4)); }
           | UNROLL "(" param ")" block           { $$ = std::unique_ptr<ast::Statement>(new ast::Unroll(std::move($3), std::move($5), @1 + @4)); }
           | WHILE  "(" expr ")" block            { $$ = std::unique_ptr<ast::Statement>(new ast::While(std::move($3), std::move($5), @1)); }
           ;

if_stmt : IF "(" expr ")" block                  { $$ = std::unique_ptr<ast::Statement>(new ast::If(std::move($3), std::move($5))); }
        | IF "(" expr ")" block ELSE block_or_if { $$ = std::unique_ptr<ast::Statement>(new ast::If(std::move($3), std::move($5), std::move($7))); }
        ;

block_or_if : block        { $$ = std::move($1); }
            | if_stmt      { $$ = std::make_unique<ast::StatementList>(); $$->emplace_back(std::move($1)); }
            ;

stmt : expr                { $$ = std::unique_ptr<ast::Statement>(new ast::ExprStatement(std::move($1))); }
     | compound_assignment { $$ = std::move($1); }
     | jump_stmt           { $$ = std::move($1); }
     | map "=" expr        { $$ = std::unique_ptr<ast::Statement>(new ast::AssignMapStatement(std::move($1), std::move($3), @2)); }
     | var "=" expr        { $$ = std::unique_ptr<ast::Statement>(new ast::AssignVarStatement(std::move($1), std::move($3), @2)); }
     ;

compound_assignment : map LEFTASSIGN expr  { $$ = std::unique_ptr<ast::Statement>(new ast::AssignMapStatement(std::make_unique<ast::Map>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::LEFT, std::move($3), @2)))); }
                    | var LEFTASSIGN expr  { $$ = std::unique_ptr<ast::Statement>(new ast::AssignVarStatement(std::make_unique<ast::Variable>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::LEFT, std::move($3), @2)))); }
                    | map RIGHTASSIGN expr { $$ = std::unique_ptr<ast::Statement>(new ast::AssignMapStatement(std::make_unique<ast::Map>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::RIGHT, std::move($3), @2)))); }
                    | var RIGHTASSIGN expr { $$ = std::unique_ptr<ast::Statement>(new ast::AssignVarStatement(std::make_unique<ast::Variable>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::RIGHT, std::move($3), @2)))); }
                    | map PLUSASSIGN expr  { $$ = std::unique_ptr<ast::Statement>(new ast::AssignMapStatement(std::make_unique<ast::Map>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::PLUS, std::move($3), @2)))); }
                    | var PLUSASSIGN expr  { $$ = std::unique_ptr<ast::Statement>(new ast::AssignVarStatement(std::make_unique<ast::Variable>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::PLUS, std::move($3), @2)))); }
                    | map MINUSASSIGN expr { $$ = std::unique_ptr<ast::Statement>(new ast::AssignMapStatement(std::make_unique<ast::Map>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::MINUS, std::move($3), @2)))); }
                    | var MINUSASSIGN expr { $$ = std::unique_ptr<ast::Statement>(new ast::AssignVarStatement(std::make_unique<ast::Variable>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::MINUS, std::move($3), @2)))); }
                    | map MULASSIGN expr   { $$ = std::unique_ptr<ast::Statement>(new ast::AssignMapStatement(std::make_unique<ast::Map>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::MUL, std::move($3), @2)))); }
                    | var MULASSIGN expr   { $$ = std::unique_ptr<ast::Statement>(new ast::AssignVarStatement(std::make_unique<ast::Variable>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::MUL, std::move($3), @2)))); }
                    | map DIVASSIGN expr   { $$ = std::unique_ptr<ast::Statement>(new ast::AssignMapStatement(std::make_unique<ast::Map>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::DIV, std::move($3), @2)))); }
                    | var DIVASSIGN expr   { $$ = std::unique_ptr<ast::Statement>(new ast::AssignVarStatement(std::make_unique<ast::Variable>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::DIV, std::move($3), @2)))); }
                    | map MODASSIGN expr   { $$ = std::unique_ptr<ast::Statement>(new ast::AssignMapStatement(std::make_unique<ast::Map>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::MOD, std::move($3), @2)))); }
                    | var MODASSIGN expr   { $$ = std::unique_ptr<ast::Statement>(new ast::AssignVarStatement(std::make_unique<ast::Variable>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::MOD, std::move($3), @2)))); }
                    | map BANDASSIGN expr  { $$ = std::unique_ptr<ast::Statement>(new ast::AssignMapStatement(std::make_unique<ast::Map>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::BAND, std::move($3), @2)))); }
                    | var BANDASSIGN expr  { $$ = std::unique_ptr<ast::Statement>(new ast::AssignVarStatement(std::make_unique<ast::Variable>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::BAND, std::move($3), @2)))); }
                    | map BORASSIGN expr   { $$ = std::unique_ptr<ast::Statement>(new ast::AssignMapStatement(std::make_unique<ast::Map>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::BOR, std::move($3), @2)))); }
                    | var BORASSIGN expr   { $$ = std::unique_ptr<ast::Statement>(new ast::AssignVarStatement(std::make_unique<ast::Variable>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::BOR, std::move($3), @2)))); }
                    | map BXORASSIGN expr  { $$ = std::unique_ptr<ast::Statement>(new ast::AssignMapStatement(std::make_unique<ast::Map>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::BXOR, std::move($3), @2)))); }
                    | var BXORASSIGN expr  { $$ = std::unique_ptr<ast::Statement>(new ast::AssignVarStatement(std::make_unique<ast::Variable>(*$1), std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::BXOR, std::move($3), @2)))); }
                    ;

int : MINUS INT    { $$ = std::unique_ptr<ast::Expression>(new ast::Integer(-1 * $2, @$)); }
    | INT          { $$ = std::unique_ptr<ast::Expression>(new ast::Integer($1, @$)); }
    ;

expr : int                                      { $$ = std::move($1); }
     | STRING                                   { $$ = std::unique_ptr<ast::Expression>(new ast::String(std::move($1), @$)); }
     | BUILTIN                                  { $$ = std::unique_ptr<ast::Expression>(new ast::Builtin(std::move($1), @$)); }
     | CALL_BUILTIN                             { $$ = std::unique_ptr<ast::Expression>(new ast::Builtin(std::move($1), @$)); }
     | IDENT                                    { $$ = std::unique_ptr<ast::Expression>(new ast::Identifier(std::move($1), @$)); }
     | STACK_MODE                               { $$ = std::unique_ptr<ast::Expression>(new ast::StackMode(std::move($1), @$)); }
     | ternary                                  { $$ = std::move($1); }
     | param                                    { $$ = std::move($1); }
     | map_or_var                               { $$ = std::move($1); }
     | call                                     { $$ = std::move($1); }
     | "(" expr ")"                             { $$ = std::move($2); }
     | expr EQ expr                             { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::EQ, std::move($3), @2)); }
     | expr NE expr                             { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::NE, std::move($3), @2)); }
     | expr LE expr                             { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::LE, std::move($3), @2)); }
     | expr GE expr                             { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::GE, std::move($3), @2)); }
     | expr LT expr                             { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::LT, std::move($3), @2)); }
     | expr GT expr                             { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::GT, std::move($3), @2)); }
     | expr LAND expr                           { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::LAND, std::move($3), @2)); }
     | expr LOR expr                            { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::LOR, std::move($3), @2)); }
     | expr LEFT expr                           { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::LEFT, std::move($3), @2)); }
     | expr RIGHT expr                          { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::RIGHT, std::move($3), @2)); }
     | expr PLUS expr                           { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::PLUS, std::move($3), @2)); }
     | expr MINUS expr                          { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::MINUS, std::move($3), @2)); }
     | expr MUL expr                            { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::MUL, std::move($3), @2)); }
     | expr DIV expr                            { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::DIV, std::move($3), @2)); }
     | expr MOD expr                            { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::MOD, std::move($3), @2)); }
     | expr BAND expr                           { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::BAND, std::move($3), @2)); }
     | expr BOR expr                            { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::BOR, std::move($3), @2)); }
     | expr BXOR expr                           { $$ = std::unique_ptr<ast::Expression>(new ast::Binop(std::move($1), token::BXOR, std::move($3), @2)); }
     | LNOT expr                                { $$ = std::unique_ptr<ast::Expression>(new ast::Unop(token::LNOT, std::move($2), @1)); }
     | BNOT expr                                { $$ = std::unique_ptr<ast::Expression>(new ast::Unop(token::BNOT, std::move($2), @1)); }
     | MINUS expr                               { $$ = std::unique_ptr<ast::Expression>(new ast::Unop(token::MINUS, std::move($2), @1)); }
     | MUL  expr %prec DEREF                    { $$ = std::unique_ptr<ast::Expression>(new ast::Unop(token::MUL,  std::move($2), @1)); }
     | expr DOT ident                           { $$ = std::unique_ptr<ast::Expression>(new ast::FieldAccess(std::move($1), $3, @2)); }
     | expr DOT INT                             { $$ = std::unique_ptr<ast::Expression>(new ast::FieldAccess(std::move($1), $3, @3)); }
     | expr PTR ident                           { $$ = std::unique_ptr<ast::Expression>(new ast::FieldAccess(std::unique_ptr<ast::Expression>(new ast::Unop(token::MUL, std::move($1), @2)), $3, @$)); }
     | expr "[" expr "]"                        { $$ = std::unique_ptr<ast::Expression>(new ast::ArrayAccess(std::move($1), std::move($3), @2 + @4)); }
     | "(" IDENT ")" expr %prec CAST            { $$ = std::unique_ptr<ast::Expression>(new ast::Cast(std::move($2), false, std::move($4), @1 + @3)); }
     | "(" IDENT MUL ")" expr %prec CAST        { $$ = std::unique_ptr<ast::Expression>(new ast::Cast(std::move($2), true, std::move($5), @1 + @4)); }
     | "(" expr "," vargs ")"                   {
                                                  auto args = std::make_unique<ast::ExpressionList>();
                                                  args->emplace_back(std::move($2));
                                                  args->insert(args->end(), std::move_iterator($4->begin()), std::move_iterator($4->end()));
                                                  $$ = std::unique_ptr<ast::Expression>(new ast::Tuple(std::move(args), @$));
                                                }
     | pre_post_op                              { $$ = std::move($1); }
     ;

pre_post_op : map_or_var INCREMENT   { $$ = std::unique_ptr<ast::Expression>(new ast::Unop(token::INCREMENT, std::move($1), true, @2)); }
            | map_or_var DECREMENT   { $$ = std::unique_ptr<ast::Expression>(new ast::Unop(token::DECREMENT, std::move($1), true, @2)); }
            | INCREMENT map_or_var   { $$ = std::unique_ptr<ast::Expression>(new ast::Unop(token::INCREMENT, std::move($2), @1)); }
            | DECREMENT map_or_var   { $$ = std::unique_ptr<ast::Expression>(new ast::Unop(token::DECREMENT, std::move($2), @1)); }
            | ident INCREMENT      { error(@1, "The ++ operator must be applied to a map or variable"); YYERROR; }
            | INCREMENT ident      { error(@1, "The ++ operator must be applied to a map or variable"); YYERROR; }
            | ident DECREMENT      { error(@1, "The -- operator must be applied to a map or variable"); YYERROR; }
            | DECREMENT ident      { error(@1, "The -- operator must be applied to a map or variable"); YYERROR; }
            ;

ident : IDENT         { $$ = std::move($1); }
      | BUILTIN       { $$ = std::move($1); }
      | CALL          { $$ = std::move($1); }
      | CALL_BUILTIN  { $$ = std::move($1); }
      | STACK_MODE    { $$ = std::move($1); }
      ;

call : CALL "(" ")"                 { $$ = std::unique_ptr<ast::Expression>(new ast::Call($1, @$)); }
     | CALL "(" vargs ")"           { $$ = std::unique_ptr<ast::Expression>(new ast::Call($1, std::move($3), @$)); }
     | CALL_BUILTIN  "(" ")"        { $$ = std::unique_ptr<ast::Expression>(new ast::Call($1, @$)); }
     | CALL_BUILTIN "(" vargs ")"   { $$ = std::unique_ptr<ast::Expression>(new ast::Call($1, std::move($3), @$)); }
     | IDENT "(" ")"                { error(@1, "Unknown function: " + $1); YYERROR;  }
     | IDENT "(" vargs ")"          { error(@1, "Unknown function: " + $1); YYERROR;  }
     | BUILTIN "(" ")"              { error(@1, "Unknown function: " + $1); YYERROR;  }
     | BUILTIN "(" vargs ")"        { error(@1, "Unknown function: " + $1); YYERROR;  }
     | STACK_MODE "(" ")"           { error(@1, "Unknown function: " + $1); YYERROR;  }
     | STACK_MODE "(" vargs ")"     { error(@1, "Unknown function: " + $1); YYERROR;  }
     ;

map : MAP               { $$ = std::make_unique<ast::Map>($1, @$); }
    | MAP "[" vargs "]" { $$ = std::make_unique<ast::Map>($1, std::move($3), @$); }
    ;

var : VAR { $$ = std::unique_ptr<ast::Variable>(new ast::Variable($1, @$)); }
    ;

map_or_var : var { $$ = std::move($1); }
           | map { $$ = std::move($1); }
           ;

vargs : vargs "," expr { $1->push_back(std::move($3)); $$ = std::move($1); }
      | expr           { $$ = std::make_unique<ast::ExpressionList>(); $$->push_back(std::move($1)); }
      ;

%%

void bpftrace::Parser::error(const location &l, const std::string &m)
{
  driver.error(l, m);
}
