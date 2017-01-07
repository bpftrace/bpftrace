#include <iostream>

#include "semantic_analyser.h"
#include "ast.h"
#include "parser.tab.hh"

namespace ebpf {
namespace bpftrace {
namespace ast {

void SemanticAnalyser::visit(Integer &integer)
{
  type_ = Type::integer;
}

void SemanticAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "nsecs" ||
      builtin.ident == "pid" ||
      builtin.ident == "tid") {
    type_ = Type::integer;
  }
  else {
    type_ = Type::none;
    err_ << "Unknown builtin: '" << builtin.ident << "'" << std::endl;
  }
}

void SemanticAnalyser::visit(Call &call)
{
  if (call.vargs) {
    for (Expression *expr : *call.vargs) {
      expr->accept(*this);
    }
  }

  if (call.func == "quantize")
    type_ = Type::quantize;
  else if (call.func == "count")
    type_ = Type::count;
  else {
    type_ = Type::none;
    err_ << "Unknown function: '" << call.func << "'" << std::endl;
  }
}

void SemanticAnalyser::visit(Map &map)
{
  std::vector<Type> args;
  if (map.vargs) {
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
      args.push_back(type_);
    }
  }

  auto search = map_args_.find(map.ident);
  if (search != map_args_.end()) {
    if (search->second != args) {
      err_ << "Argument mismatch for " << map.ident << ": ";
      err_ << "trying to access with arguments: [ ";
      for (Type t : args) { err_ << typestr(t) << " "; }
      err_ << "]" << std::endl;
      err_ << "when map already uses the arguments: [ ";
      for (Type t : search->second) { err_ << typestr(t) << " "; }
      err_ << "]" << std::endl;
    }
  }
  else {
    map_args_.insert({map.ident, args});
  }
}

void SemanticAnalyser::visit(Binop &binop)
{
  binop.left->accept(*this);
  switch (binop.op) {
    case ebpf::bpftrace::Parser::token::EQ:    break;
    case ebpf::bpftrace::Parser::token::NE:    break;
    case ebpf::bpftrace::Parser::token::LE:    break;
    case ebpf::bpftrace::Parser::token::GE:    break;
    case ebpf::bpftrace::Parser::token::LT:    break;
    case ebpf::bpftrace::Parser::token::GT:    break;
    case ebpf::bpftrace::Parser::token::LAND:  break;
    case ebpf::bpftrace::Parser::token::LOR:   break;
    case ebpf::bpftrace::Parser::token::PLUS:  break;
    case ebpf::bpftrace::Parser::token::MINUS: break;
    case ebpf::bpftrace::Parser::token::MUL:   break;
    case ebpf::bpftrace::Parser::token::DIV:   break;
    case ebpf::bpftrace::Parser::token::MOD:   break;
    case ebpf::bpftrace::Parser::token::BAND:  break;
    case ebpf::bpftrace::Parser::token::BOR:   break;
    case ebpf::bpftrace::Parser::token::BXOR:  break;
    default: abort();
  }
  binop.right->accept(*this);
}

void SemanticAnalyser::visit(Unop &unop)
{
  switch (unop.op) {
    case ebpf::bpftrace::Parser::token::LNOT: break;
    case ebpf::bpftrace::Parser::token::BNOT: break;
    default: abort();
  }
  unop.expr->accept(*this);
}

void SemanticAnalyser::visit(ExprStatement &expr)
{
  expr.expr->accept(*this);
}

void SemanticAnalyser::visit(AssignMapStatement &assignment)
{
  assignment.map->accept(*this);
  assignment.expr->accept(*this);

  std::string map_ident = assignment.map->ident;
  auto search = map_val_.find(map_ident);
  if (search != map_val_.end()) {
    if (search->second != type_) {
      err_ << "Type mismatch for " << map_ident << ": ";
      err_ << "trying to assign variable of type '" << typestr(type_);
      err_ << "' when map already contains a '";
      err_ << typestr(search->second) << "'" << std::endl;
    }
  }
  else {
    // This map hasn't been seen before
    map_val_.insert({map_ident, type_});
  }
}

void SemanticAnalyser::visit(AssignMapCallStatement &assignment)
{
  assignment.map->accept(*this);
  assignment.call->accept(*this);

  std::string map_ident = assignment.map->ident;
  auto search = map_val_.find(map_ident);
  if (search != map_val_.end()) {
    if (search->second != type_) {
      err_ << "Type mismatch for " << map_ident << ": ";
      err_ << "trying to assign result of '" << assignment.call->func;
      err_ << "'" << typestr(type_);
      err_ << "' when map already contains a '";
      err_ << typestr(search->second) << "'" << std::endl;
    }
  }
  else {
    // This map hasn't been seen before
    map_val_.insert({map_ident, type_});
  }
}

void SemanticAnalyser::visit(Predicate &pred)
{
  pred.expr->accept(*this);
}

void SemanticAnalyser::visit(Probe &probe)
{
  if (probe.pred) {
    probe.pred->accept(*this);
  }
  for (Statement *stmt : *probe.stmts) {
    stmt->accept(*this);
  }
}

void SemanticAnalyser::visit(Program &program)
{
  for (Probe *probe : *program.probes) {
    probe->accept(*this);
  }
}

int SemanticAnalyser::analyse()
{
  root_->accept(*this);

  std::string errors = err_.str();
  if (errors.empty()) {
    return 0;
  }
  else {
    std::cerr << errors;
    return 1;
  }
}

std::string SemanticAnalyser::typestr(Type t)
{
  switch (t)
  {
    case Type::none:     return "none";     break;
    case Type::integer:  return "integer";  break;
    case Type::quantize: return "quantize"; break;
    case Type::count:    return "count";    break;
    default: abort();
  }
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
