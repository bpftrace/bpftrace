#include <iostream>

#include "semantic_analyser.h"
#include "ast.h"
#include "parser.tab.hh"

namespace ebpf {
namespace bpftrace {
namespace ast {

using ebpf::bpftrace::typestr;

void SemanticAnalyser::visit(Integer &)
{
  type_ = Type::integer;
}

void SemanticAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "nsecs" ||
      builtin.ident == "pid" ||
      builtin.ident == "tid" ||
      builtin.ident == "uid" ||
      builtin.ident == "gid") {
    type_ = Type::integer;
  }
  else {
    type_ = Type::none;
    err_ << "Unknown builtin: '" << builtin.ident << "'" << std::endl;
  }
}

void SemanticAnalyser::visit(Call &call)
{
  std::vector<Expression*>::size_type nargs = 0;
  if (call.vargs) {
    nargs = call.vargs->size();
    for (Expression *expr : *call.vargs) {
      expr->accept(*this);
    }
  }

  if (call.func == "quantize") {
    type_ = Type::quantize;
    if (nargs != 1) {
      err_ << "quantize() should take 1 argument (";
      err_ << nargs << " provided)" << std::endl;
    }
  }
  else if (call.func == "count") {
    type_ = Type::count;
    if (nargs != 0) {
      err_ << "count() should take 0 arguments (";
      err_ << nargs << " provided)" << std::endl;
    }
  }
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

  auto search = bpftrace_.map_args_.find(map.ident);
  if (search != bpftrace_.map_args_.end()) {
    if (search->second != args) {
      err_ << "Argument mismatch for " << map.ident << ": ";
      err_ << "trying to access with arguments: [ ";
      for (Type t : args) { err_ << typestr(t) << " "; }
      err_ << "]\n\twhen map expects arguments: [ ";
      for (Type t : search->second) { err_ << typestr(t) << " "; }
      err_ << "]\n" << std::endl;
    }
  }
  else {
    bpftrace_.map_args_.insert({map.ident, args});
  }

  auto search_val = bpftrace_.map_val_.find(map.ident);
  if (search_val != bpftrace_.map_val_.end()) {
    type_ = search_val->second;
  }
  else {
    if (is_final_pass()) {
      err_ << "Undefined map: " << map.ident << std::endl;
    }
    type_ = Type::none;
  }
}

void SemanticAnalyser::visit(Binop &binop)
{
  Type lhs, rhs;
  binop.left->accept(*this);
  lhs = type_;
  binop.right->accept(*this);
  rhs = type_;

  if (is_final_pass() && lhs != rhs) {
    err_ << "Type mismatch for '" << opstr(binop) << "': ";
    err_ << "comparing '" << typestr(lhs) << "' ";
    err_ << "with '" << typestr(rhs) << "'" << std::endl;
  }

  type_ = Type::integer;
}

void SemanticAnalyser::visit(Unop &unop)
{
  unop.expr->accept(*this);
  type_ = Type::integer;
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
  auto search = bpftrace_.map_val_.find(map_ident);
  if (search != bpftrace_.map_val_.end()) {
    if (search->second == Type::none) {
      if (is_final_pass()) {
        err_ << "Undefined map: " << map_ident << std::endl;
      }
      else {
        search->second = type_;
      }
    }
    else if (search->second != type_) {
      err_ << "Type mismatch for " << map_ident << ": ";
      err_ << "trying to assign value of type '" << typestr(type_);
      err_ << "'\n\twhen map already contains a value of type '";
      err_ << typestr(search->second) << "'\n" << std::endl;
    }
  }
  else {
    // This map hasn't been seen before
    bpftrace_.map_val_.insert({map_ident, type_});
  }
}

void SemanticAnalyser::visit(AssignMapCallStatement &assignment)
{
  assignment.map->accept(*this);
  assignment.call->accept(*this);

  std::string map_ident = assignment.map->ident;
  auto search = bpftrace_.map_val_.find(map_ident);
  if (search != bpftrace_.map_val_.end()) {
    if (search->second == Type::none) {
      if (is_final_pass()) {
        err_ << "Undefined map: " << map_ident << std::endl;
      }
      else {
        search->second = type_;
      }
    }
    else if (search->second != type_) {
      err_ << "Type mismatch for " << map_ident << ": ";
      err_ << "trying to assign result of '" << assignment.call->func;
      err_ << "()'\n\twhen map already contains a value of type '";
      err_ << typestr(search->second) << "'\n" << std::endl;
    }
  }
  else {
    // This map hasn't been seen before
    bpftrace_.map_val_.insert({map_ident, type_});
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

  if (is_final_pass() && bpftrace_.add_probe(probe)) {
    err_ << "Invalid probe type: '" << probe.type << "'" << std::endl;
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
  // Multiple passes to handle variables being used before they are defined
  std::string errors;

  for (pass_ = 1; pass_ <= num_passes_; pass_++) {
    root_->accept(*this);
    errors = err_.str();
    if (!errors.empty()) {
      out_ << errors;
      return pass_;
    }
  }

  return 0;
}

bool SemanticAnalyser::is_final_pass() const
{
  return pass_ == num_passes_;
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
