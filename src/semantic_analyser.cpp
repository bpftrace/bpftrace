#include <iostream>

#include "semantic_analyser.h"
#include "ast.h"
#include "parser.tab.hh"

namespace bpftrace {
namespace ast {

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
  else if (call.func == "delete") {
    // Don't assign a type
    if (nargs != 0) {
      err_ << "delete() should take 0 arguments (";
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

  auto search = map_args_.find(map.ident);
  if (search != map_args_.end()) {
    if (search->second != args) {
      err_ << "Argument mismatch for " << map.ident << ": ";
      err_ << "trying to access with arguments: ";
      err_ << argument_list(args, true);
      err_ << "\n\twhen map expects arguments: ";
      err_ << argument_list(search->second, true);
      err_ << "\n" << std::endl;
    }
  }
  else {
    map_args_.insert({map.ident, args});
  }

  auto search_val = map_val_.find(map.ident);
  if (search_val != map_val_.end()) {
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
    err_ << "comparing '" << lhs << "' ";
    err_ << "with '" << rhs << "'" << std::endl;
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
  auto search = map_val_.find(map_ident);
  if (search != map_val_.end()) {
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
      err_ << "trying to assign value of type '" << type_;
      err_ << "'\n\twhen map already contains a value of type '";
      err_ << search->second << "'\n" << std::endl;
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
      err_ << search->second << "'\n" << std::endl;
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

int SemanticAnalyser::create_maps()
{
  for (auto &map_val : map_val_)
  {
    std::string map_name = map_val.first;
    Type type = map_val.second;

    auto search_args = map_args_.find(map_name);
    if (search_args == map_args_.end())
      abort();
    auto &args = search_args->second;

    bpftrace_.maps_[map_name] = std::make_unique<bpftrace::Map>(map_name, type, args);
  }

  return 0;
}

bool SemanticAnalyser::is_final_pass() const
{
  return pass_ == num_passes_;
}

} // namespace ast
} // namespace bpftrace
