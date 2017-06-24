#include <iostream>

#include "semantic_analyser.h"
#include "ast.h"
#include "parser.tab.hh"
#include "arch/arch.h"

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
      builtin.ident == "gid" ||
      builtin.ident == "retval") {
    type_ = Type::integer;
  }
  else if (builtin.ident == "stack")
  {
    type_ = Type::stack;
    needs_stackid_map_ = true;
  }
  else if (!builtin.ident.compare(0, 3, "arg") && builtin.ident.size() == 4 &&
      builtin.ident.at(3) >= '0' && builtin.ident.at(3) <= '9') {
    int arg_num = atoi(builtin.ident.substr(3).c_str());
    if (arg_num > arch::max_arg())
      err_ << arch::name() << " doesn't support " << builtin.ident << std::endl;
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
    if (nargs != 1) {
      err_ << "quantize() should take 1 argument (";
      err_ << nargs << " provided)" << std::endl;
    }
    if (type_ != Type::integer) {
      err_ << "quantize() only supports integer arguments";
      err_ << " (" << type_ << " provided)" << std::endl;
    }
    type_ = Type::quantize;
  }
  else if (call.func == "count") {
    if (nargs != 0) {
      err_ << "count() should take 0 arguments (";
      err_ << nargs << " provided)" << std::endl;
    }
    type_ = Type::count;
  }
  else if (call.func == "delete") {
    if (nargs != 0) {
      err_ << "delete() should take 0 arguments (";
      err_ << nargs << " provided)" << std::endl;
    }
    // Don't assign a type
  }
  else {
    type_ = Type::none;
    err_ << "Unknown function: '" << call.func << "'" << std::endl;
  }
}

void SemanticAnalyser::visit(Map &map)
{
  MapKey key;
  if (map.vargs) {
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
      key.args_.push_back({type_, 8});
    }
  }

  auto search = map_key_.find(map.ident);
  if (search != map_key_.end()) {
    if (search->second != key) {
      err_ << "Argument mismatch for " << map.ident << ": ";
      err_ << "trying to access with arguments: ";
      err_ << key.argument_type_list();
      err_ << "\n\twhen map expects arguments: ";
      err_ << search->second.argument_type_list();
      err_ << "\n" << std::endl;
    }
  }
  else {
    map_key_.insert({map.ident, key});
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

    auto search_args = map_key_.find(map_name);
    if (search_args == map_key_.end())
      abort();
    auto &key = search_args->second;

    bpftrace_.maps_[map_name] = std::make_unique<bpftrace::Map>(map_name, type, key);
  }

  if (needs_stackid_map_)
  {
    bpftrace_.stackid_map_ = std::make_unique<bpftrace::Map>("stackid");
  }

  return 0;
}

bool SemanticAnalyser::is_final_pass() const
{
  return pass_ == num_passes_;
}

} // namespace ast
} // namespace bpftrace
