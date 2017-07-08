#include <iostream>

#include "semantic_analyser.h"
#include "ast.h"
#include "parser.tab.hh"
#include "arch/arch.h"

namespace bpftrace {
namespace ast {

void SemanticAnalyser::visit(Integer &integer)
{
  integer.type = SizedType(Type::integer, 8);
}

void SemanticAnalyser::visit(String &string)
{
  if (string.str.size() > STRING_SIZE-1) {
    err_ << "String is too long (over " << STRING_SIZE << " bytes): " << string.str << std::endl;
  }
  string.type = SizedType(Type::string, STRING_SIZE);
}

void SemanticAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "nsecs" ||
      builtin.ident == "pid" ||
      builtin.ident == "tid" ||
      builtin.ident == "uid" ||
      builtin.ident == "gid" ||
      builtin.ident == "retval") {
    builtin.type = SizedType(Type::integer, 8);
  }
  else if (builtin.ident == "stack") {
    builtin.type = SizedType(Type::stack, 8);
    needs_stackid_map_ = true;
  }
  else if (builtin.ident == "ustack") {
    builtin.type = SizedType(Type::ustack, 8);
    needs_stackid_map_ = true;
  }
  else if (builtin.ident == "comm") {
    builtin.type = SizedType(Type::string, STRING_SIZE);
  }
  else if (!builtin.ident.compare(0, 3, "arg") && builtin.ident.size() == 4 &&
      builtin.ident.at(3) >= '0' && builtin.ident.at(3) <= '9') {
    int arg_num = atoi(builtin.ident.substr(3).c_str());
    if (arg_num > arch::max_arg())
      err_ << arch::name() << " doesn't support " << builtin.ident << std::endl;
    builtin.type = SizedType(Type::integer, 8);
  }
  else {
    builtin.type = SizedType(Type::none, 0);
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
    if (call.vargs->at(0)->type.type != Type::integer) {
      err_ << "quantize() only supports integer arguments";
      err_ << " (" << call.vargs->at(0)->type.type << " provided)" << std::endl;
    }
    call.type = SizedType(Type::quantize, 8);
  }
  else if (call.func == "count") {
    if (nargs != 0) {
      err_ << "count() should take 0 arguments (";
      err_ << nargs << " provided)" << std::endl;
    }
    call.type = SizedType(Type::count, 8);
  }
  else if (call.func == "delete") {
    if (nargs != 0) {
      err_ << "delete() should take 0 arguments (";
      err_ << nargs << " provided)" << std::endl;
    }
    // Don't assign a type
  }
  else {
    call.type = SizedType(Type::none, 0);
    err_ << "Unknown function: '" << call.func << "'" << std::endl;
  }
}

void SemanticAnalyser::visit(Map &map)
{
  MapKey key;
  if (map.vargs) {
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
      key.args_.push_back({expr->type.type, expr->type.size});
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
    map.type = search_val->second;
  }
  else {
    if (is_final_pass()) {
      err_ << "Undefined map: " << map.ident << std::endl;
    }
    map.type = SizedType(Type::none, 0);
  }
}

void SemanticAnalyser::visit(Binop &binop)
{
  binop.left->accept(*this);
  binop.right->accept(*this);
  Type &lhs = binop.left->type.type;
  Type &rhs = binop.right->type.type;

  if (is_final_pass()) {
    if (lhs != rhs) {
      err_ << "Type mismatch for '" << opstr(binop) << "': ";
      err_ << "comparing '" << lhs << "' ";
      err_ << "with '" << rhs << "'" << std::endl;
    }
    else if (lhs != Type::integer &&
             binop.op != Parser::token::EQ &&
             binop.op != Parser::token::NE) {
      err_ << "The " << opstr(binop) << " operator can not be used on expressions of type " << lhs << std::endl;
    }
  }

  binop.type = SizedType(Type::integer, 8);
}

void SemanticAnalyser::visit(Unop &unop)
{
  unop.expr->accept(*this);

  if (unop.expr->type.type != Type::integer) {
    err_ << "The " << opstr(unop) << " operator can not be used on expressions of type " << unop.expr->type << std::endl;
  }

  unop.type = SizedType(Type::integer, 8);
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
    if (search->second.type == Type::none) {
      if (is_final_pass()) {
        err_ << "Undefined map: " << map_ident << std::endl;
      }
      else {
        search->second = assignment.expr->type;
      }
    }
    else if (search->second.type != assignment.expr->type.type) {
      err_ << "Type mismatch for " << map_ident << ": ";
      err_ << "trying to assign value of type '" << assignment.expr->type;
      err_ << "'\n\twhen map already contains a value of type '";
      err_ << search->second << "'\n" << std::endl;
    }
  }
  else {
    // This map hasn't been seen before
    map_val_.insert({map_ident, assignment.expr->type});
  }
}

void SemanticAnalyser::visit(AssignMapCallStatement &assignment)
{
  assignment.map->accept(*this);
  assignment.call->accept(*this);

  std::string map_ident = assignment.map->ident;
  auto search = map_val_.find(map_ident);
  if (search != map_val_.end()) {
    if (search->second.type == Type::none) {
      if (is_final_pass()) {
        err_ << "Undefined map: " << map_ident << std::endl;
      }
      else {
        search->second = assignment.call->type;
      }
    }
    else if (search->second.type != assignment.call->type.type) {
      err_ << "Type mismatch for " << map_ident << ": ";
      err_ << "trying to assign result of '" << assignment.call->func;
      err_ << "()'\n\twhen map already contains a value of type '";
      err_ << search->second << "'\n" << std::endl;
    }
  }
  else {
    // This map hasn't been seen before
    map_val_.insert({map_ident, assignment.call->type});
  }
}

void SemanticAnalyser::visit(Predicate &pred)
{
  pred.expr->accept(*this);
  if (is_final_pass() && pred.expr->type.type != Type::integer) {
    err_ << "Invalid type for predicate: " << pred.expr->type.type << std::endl;
  }
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
    SizedType type = map_val.second;

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
