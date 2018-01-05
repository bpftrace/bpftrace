#include "semantic_analyser.h"
#include "ast.h"
#include "fake_map.h"
#include "parser.tab.hh"
#include "printf.h"
#include "arch/arch.h"

#include "libbpf.h"

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
      builtin.ident == "cpu" ||
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
  else if (builtin.ident == "func") {
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type == ProbeType::kprobe ||
          type == ProbeType::kretprobe ||
          type == ProbeType::tracepoint)
        builtin.type = SizedType(Type::sym, 8);
      else if (type == ProbeType::uprobe || type == ProbeType::uretprobe)
        builtin.type = SizedType(Type::usym, 8);
      else
        err_ << "The func builtin can not be used with '" << attach_point->provider
             << "' probes" << std::endl;
    }
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
    err_ << "Unknown builtin variable: '" << builtin.ident << "'" << std::endl;
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
    if (!call.map) {
      err_ << "quantize() should be assigned to a map" << std::endl;
    }
    if (nargs != 1) {
      err_ << "quantize() should take 1 argument (";
      err_ << nargs << " provided)" << std::endl;
    }
    if (is_final_pass() && call.vargs->at(0)->type.type != Type::integer) {
      err_ << "quantize() only supports integer arguments";
      err_ << " (" << call.vargs->at(0)->type.type << " provided)" << std::endl;
    }
    call.type = SizedType(Type::quantize, 8);
  }
  else if (call.func == "count") {
    if (!call.map) {
      err_ << "count() should be assigned to a map" << std::endl;
    }
    if (nargs != 0) {
      err_ << "count() should take 0 arguments (";
      err_ << nargs << " provided)" << std::endl;
    }
    call.type = SizedType(Type::count, 8);
  }
  else if (call.func == "delete") {
    if (!call.map) {
      err_ << "delete() should be assigned to a map" << std::endl;
    }
    if (nargs != 0) {
      err_ << "delete() should take 0 arguments (";
      err_ << nargs << " provided)" << std::endl;
    }
    call.type = SizedType(Type::del, 0);
  }
  else if (call.func == "str" || call.func == "sym" || call.func == "usym") {
    if (nargs != 1) {
      err_ << call.func << "() should take 1 argument (";
      err_ << nargs << " provided)" << std::endl;
    }
    if (is_final_pass() && call.vargs->at(0)->type.type != Type::integer) {
      err_ << call.func << "() only supports integer arguments";
      err_ << " (" << call.vargs->at(0)->type.type << " provided)" << std::endl;
    }

    if (call.func == "str")
      call.type = SizedType(Type::string, STRING_SIZE);
    else if (call.func == "sym")
      call.type = SizedType(Type::sym, 8);
    else if (call.func == "usym")
      call.type = SizedType(Type::usym, 8);
  }
  else if (call.func == "reg") {
    if (nargs != 1) {
      err_ << call.func << "() should take 1 argument (";
      err_ << nargs << " provided)" << std::endl;
    }
    else {
      auto &arg = *call.vargs->at(0);
      if (arg.type.type != Type::string || !arg.is_literal) {
        err_ << "reg() expects a string literal";
        err_ << " (" << arg.type.type << " provided)" << std::endl;
      }
      else {
        auto &reg_name = static_cast<String&>(arg).str;
        int offset = arch::offset(reg_name);;
        if (offset == -1) {
          err_ << "'" << reg_name << "' is not a valid register on this architecture";
          err_ << " (" << arch::name() << ")" << std::endl;
        }
      }
    }

    call.type = SizedType(Type::integer, 8);
  }
  else if (call.func == "printf") {
    if (call.map) {
      err_ << "printf() should not be assigned to a map" << std::endl;
    }
    if (nargs == 0) {
      err_ << "printf() requires at least 1 argument (";
      err_ << nargs << " provided)" << std::endl;
    }
    if (nargs > 7) {
      err_ << "printf() can only take up to 7 arguments (";
      err_ << nargs << " provided)" << std::endl;
    }
    if (nargs > 0) {
      Expression &fmt_arg = *call.vargs->at(0);
      if (fmt_arg.type.type != Type::string || !fmt_arg.is_literal) {
        err_ << "The first argument to printf() must be a string literal";
        err_ << " (" << fmt_arg.type.type << " provided)" << std::endl;
      }
      if (is_final_pass()) {
        String &fmt = static_cast<String&>(fmt_arg);
        std::vector<SizedType> args;
        for (auto iter = call.vargs->begin()+1; iter != call.vargs->end(); iter++) {
          args.push_back((*iter)->type);
        }
        err_ << verify_format_string(fmt.str, args);

        bpftrace_.printf_args_.push_back(std::make_tuple(fmt.str, args));
      }
    }
    call.type = SizedType(Type::none, 0);
  }
  else {
    err_ << "Unknown function: '" << call.func << "'" << std::endl;
    call.type = SizedType(Type::none, 0);
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

void SemanticAnalyser::visit(Variable &var)
{
  auto search_val = variable_val_.find(var.ident);
  if (search_val != variable_val_.end()) {
    var.type = search_val->second;
  }
  else {
    err_ << "Undefined variable: " << var.ident << std::endl;
    var.type = SizedType(Type::none, 0);
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

  if (is_final_pass() && unop.expr->type.type != Type::integer) {
    err_ << "The " << opstr(unop) << " operator can not be used on expressions of type " << unop.expr->type << std::endl;
  }

  unop.type = SizedType(Type::integer, 8);
}

void SemanticAnalyser::visit(FieldAccess &acc)
{
  acc.expr->accept(*this);

  if (acc.expr->type.type != Type::cast) {
    if (is_final_pass()) {
      err_ << "Can not access field '" << acc.field
           << "' on expression of type '" << acc.expr->type
           << "'" << std::endl;
    }
    return;
  }

  std::string cast_type;
  if (acc.expr->is_variable) {
    auto var = static_cast<Variable*>(acc.expr);
    cast_type = variable_casts_[var->ident];
  }
  else if (acc.expr->is_map) {
    auto map = static_cast<Map*>(acc.expr);
    cast_type = map_casts_[map->ident];
  }
  else if (acc.expr->is_cast) {
    auto cast = static_cast<Cast*>(acc.expr);
    cast_type = cast->cast_type;
  }
  else {
    abort();
  }

  auto fields = bpftrace_.structs_[cast_type];
  if (fields.count(acc.field) == 0) {
    err_ << "Struct/union of type '" << cast_type << "' does not contain "
         << "a field named '" << acc.field << "'" << std::endl;
  }
  else {
    acc.type = std::get<0>(fields[acc.field]);
  }
}

void SemanticAnalyser::visit(Cast &cast)
{
  cast.expr->accept(*this);
  cast.type = SizedType(Type::cast, cast.expr->type.size);

  if (bpftrace_.structs_.count(cast.cast_type) == 0) {
    err_ << "Unknown struct/union: '" << cast.cast_type << "'" << std::endl;
  }
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
    else if (search->second.type != assignment.expr->type.type &&
             assignment.expr->type.type != Type::del) {
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

  if (assignment.expr->type.type == Type::cast) {
    auto cast = static_cast<Cast*>(assignment.expr);
    if (map_casts_.count(map_ident) > 0 &&
        map_casts_[map_ident] != cast->cast_type) {
      err_ << "Type mismatch for " << map_ident << ": ";
      err_ << "trying to assign value of type '" << cast->cast_type;
      err_ << "'\n\twhen map already contains a value of type '";
      err_ << map_casts_[map_ident] << "'\n" << std::endl;
    }
    else {
      map_casts_[map_ident] = cast->cast_type;
    }
  }
}

void SemanticAnalyser::visit(AssignVarStatement &assignment)
{
  assignment.expr->accept(*this);

  std::string var_ident = assignment.var->ident;
  auto search = variable_val_.find(var_ident);
  if (search != variable_val_.end()) {
    if (search->second.type == Type::none) {
      if (is_final_pass()) {
        err_ << "Undefined variable: " << var_ident << std::endl;
      }
      else {
        search->second = assignment.expr->type;
      }
    }
    else if (search->second.type != assignment.expr->type.type &&
             assignment.expr->type.type != Type::del) {
      err_ << "Type mismatch for " << var_ident << ": ";
      err_ << "trying to assign value of type '" << assignment.expr->type;
      err_ << "'\n\twhen variable already contains a value of type '";
      err_ << search->second << "'\n" << std::endl;
    }
  }
  else {
    // This variable hasn't been seen before
    variable_val_.insert({var_ident, assignment.expr->type});
    assignment.var->type = assignment.expr->type;
  }

  if (assignment.expr->type.type == Type::cast) {
    auto cast = static_cast<Cast*>(assignment.expr);
    if (variable_casts_.count(var_ident) > 0 &&
        variable_casts_[var_ident] != cast->cast_type) {
      err_ << "Type mismatch for " << var_ident << ": ";
      err_ << "trying to assign value of type '" << cast->cast_type;
      err_ << "'\n\twhen variable already contains a value of type '";
      err_ << variable_casts_[var_ident] << "'\n" << std::endl;
    }
    else {
      variable_casts_[var_ident] = cast->cast_type;
    }
  }
}

void SemanticAnalyser::visit(Predicate &pred)
{
  pred.expr->accept(*this);
  if (is_final_pass() && pred.expr->type.type != Type::integer) {
    err_ << "Invalid type for predicate: " << pred.expr->type.type << std::endl;
  }
}

void SemanticAnalyser::visit(AttachPoint &ap)
{
  if (ap.provider == "kprobe" || ap.provider == "kretprobe") {
    if (ap.target != "")
      err_ << "kprobes should not have a target" << std::endl;
    if (ap.func == "")
      err_ << "kprobes should be attached to a function" << std::endl;
  }
  else if (ap.provider == "uprobe" || ap.provider == "uretprobe") {
    if (ap.target == "")
      err_ << "uprobes should have a target" << std::endl;
    if (ap.func == "")
      err_ << "uprobes should be attached to a function" << std::endl;
  }
  else if (ap.provider == "tracepoint") {
    if (ap.target == "" || ap.func == "")
      err_ << "tracepoint probe must have a target" << std::endl;
  }
  else if (ap.provider == "profile") {
    if (ap.target == "")
      err_ << "profile probe must have unit of time" << std::endl;
    else if (ap.target != "hz" &&
             ap.target != "us" &&
             ap.target != "ms" &&
             ap.target != "s")
      err_ << ap.target << " is not an accepted unit of time" << std::endl;
    if (ap.func != "")
      err_ << "profile probe must have an integer frequency" << std::endl;
    else if (ap.freq <= 0)
      err_ << "profile frequency should be a positive integer" << std::endl;
  }
  else if (ap.provider == "BEGIN" || ap.provider == "END") {
    if (ap.target != "" || ap.func != "")
      err_ << "BEGIN/END probes should not have a target" << std::endl;
    if (is_final_pass()) {
      if (ap.provider == "BEGIN") {
        if (has_begin_probe_)
          err_ << "More than one BEGIN probe defined" << std::endl;
        has_begin_probe_ = true;
      }
      if (ap.provider == "END") {
        if (has_end_probe_)
          err_ << "More than one END probe defined" << std::endl;
        has_end_probe_ = true;
      }
    }
  }
  else {
    err_ << "Invalid provider: '" << ap.provider << "'" << std::endl;
  }
}

void SemanticAnalyser::visit(Probe &probe)
{
  // Clear out map of variable names - variables should be probe-local
  variable_val_.clear();
  variable_casts_.clear();
  probe_ = &probe;

  for (AttachPoint *ap : *probe.attach_points) {
    ap->accept(*this);
  }
  if (probe.pred) {
    probe.pred->accept(*this);
  }
  for (Statement *stmt : *probe.stmts) {
    stmt->accept(*this);
  }

  if (is_final_pass()) {
    bpftrace_.add_probe(probe);
  }
}

void SemanticAnalyser::visit(Include &include)
{
}

void SemanticAnalyser::visit(Program &program)
{
  for (Include *include : *program.includes)
    include->accept(*this);
  for (Probe *probe : *program.probes)
    probe->accept(*this);
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

int SemanticAnalyser::create_maps(bool debug)
{
  for (auto &map_val : map_val_)
  {
    std::string map_name = map_val.first;
    SizedType type = map_val.second;

    auto search_args = map_key_.find(map_name);
    if (search_args == map_key_.end())
      abort();
    auto &key = search_args->second;

    if (debug)
      bpftrace_.maps_[map_name] = std::make_unique<bpftrace::FakeMap>(map_name, type, key);
    else
      bpftrace_.maps_[map_name] = std::make_unique<bpftrace::Map>(map_name, type, key);
  }

  if (debug)
  {
    if (needs_stackid_map_)
      bpftrace_.stackid_map_ = std::make_unique<bpftrace::FakeMap>(BPF_MAP_TYPE_STACK_TRACE);
    bpftrace_.perf_event_map_ = std::make_unique<bpftrace::FakeMap>(BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  }
  else
  {
    if (needs_stackid_map_)
      bpftrace_.stackid_map_ = std::make_unique<bpftrace::Map>(BPF_MAP_TYPE_STACK_TRACE);
    bpftrace_.perf_event_map_ = std::make_unique<bpftrace::Map>(BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  }

  return 0;
}

bool SemanticAnalyser::is_final_pass() const
{
  return pass_ == num_passes_;
}

} // namespace ast
} // namespace bpftrace
