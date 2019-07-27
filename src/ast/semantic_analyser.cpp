#include "semantic_analyser.h"
#include "ast.h"
#include "fake_map.h"
#include "parser.tab.hh"
#include "printf.h"
#include "tracepoint_format_parser.h"
#include "utils.h"
#include "arch/arch.h"
#include "list.h"
#include <algorithm>
#include <cstring>
#include <sys/stat.h>
#include <regex>

#include "libbpf.h"

namespace bpftrace {
namespace ast {

void SemanticAnalyser::visit(Integer &integer)
{
  integer.type = SizedType(Type::integer, 8);
}

void SemanticAnalyser::visit(PositionalParameter &param)
{
  param.type = SizedType(Type::integer, 8);
  switch (param.ptype) {
    case PositionalParameterType::positional:
      if (param.n <= 0) {
        err_ << "$" << param.n << " is not a valid parameter" << std::endl;
      }
      if (is_final_pass()) {
        std::string pstr = bpftrace_.get_param(param.n, param.is_in_str);
        if (!bpftrace_.is_numeric(pstr) && !param.is_in_str) {
          err_ << "$" << param.n << " used numerically, but given \"" << pstr
               << "\". Try using str($" << param.n << ")." << std::endl;
        }
        if (bpftrace_.is_numeric(pstr) && param.is_in_str) {
          // This is blocked due to current limitations in our codegen
          err_ << "$" << param.n << " used in str(), but given numeric value: "
               << pstr << ". Try $" << param.n << " instead of str($"
               << param.n << ")." << std::endl;
        }
      }
      break;
    case PositionalParameterType::count:
      if (is_final_pass() && param.is_in_str) {
        err_ << "use $#, not str($#)" << std::endl;
      }
      break;
    default:
      err_ << "unknown parameter type" << std::endl;
      param.type = SizedType(Type::none, 0);
      break;
  }
}

void SemanticAnalyser::visit(String &string)
{
  if (string.str.size() > STRING_SIZE-1) {
    err_ << "String is too long (over " << STRING_SIZE << " bytes): "
         << string.str << std::endl;
  }
  string.type = SizedType(Type::string, STRING_SIZE);
}

void SemanticAnalyser::visit(StackMode &mode)
{
  mode.type = SizedType(Type::stack_mode, 0);
  if (mode.mode == "bpftrace") {
    mode.type.stack_type.mode = bpftrace::StackMode::bpftrace;
  } else if (mode.mode == "perf") {
    mode.type.stack_type.mode = bpftrace::StackMode::perf;
  } else {
    mode.type = SizedType(Type::none, 0);
    err_ << "Unknown stack mode: '" << mode.mode << "'" << std::endl;
  }
}

void SemanticAnalyser::visit(Identifier &identifier)
{
  if (bpftrace_.enums_.count(identifier.ident) != 0) {
    identifier.type = SizedType(Type::integer, 8);
  }
  else {
    identifier.type = SizedType(Type::none, 0);
    err_ << "Unknown identifier: '" << identifier.ident << "'" << std::endl;
  }
}

void SemanticAnalyser::visit(Builtin &builtin)
{
  std::stringstream buf;
  if (builtin.ident == "nsecs" ||
      builtin.ident == "elapsed" ||
      builtin.ident == "pid" ||
      builtin.ident == "tid" ||
      builtin.ident == "cgroup" ||
      builtin.ident == "uid" ||
      builtin.ident == "gid" ||
      builtin.ident == "cpu" ||
      builtin.ident == "curtask" ||
      builtin.ident == "rand" ||
      builtin.ident == "ctx") {
    builtin.type = SizedType(Type::integer, 8);
    if (builtin.ident == "cgroup") {
      #ifndef HAVE_GET_CURRENT_CGROUP_ID
      buf << "BPF_FUNC_get_current_cgroup_id is not available for your kernel version";
      #endif
    }
  }
  else if (builtin.ident == "retval") {
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::kretprobe && type != ProbeType::uretprobe) {
        buf << "The retval builtin can only be used with 'kretprobe' and 'uretprobe' probes"
            << (type == ProbeType::tracepoint ? " (try to use args->ret instead)" : "");
      }
    }
    builtin.type = SizedType(Type::integer, 8);
  }
  else if (builtin.ident == "kstack") {
    builtin.type = SizedType(Type::kstack, StackType());
    needs_stackid_maps_.insert(builtin.type.stack_type);
  }
  else if (builtin.ident == "ustack") {
    builtin.type = SizedType(Type::ustack, StackType());
    needs_stackid_maps_.insert(builtin.type.stack_type);
  }
  else if (builtin.ident == "comm") {
    builtin.type = SizedType(Type::string, COMM_SIZE);
  }
  else if (builtin.ident == "func") {
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type == ProbeType::kprobe ||
          type == ProbeType::kretprobe)
        builtin.type = SizedType(Type::ksym, 8);
      else if (type == ProbeType::uprobe || type == ProbeType::uretprobe)
        builtin.type = SizedType(Type::usym, 16);
      else
        buf << "The func builtin can not be used with '" << attach_point->provider
            << "' probes";
    }
  }
  else if (!builtin.ident.compare(0, 3, "arg") && builtin.ident.size() == 4 &&
      builtin.ident.at(3) >= '0' && builtin.ident.at(3) <= '9') {
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::kprobe &&
          type != ProbeType::uprobe &&
          type != ProbeType::usdt)
        buf << "The " << builtin.ident << " builtin can only be used with "
            << "'kprobes', 'uprobes' and 'usdt' probes";
    }
    int arg_num = atoi(builtin.ident.substr(3).c_str());
    if (arg_num > arch::max_arg())
      buf << arch::name() << " doesn't support " << builtin.ident;
    builtin.type = SizedType(Type::integer, 8);
  }
  else if (builtin.ident == "probe") {
    builtin.type = SizedType(Type::probe, 8);
    probe_->need_expansion = true;
  }
  else if (builtin.ident == "username") {
    builtin.type = SizedType(Type::username, 8);
  }
  else if (builtin.ident == "args") {
    probe_->need_expansion = true;
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::tracepoint) {
        buf << "The args builtin can only be used with tracepoint probes "
             << "(" << attach_point->provider << " used here)";
        continue;
      }

      /*
       * tracepoint wildcard expansion, part 2 of 3. This:
       * 1. expands the wildcard, then sets args to be the first matched probe.
       *    This is so that enough of the type information is available to
       *    survive the later semantic analyser checks.
       * 2. sets is_tparg so that codegen does the real type setting after
       *    expansion.
       */
      auto symbol_stream = bpftrace_.get_symbols_from_file(
          "/sys/kernel/debug/tracing/available_events");
      auto matches = bpftrace_.find_wildcard_matches(attach_point->target,
                                                     attach_point->func,
                                                     *symbol_stream);
      for (auto &match : matches) {
        std::string tracepoint_struct = TracepointFormatParser::get_struct_name(
            attach_point->target, match);
        Struct &cstruct = bpftrace_.structs_[tracepoint_struct];
        builtin.type = SizedType(Type::cast, cstruct.size, tracepoint_struct);
        builtin.type.is_pointer = true;
        builtin.type.is_tparg = true;
        break;
      }
    }
  }
  else {
    builtin.type = SizedType(Type::none, 0);
    buf << "Unknown builtin variable: '" << builtin.ident << "'";
  }

  std::string err = buf.str();
  if (err.size() > 0) {
    bpftrace_.error(err_, builtin.loc, err);
  }
}

void SemanticAnalyser::visit(Call &call)
{
  std::stringstream buf;
  // Check for unsafe-ness first. It is likely the most pertinent issue
  // (and should be at the top) for any function call.
  if (bpftrace_.safe_mode_ && is_unsafe_func(call.func)) {
    buf << call.func << "() is an unsafe function being used in safe mode";
  }

  if (call.vargs) {
    for (Expression *expr : *call.vargs) {
      expr->accept(*this);
    }
  }

  if (call.func == "hist") {
    check_assignment(call, true, false);
    check_nargs(call, 1);
    check_arg(call, Type::integer, 0);

    call.type = SizedType(Type::hist, 8);
  }
  else if (call.func == "lhist") {
    check_assignment(call, true, false);
    if (check_nargs(call, 4)) {
      check_arg(call, Type::integer, 0, false);
      check_arg(call, Type::integer, 1, true);
      check_arg(call, Type::integer, 2, true);
      check_arg(call, Type::integer, 3, true);
    }

    if (is_final_pass()) {
      Expression &min_arg = *call.vargs->at(1);
      Expression &max_arg = *call.vargs->at(2);
      Expression &step_arg = *call.vargs->at(3);
      Integer &min = static_cast<Integer&>(min_arg);
      Integer &max = static_cast<Integer&>(max_arg);
      Integer &step = static_cast<Integer&>(step_arg);
      if (step.n <= 0)
        buf << "lhist() step must be >= 1 (" << step.n << " provided)";
      else
      {
        int buckets = (max.n - min.n) / step.n;
        if (buckets > 1000)
          buf << "lhist() too many buckets, must be <= 1000 (would need " << buckets << ")";
      }
      if (min.n < 0)
        buf << "lhist() min must be non-negative (provided min " << min.n << ")";
      if (min.n > max.n)
        buf << "lhist() min must be less than max (provided min " << min.n << " and max ";
      if ((max.n - min.n) < step.n)
        buf << "lhist() step is too large for the given range (provided step " << step.n << " for range " << (max.n - min.n) << ")";

      // store args for later passing to bpftrace::Map
      auto search = map_args_.find(call.map->ident);
      if (search == map_args_.end())
        map_args_.insert({call.map->ident, *call.vargs});
    }
    call.type = SizedType(Type::lhist, 8);
  }
  else if (call.func == "count") {
    check_assignment(call, true, false);
    check_nargs(call, 0);

    call.type = SizedType(Type::count, 8);
  }
  else if (call.func == "sum") {
    check_assignment(call, true, false);
    check_nargs(call, 1);

    call.type = SizedType(Type::sum, 8);
  }
  else if (call.func == "min") {
    check_assignment(call, true, false);
    check_nargs(call, 1);

    call.type = SizedType(Type::min, 8);
  }
  else if (call.func == "max") {
    check_assignment(call, true, false);
    check_nargs(call, 1);

    call.type = SizedType(Type::max, 8);
  }
  else if (call.func == "avg") {
    check_assignment(call, true, false);
    check_nargs(call, 1);

    call.type = SizedType(Type::avg, 8);
  }
  else if (call.func == "stats") {
    check_assignment(call, true, false);
    check_nargs(call, 1);

    call.type = SizedType(Type::stats, 8);
  }
  else if (call.func == "delete") {
    check_assignment(call, false, false);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        buf << "delete() expects a map to be provided";
    }

    call.type = SizedType(Type::none, 0);
  }
  else if (call.func == "str") {
    if (check_varargs(call, 1, 2)) {
      check_arg(call, Type::integer, 0);
      call.type = SizedType(Type::string, bpftrace_.strlen_);
      if (is_final_pass() && call.vargs->size() > 1) {
        check_arg(call, Type::integer, 1, false);
      }
      if (auto *param = dynamic_cast<PositionalParameter*>(call.vargs->at(0))) {
        param->is_in_str = true;
      }
    }
  }
  else if (call.func == "ksym" || call.func == "usym") {
    if (check_nargs(call, 1)) {
      // allow symbol lookups on casts (eg, function pointers)
      auto &arg = *call.vargs->at(0);
      if (arg.type.type != Type::integer && arg.type.type != Type::cast)
        buf << call.func << "() expects an integer or pointer argument";
    }

    if (call.func == "ksym")
      call.type = SizedType(Type::ksym, 8);
    else if (call.func == "usym")
      call.type = SizedType(Type::usym, 16);
  }
  else if (call.func == "ntop") {
    if (!check_varargs(call, 1, 2))
      return;

    auto arg = call.vargs->at(0);
    if (call.vargs->size() == 2) {
      arg = call.vargs->at(1);
      check_arg(call, Type::integer, 0);
    }

    if (arg->type.type != Type::integer && arg->type.type != Type::array)
      buf << call.func << "() expects an integer or array argument, got " << arg->type.type;

    // Kind of:
    //
    // struct {
    //   int af_type;
    //   union {
    //     char[4] inet4;
    //     char[16] inet6;
    //   }
    // }
    int buffer_size = 24;
    if (arg->type.type == Type::array) {
      if (arg->type.elem_type != Type::integer || arg->type.pointee_size != 1 || !(arg->type.size == 4 || arg->type.size == 16)) {
        buf << call.func << "() invalid array";
      }
    }
    call.type = SizedType(Type::inet, buffer_size);
    call.type.is_internal = true;
  }
  else if (call.func == "join") {
    check_assignment(call, false, false);
    check_varargs(call, 1, 2);
    check_arg(call, Type::integer, 0);
    call.type = SizedType(Type::none, 0);
    needs_join_map_ = true;

    if (is_final_pass()) {
      if (call.vargs && call.vargs->size() > 1) {
        check_arg(call, Type::string, 1, true);
        auto &join_delim_arg = *call.vargs->at(1);
        String &join_delim_str = static_cast<String&>(join_delim_arg);
        bpftrace_.join_args_.push_back(join_delim_str.str);
      } else {
        std::string join_delim_default = " ";
        bpftrace_.join_args_.push_back(join_delim_default);
      }
    }
  }
  else if (call.func == "reg") {
    if (check_nargs(call, 1)) {
      for (auto &attach_point : *probe_->attach_points) {
        ProbeType type = probetype(attach_point->provider);
        if (type == ProbeType::tracepoint) {
          buf << "The reg function cannot be used with 'tracepoint' probes";
          continue;
        }
      }

      if (check_arg(call, Type::string, 0, true)) {
        auto &arg = *call.vargs->at(0);
        auto &reg_name = static_cast<String&>(arg).str;
        int offset = arch::offset(reg_name);;
        if (offset == -1) {
          buf << "'" << reg_name << "' is not a valid register on this architecture";
          buf << " (" << arch::name() << ")";
        }
      }
    }

    call.type = SizedType(Type::integer, 8);
  }
  else if (call.func == "kaddr") {
    if (check_nargs(call, 1)) {
      check_arg(call, Type::string, 0, true);
    }
    call.type = SizedType(Type::integer, 8);
  }
   else if (call.func == "uaddr")
   {
    if (check_nargs(call, 1)) {
      if (check_arg(call, Type::string, 0, true)) {
        check_symbol(call, 0);
      }
    }
    call.type = SizedType(Type::integer, 8);
  }
  else if (call.func == "cgroupid") {
    if (check_nargs(call, 1)) {
      check_arg(call, Type::string, 0, true);
    }
    call.type = SizedType(Type::integer, 8);
  }
  else if (call.func == "printf" || call.func == "system" || call.func == "cat") {
    check_assignment(call, false, false);
    if (check_varargs(call, 1, 7)) {
      check_arg(call, Type::string, 0, true);
      if (is_final_pass()) {
        auto &fmt_arg = *call.vargs->at(0);
        String &fmt = static_cast<String&>(fmt_arg);
        std::vector<Field> args;
        for (auto iter = call.vargs->begin()+1; iter != call.vargs->end(); iter++) {
          auto ty = (*iter)->type;
          // Promote to 64-bit if it's not an array type
          if (!ty.IsArray())
            ty.size = 8;
          args.push_back({ .type =  ty, .offset = 0 });
        }
        buf << verify_format_string(fmt.str, args);

        if (call.func == "printf")
          bpftrace_.printf_args_.emplace_back(fmt.str, args);
        else if (call.func == "system")
          bpftrace_.system_args_.emplace_back(fmt.str, args);
        else
          bpftrace_.cat_args_.emplace_back(fmt.str, args);
      }
    }

    call.type = SizedType(Type::none, 0);
  }
  else if (call.func == "exit") {
    check_nargs(call, 0);
  }
  else if (call.func == "print") {
    check_assignment(call, false, false);
    if (check_varargs(call, 1, 3)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        buf << "print() expects a map to be provided";
      else {
        Map &map = static_cast<Map&>(arg);
        map.skip_key_validation = true;
        if (map.vargs != nullptr) {
          buf << "The map passed to " << call.func << "() should not be "
              << "indexed by a key";
        }
      }
      if (is_final_pass()) {
        if (call.vargs->size() > 1)
          check_arg(call, Type::integer, 1, true);
        if (call.vargs->size() > 2)
          check_arg(call, Type::integer, 2, true);
      }
    }
  }
  else if (call.func == "clear") {
    check_assignment(call, false, false);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        buf << "clear() expects a map to be provided";
      else {
        Map &map = static_cast<Map&>(arg);
        map.skip_key_validation = true;
        if (map.vargs != nullptr) {
          buf << "The map passed to " << call.func << "() should not be "
              << "indexed by a key";
        }
      }
    }
  }
  else if (call.func == "zero") {
    check_assignment(call, false, false);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        buf << "zero() expects a map to be provided";
      else {
        Map &map = static_cast<Map&>(arg);
        map.skip_key_validation = true;
        if (map.vargs != nullptr) {
          buf << "The map passed to " << call.func << "() should not be "
              << "indexed by a key";
        }
      }
    }
  }
  else if (call.func == "time") {
    check_assignment(call, false, false);
    if (check_varargs(call, 0, 1)) {
      if (is_final_pass()) {
        if (call.vargs && call.vargs->size() > 0) {
          check_arg(call, Type::string, 0, true);
          auto &fmt_arg = *call.vargs->at(0);
          String &fmt = static_cast<String&>(fmt_arg);
          bpftrace_.time_args_.push_back(fmt.str);
        } else {
          std::string fmt_default = "%H:%M:%S\n";
          bpftrace_.time_args_.push_back(fmt_default.c_str());
        }
      }
    }
  }
  else if (call.func == "kstack") {
    check_stack_call(call, Type::kstack);
  }
  else if (call.func == "ustack") {
    check_stack_call(call, Type::ustack);
  }
  else {
    buf << "Unknown function: '" << call.func << "'";
    call.type = SizedType(Type::none, 0);
  }

  std::string err = buf.str();
  if (err.size() > 0)
    bpftrace_.error(err_, call.loc, err);
}

void SemanticAnalyser::check_stack_call(Call &call, Type type) {
  call.type = SizedType(type, StackType());
  if (check_varargs(call, 0, 2) && is_final_pass()) {
    StackType stack_type;
    if (call.vargs) {
      switch (call.vargs->size()) {
        case 0: break;
        case 1: {
          auto &arg = *call.vargs->at(0);
          if (is_final_pass() && arg.type.type != Type::stack_mode) {
            check_arg(call, Type::integer, 0, true);
            stack_type.limit = static_cast<Integer&>(arg).n;
          } else {
            check_arg(call, Type::stack_mode, 0, false);
            stack_type.mode = static_cast<StackMode&>(arg).type.stack_type.mode;
          }
          break;
        }
        case 2: {
          check_arg(call, Type::stack_mode, 0, false);
          auto &mode_arg = *call.vargs->at(0);
          stack_type.mode = static_cast<StackMode&>(mode_arg).type.stack_type.mode;

          check_arg(call, Type::integer, 1, true);
          auto &limit_arg = *call.vargs->at(1);
          stack_type.limit = static_cast<Integer&>(limit_arg).n;
          break;
        }
        default:
          err_ << "Invalid number of arguments" << std::endl;
          break;
      }
    }
    if (stack_type.limit > MAX_STACK_SIZE)
      err_ << call.func << "([int limit]): limit shouldn't exceed " << MAX_STACK_SIZE << ", " << stack_type.limit << " given" << std::endl;
    call.type = SizedType(type, stack_type);
    needs_stackid_maps_.insert(stack_type);
  }
}

void SemanticAnalyser::visit(Map &map)
{
  if (is_final_pass()) {
    MapKey key;
    if (map.vargs) {
      for (Expression *expr : *map.vargs) {
        expr->accept(*this);
        // promote map key to 64-bit:
        if (!expr->type.IsArray())
          expr->type.size = 8;
        key.args_.push_back(expr->type);
      }
    }

    if (!map.skip_key_validation) {
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
    }
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
    err_ << "Undefined or undeclared variable: " << var.ident << std::endl;
    var.type = SizedType(Type::none, 0);
  }
}

void SemanticAnalyser::visit(ArrayAccess &arr)
{
  arr.expr->accept(*this);
  arr.indexpr->accept(*this);

  SizedType &type = arr.expr->type;
  SizedType &indextype = arr.indexpr->type;

  if (is_final_pass() && !(type.type == Type::array))
    err_ << "The array index operator [] can only be used on arrays." << std::endl;

  if (is_final_pass() && !(indextype.type == Type::integer))
    err_ << "The array index operator [] only accepts integer indices." << std::endl;

  if (is_final_pass() && (indextype.type == Type::integer)) {
    Integer *index = static_cast<Integer *>(arr.indexpr);

    if ((size_t) index->n >= type.size)
      err_ << "the index " << index->n << " is out of bounds for array of size " << type.size << std::endl;
  }

  arr.type = SizedType(type.elem_type, type.pointee_size);
}

void SemanticAnalyser::visit(Binop &binop)
{
  binop.left->accept(*this);
  binop.right->accept(*this);
  Type &lhs = binop.left->type.type;
  Type &rhs = binop.right->type.type;

  std::stringstream buf;
  if (is_final_pass()) {
    if ((lhs != rhs) &&
      // allow integer to cast pointer comparisons (eg, ptr != 0):
      !(lhs == Type::cast && rhs == Type::integer) &&
      !(lhs == Type::integer && rhs == Type::cast)) {
      buf << "Type mismatch for '" << opstr(binop) << "': ";
      buf << "comparing '" << lhs << "' ";
      buf << "with '" << rhs << "'";
      bpftrace_.error(err_, binop.left->loc + binop.right->loc, buf.str());
    }

    else if (lhs != Type::integer
             && binop.op != Parser::token::EQ
             && binop.op != Parser::token::NE) {
      buf << "The " << opstr(binop)
          << " operator can not be used on expressions of type " << lhs
          << std::endl;
      bpftrace_.error(err_, binop.loc, buf.str());
    }
  }

  binop.type = SizedType(Type::integer, 8);
}

void SemanticAnalyser::visit(Unop &unop)
{
  if (unop.op == Parser::token::PLUSPLUS ||
      unop.op == Parser::token::MINUSMINUS) {
    // Handle ++ and -- before visiting unop.expr, because these
    // operators should be able to work with undefined maps.
    if (!unop.expr->is_map && !unop.expr->is_variable) {
      err_ << "The " << opstr(unop)
           << " operator must be applied to a map or variable" << std::endl;
    }
    if (unop.expr->is_map) {
      Map &map = static_cast<Map&>(*unop.expr);
      assign_map_type(map, SizedType(Type::integer, 8));
    }
  }

  unop.expr->accept(*this);

  SizedType &type = unop.expr->type;
  if (is_final_pass() &&
      !(type.type == Type::integer) &&
      !(type.type == Type::cast && unop.op == Parser::token::MUL)) {
    err_ << "The " << opstr(unop) << " operator can not be used on expressions of type '"
         << type << "'" << std::endl;
  }

  if (unop.op == Parser::token::MUL) {
    if (type.type == Type::cast) {
      if (type.is_pointer) {
        if (bpftrace_.structs_.count(type.cast_type) == 0) {
          err_ << "Unknown struct/union: '" << type.cast_type << "'" << std::endl;
          return;
        }
        int cast_size = bpftrace_.structs_[type.cast_type].size;
        unop.type = SizedType(Type::cast, cast_size, type.cast_type);
        unop.type.is_tparg = type.is_tparg;
      }
      else {
        err_ << "Can not dereference struct/union of type '" << type.cast_type << "'. "
             << "It is not a pointer." << std::endl;
      }
    }
    else if (type.type == Type::integer) {
      unop.type = SizedType(Type::integer, type.size);
    }
  }
  else {
    unop.type = SizedType(Type::integer, 8);
  }
}

void SemanticAnalyser::visit(Ternary &ternary)
{
  ternary.cond->accept(*this);
  ternary.left->accept(*this);
  ternary.right->accept(*this);
  Type &lhs = ternary.left->type.type;
  Type &rhs = ternary.right->type.type;
  if (is_final_pass()) {
    if (lhs != rhs) {
      err_ << "Ternary operator must return the same type: ";
      err_ << "have '" << lhs << "' ";
      err_ << "and '" << rhs << "'" << std::endl;
    }
  }
  if (lhs == Type::string)
    ternary.type = SizedType(lhs, STRING_SIZE);
  else if (lhs == Type::integer)
    ternary.type = SizedType(lhs, 8);
  else {
    err_ << "Ternary return type unsupported " << lhs << std::endl;
  }
}

void SemanticAnalyser::visit(If &if_block)
{
  if_block.cond->accept(*this);

  for (Statement *stmt : *if_block.stmts) {
    stmt->accept(*this);
  }

  if (if_block.else_stmts) {
    for (Statement *stmt : *if_block.else_stmts) {
      stmt->accept(*this);
    }
  }
}

void SemanticAnalyser::visit(Unroll &unroll)
{
  if (unroll.var > 20)
  {
    err_ << "unroll maximum value is 20.\n" << std::endl;
  }
  else if (unroll.var < 1)
  {
    err_ << "unroll minimum value is 1.\n" << std::endl;
  }

  for (int i=0; i < unroll.var; i++) {
    for (Statement *stmt : *unroll.stmts)
    {
      stmt->accept(*this);
    }
  }
}

void SemanticAnalyser::visit(FieldAccess &acc)
{
  acc.expr->accept(*this);

  SizedType &type = acc.expr->type;
  if (type.type != Type::cast) {
    if (is_final_pass()) {
      err_ << "Can not access field '" << acc.field
           << "' on expression of type '" << type
           << "'" << std::endl;
    }
    return;
  }

  if (type.is_pointer) {
    err_ << "Can not access field '" << acc.field << "' on type '"
         << type.cast_type << "'. Try dereferencing it first, or using '->'"
         << std::endl;
    return;
  }
  if (bpftrace_.structs_.count(type.cast_type) == 0) {
    err_ << "Unknown struct/union: '" << type.cast_type << "'" << std::endl;
    return;
  }

  std::map<std::string, FieldsMap> structs;

  if (type.is_tparg) {
    for (AttachPoint *attach_point : *probe_->attach_points) {
      assert(probetype(attach_point->provider) == ProbeType::tracepoint);

      auto symbol_stream = bpftrace_.get_symbols_from_file(
          "/sys/kernel/debug/tracing/available_events");
      auto matches = bpftrace_.find_wildcard_matches(attach_point->target,
                                                     attach_point->func,
                                                     *symbol_stream);
      for (auto &match : matches) {
        std::string tracepoint_struct =
            TracepointFormatParser::get_struct_name(attach_point->target,
                                                    match);
        structs[tracepoint_struct] = bpftrace_.structs_[tracepoint_struct].fields;
      }
    }
  } else {
    structs[type.cast_type] = bpftrace_.structs_[type.cast_type].fields;
  }

  for (auto it : structs) {
    std::string cast_type = it.first;
    FieldsMap fields = it.second;
    if (fields.count(acc.field) == 0) {
      err_ << "Struct/union of type '" << cast_type << "' does not contain "
          << "a field named '" << acc.field << "'" << std::endl;
    }
    else {
      acc.type = fields[acc.field].type;
      acc.type.is_internal = type.is_internal;
    }
  }
}

void SemanticAnalyser::visit(Cast &cast)
{
  cast.expr->accept(*this);

  if (bpftrace_.structs_.count(cast.cast_type) == 0) {
    err_ << "Unknown struct/union: '" << cast.cast_type << "'" << std::endl;
    return;
  }

  int cast_size;
  if (cast.is_pointer) {
    cast_size = sizeof(uintptr_t);
  }
  else {
    cast_size = bpftrace_.structs_[cast.cast_type].size;
  }
  cast.type = SizedType(Type::cast, cast_size, cast.cast_type);
  cast.type.is_pointer = cast.is_pointer;
}

void SemanticAnalyser::visit(ExprStatement &expr)
{
  expr.expr->accept(*this);
}

void SemanticAnalyser::visit(AssignMapStatement &assignment)
{
  assignment.map->accept(*this);
  assignment.expr->accept(*this);

  assign_map_type(*assignment.map, assignment.expr->type);

  const std::string &map_ident = assignment.map->ident;
  if (assignment.expr->type.type == Type::cast) {
    std::string cast_type = assignment.expr->type.cast_type;
    std::string curr_cast_type = map_val_[map_ident].cast_type;
    if (curr_cast_type != "" && curr_cast_type != cast_type) {
      err_ << "Type mismatch for " << map_ident << ": ";
      err_ << "trying to assign value of type '" << cast_type;
      err_ << "'\n\twhen map already contains a value of type '";
      err_ << curr_cast_type << "'\n" << std::endl;
    }
    else {
      map_val_[map_ident].cast_type = cast_type;
      map_val_[map_ident].is_internal = true;
    }
  }
}

void SemanticAnalyser::visit(AssignVarStatement &assignment)
{
  assignment.expr->accept(*this);

  std::string var_ident = assignment.var->ident;
  auto search = variable_val_.find(var_ident);
  assignment.var->type = assignment.expr->type;
  if (search != variable_val_.end()) {
    if (search->second.type == Type::none) {
      if (is_final_pass()) {
        err_ << "Undefined variable: " << var_ident << std::endl;
      }
      else {
        search->second = assignment.expr->type;
      }
    }
    else if (search->second.type != assignment.expr->type.type) {
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
    std::string cast_type = assignment.expr->type.cast_type;
    std::string curr_cast_type = variable_val_[var_ident].cast_type;
    if (curr_cast_type != "" && curr_cast_type != cast_type) {
      err_ << "Type mismatch for " << var_ident << ": ";
      err_ << "trying to assign value of type '" << cast_type;
      err_ << "'\n\twhen variable already contains a value of type '";
      err_ << curr_cast_type << "'\n" << std::endl;
    }
    else {
      variable_val_[var_ident].cast_type = cast_type;
    }
  }
}

void SemanticAnalyser::visit(Predicate &pred)
{
  pred.expr->accept(*this);
  if (is_final_pass() && ((pred.expr->type.type != Type::integer) &&
     (!(pred.expr->type.is_pointer && pred.expr->type.type == Type::cast)))) {
    err_ << "Invalid type for predicate: " << pred.expr->type.type << std::endl;
  }
}

void SemanticAnalyser::visit(AttachPoint &ap)
{
  ap.provider = probetypeName(ap.provider);

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
    ap.target = resolve_binary_path(ap.target);
    struct stat s;
    if (stat(ap.target.c_str(), &s) != 0)
      err_ << "failed to stat uprobe target file " << ap.target << ": "
        << std::strerror(errno) << std::endl;
  }
  else if (ap.provider == "usdt") {
    if (ap.func == "")
      err_ << "usdt probe must have a target function or wildcard" << std::endl;

    usdt_probe_list probes;
    if (bpftrace_.pid_ > 0) {
       USDTHelper::probes_for_pid(bpftrace_.pid_);
    } else if (ap.target != "") {
       USDTHelper::probes_for_path(ap.target);
    } else {
      err_ << "usdt probe must specify at least path or pid to probe" << std::endl;
    }

    if (ap.target != "") {
      ap.target = resolve_binary_path(ap.target);
      struct stat s;
      if (stat(ap.target.c_str(), &s) != 0)
        err_ << "usdt target file " << ap.target << " does not exist" << std::endl;
    }
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
  else if (ap.provider == "interval") {
    if (ap.target == "")
      err_ << "interval probe must have unit of time" << std::endl;
    else if (ap.target != "ms" &&
             ap.target != "s")
      err_ << ap.target << " is not an accepted unit of time" << std::endl;
    if (ap.func != "")
      err_ << "interval probe must have an integer frequency" << std::endl;
  }
  else if (ap.provider == "software") {
    if (ap.target == "")
      err_ << "software probe must have a software event name" << std::endl;
    else {
      bool found = false;
      for (auto &probeListItem : SW_PROBE_LIST) {
        if (ap.target == probeListItem.path || (!probeListItem.alias.empty() && ap.target == probeListItem.alias)) {
          found = true;
          break;
        }
      }
      if (!found)
        err_ << ap.target << " is not a software probe" << std::endl;
    }
    if (ap.func != "")
      err_ << "software probe can only have an integer count" << std::endl;
    else if (ap.freq < 0)
      err_ << "software count should be a positive integer" << std::endl;
  }
  else if (ap.provider == "watchpoint") {
    if (!ap.addr)
      err_ << "watchpoint must be attached to a non-zero address" << std::endl;
    if (ap.len != 1 && ap.len != 2 && ap.len != 4 && ap.len != 8)
      err_ << "watchpoint length must be one of (1,2,4,8)" << std::endl;
    std::sort(ap.mode.begin(), ap.mode.end());
    for (const char c : ap.mode) {
      if (c != 'r' && c != 'w' && c != 'x')
        err_ << "watchpoint mode must be combination of (r,w,x)" << std::endl;
    }
    for (size_t i = 0; i < ap.mode.size() - 1; ++i) {
      if (ap.mode[i] == ap.mode[i+1])
        err_ << "watchpoint modes may not be duplicated" << std::endl;
    }
    if (ap.mode == "rx" || ap.mode == "wx" || ap.mode == "rwx")
      err_ << "watchpoint modes (rx, wx, rwx) not allowed" << std::endl;
  }
  else if (ap.provider == "hardware") {
    if (ap.target == "")
      err_ << "hardware probe must have a hardware event name" << std::endl;
    else {
      bool found = false;
      for (auto &probeListItem : HW_PROBE_LIST) {
        if (ap.target == probeListItem.path || (!probeListItem.alias.empty() && ap.target == probeListItem.alias)) {
          found = true;
          break;
        }
      }
      if (!found)
        err_ << ap.target << " is not a hardware probe" << std::endl;
    }
    if (ap.func != "")
      err_ << "hardware probe can only have an integer count" << std::endl;
    else if (ap.freq < 0)
      err_ << "hardware frequency should be a positive integer" << std::endl;
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

}

void SemanticAnalyser::visit(Program &program)
{
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
  int failed_maps = 0;
  auto is_invalid_map = [](int a) { return (int)(a < 0); };
  for (auto &map_val : map_val_)
  {
    std::string map_name = map_val.first;
    SizedType type = map_val.second;

    auto search_args = map_key_.find(map_name);
    if (search_args == map_key_.end())
    {
      out_ << "map key \"" << map_name << "\" not found" << std::endl;
      abort();
    }

    auto &key = search_args->second;

    if (debug)
      bpftrace_.maps_[map_name] = std::make_unique<bpftrace::FakeMap>(map_name, type, key);
    else
    {
      if (type.type == Type::lhist)
      {
        // store lhist args to the bpftrace::Map
        auto map_args = map_args_.find(map_name);
        if (map_args == map_args_.end())
        {
          out_ << "map arg \"" << map_name << "\" not found" << std::endl;
          abort();
        }

        Expression &min_arg = *map_args->second.at(1);
        Expression &max_arg = *map_args->second.at(2);
        Expression &step_arg = *map_args->second.at(3);
        Integer &min = static_cast<Integer&>(min_arg);
        Integer &max = static_cast<Integer&>(max_arg);
        Integer &step = static_cast<Integer&>(step_arg);
        bpftrace_.maps_[map_name] = std::make_unique<bpftrace::Map>(map_name, type, key, min.n, max.n, step.n, bpftrace_.mapmax_);
        failed_maps += is_invalid_map(bpftrace_.maps_[map_name]->mapfd_);
      }
      else
        bpftrace_.maps_[map_name] = std::make_unique<bpftrace::Map>(map_name, type, key, bpftrace_.mapmax_);
    }
  }

  for (StackType stack_type : needs_stackid_maps_) {
    // The stack type doesn't matter here, so we use kstack to force SizedType
    // to set stack_size.
    if (debug)
    {
      bpftrace_.stackid_maps_[stack_type] = std::make_unique<bpftrace::FakeMap>(SizedType(Type::kstack, stack_type));
    }
    else
    {
      bpftrace_.stackid_maps_[stack_type] = std::make_unique<bpftrace::Map>(SizedType(Type::kstack, stack_type));
      failed_maps += is_invalid_map(bpftrace_.stackid_maps_[stack_type]->mapfd_);
    }
  }

  if (debug)
  {
    if (needs_join_map_)
    {
      // join uses map storage as we'd like to process data larger than can fit on the BPF stack.
      std::string map_ident = "join";
      SizedType type = SizedType(Type::join, 8 + 8 + bpftrace_.join_argnum_ * bpftrace_.join_argsize_);
      MapKey key;
      bpftrace_.join_map_ = std::make_unique<bpftrace::FakeMap>(map_ident, type, key);
    }
    bpftrace_.perf_event_map_ = std::make_unique<bpftrace::FakeMap>(BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  }
  else
  {
    if (needs_join_map_)
    {
      // join uses map storage as we'd like to process data larger than can fit on the BPF stack.
      std::string map_ident = "join";
      SizedType type = SizedType(Type::join, 8 + 8 + bpftrace_.join_argnum_ * bpftrace_.join_argsize_);
      MapKey key;
      bpftrace_.join_map_ = std::make_unique<bpftrace::Map>(map_ident, type, key, 1);
      failed_maps += is_invalid_map(bpftrace_.join_map_->mapfd_);
    }
    bpftrace_.perf_event_map_ = std::make_unique<bpftrace::Map>(BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    failed_maps += is_invalid_map(bpftrace_.perf_event_map_->mapfd_);
  }

  if (failed_maps > 0)
  {
    out_ << "Creation of the required BPF maps has failed." << std::endl;
    out_ << "Make sure you have all the required permissions and are not";
    out_ << " confined (e.g. like" << std::endl;
    out_ << "snapcraft does). `dmesg` will likely have useful output for";
    out_ << " further troubleshooting" << std::endl;
  }

  return failed_maps;
}

bool SemanticAnalyser::is_final_pass() const
{
  return pass_ == num_passes_;
}

bool SemanticAnalyser::check_assignment(const Call &call, bool want_map, bool want_var)
{
  std::stringstream buf;
  if (want_map && want_var)
  {
    if (!call.map && !call.var)
    {
      buf << call.func << "() should be assigned to a map or a variable";
      bpftrace_.error(err_, call.loc, buf.str());
      return false;
    }
  }
  else if (want_map)
  {
    if (!call.map)
    {
      buf << call.func << "() should be assigned to a map";
      bpftrace_.error(err_, call.loc, buf.str());
      return false;
    }
  }
  else if (want_var)
  {
    if (!call.var)
    {
      buf << call.func << "() should be assigned to a variable";
      bpftrace_.error(err_, call.loc, buf.str());
      return false;
    }
  }
  else
  {
    if (call.map || call.var)
    {
      buf << call.func << "() should not be used in an assignment";
      bpftrace_.error(err_, call.loc, buf.str());
      return false;
    }
  }
  return true;
}

bool SemanticAnalyser::check_nargs(const Call &call, size_t expected_nargs)
{
  std::stringstream buf;
  std::vector<Expression*>::size_type nargs = 0;
  if (call.vargs)
    nargs = call.vargs->size();

  if (nargs != expected_nargs)
  {
    if (expected_nargs == 0)
      buf << call.func << "() requires no arguments";
    else if (expected_nargs == 1)
      buf << call.func << "() requires one argument";
    else
      buf << call.func << "() requires " << expected_nargs << " arguments";

    buf << " (" << nargs << " provided)";
    bpftrace_.error(err_, call.loc, buf.str());
    return false;
  }
  return true;
}

bool SemanticAnalyser::check_varargs(const Call &call, size_t min_nargs, size_t max_nargs)
{
  std::vector<Expression*>::size_type nargs = 0;
  std::stringstream buf;
  if (call.vargs)
    nargs = call.vargs->size();

  if (nargs < min_nargs)
  {
    if (min_nargs == 1)
      buf << call.func << "() requires at least one argument";
    else
      buf << call.func << "() requires at least " << min_nargs << " arguments";
    buf << " (" << nargs << " provided)";
    bpftrace_.error(err_, call.loc, buf.str());
    return false;
  }
  else if (nargs > max_nargs)
  {
    if (max_nargs == 0)
      buf << call.func << "() requires no arguments";
    else if (max_nargs == 1)
      buf << call.func << "() takes up to one argument";
    else
      buf << call.func << "() takes up to " << max_nargs << " arguments";

    buf << " (" << nargs << " provided)";
    bpftrace_.error(err_, call.loc, buf.str());
    return false;
  }

  return true;
}

bool SemanticAnalyser::check_arg(const Call &call, Type type, int arg_num, bool want_literal)
{
  if (!call.vargs)
    return false;

  std::stringstream buf;
  auto &arg = *call.vargs->at(arg_num);
  if (want_literal && (!arg.is_literal || arg.type.type != type))
  {
    buf << call.func << "() expects a " << type << " literal";
    buf << " (" << arg.type.type << " provided)" << std::endl;
    bpftrace_.error(err_, call.loc, buf.str());
    return false;
  }
  else if (is_final_pass() && arg.type.type != type) {
    buf << call.func << "() only supports " << type << " arguments";
    buf << " (" << arg.type.type << " provided)" << std::endl;
    bpftrace_.error(err_, call.loc, buf.str());
    return false;
  }
  return true;
}

bool SemanticAnalyser::check_symbol(const Call &call, int arg_num __attribute__((unused)))
{
  if (!call.vargs)
    return false;

  auto &arg = static_cast<String&>(*call.vargs->at(0)).str;

  std::string re = "^[a-zA-Z0-9./_-]+$";
  bool is_valid = std::regex_match(arg, std::regex(re));
  if (!is_valid)
  {
    std::stringstream buf;
    buf << call.func << "() expects a string that is a valid symbol (" << re << ") as input";
    buf << " (\"" << arg << "\" provided)";
    bpftrace_.error(err_, call.loc, buf.str());
    return false;
  }

  return true;
}

/*
 * assign_map_type
 *
 *   Semantic analysis for assigning a value of the provided type
 *   to the given map.
 */
void SemanticAnalyser::assign_map_type(const Map &map, const SizedType &type)
{
  const std::string &map_ident = map.ident;
  auto search = map_val_.find(map_ident);
  if (search != map_val_.end()) {
    if (search->second.type == Type::none) {
      if (is_final_pass()) {
        err_ << "Undefined map: " << map_ident << std::endl;
      }
      else {
        search->second = type;
      }
    }
    else if (search->second.type != type.type) {
      err_ << "Type mismatch for " << map_ident << ": ";
      err_ << "trying to assign value of type '" << type;
      err_ << "'\n\twhen map already contains a value of type '";
      err_ << search->second << "'\n" << std::endl;
    }
  }
  else {
    // This map hasn't been seen before
    map_val_.insert({map_ident, type});
    if (map_val_[map_ident].type == Type::integer) {
      // Store all integer values as 64-bit in maps, so that there will
      // be space for any integer to be assigned to the map later
      map_val_[map_ident].size = 8;
    }
  }
}

} // namespace ast
} // namespace bpftrace
