#include "semantic_analyser.h"
#include "ast.h"
#include "fake_map.h"
#include "parser.tab.hh"
#include "printf.h"
#include "tracepoint_format_parser.h"
#include "utils.h"
#include "arch/arch.h"
#include "list.h"
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
  std::string pstr = bpftrace_.get_param(param.n);
  if (is_final_pass()) {
    if (!bpftrace_.is_numeric(pstr)) {
      if (!call_ || call_->func != "str")
        /*
         * call_ was added just for this test: ensuring a string parameter is
         * only used inside str(). Without it, string parameters used as
         * integers would return their buffer address. Maybe that's ok?
         * If this behavior is changed, codegen needs to support it.
         */
        err_ << "$" << param.n << " used numerically, but given \"" << pstr << "\". Try using str($" << param.n << ")." << std::endl;
    }
  }
}

void SemanticAnalyser::visit(String &string)
{
  if (string.str.size() > STRING_SIZE-1) {
    err_ << "String is too long (over " << STRING_SIZE << " bytes): " << string.str << std::endl;
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
        err_ << "BPF_FUNC_get_current_cgroup_id is not available for your kernel version" << std::endl;
      #endif
    }
  }
  else if (builtin.ident == "retval") {
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::kretprobe && type != ProbeType::uretprobe) {
        err_ << "The retval builtin can only be used with 'kretprobe' and 'uretprobe' probes"
             << (type == ProbeType::tracepoint ? " (try to use args->ret instead)" : "")
             << std::endl;
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
          type == ProbeType::kretprobe ||
          type == ProbeType::tracepoint)
        builtin.type = SizedType(Type::ksym, 8);
      else if (type == ProbeType::uprobe || type == ProbeType::uretprobe)
        builtin.type = SizedType(Type::usym, 16);
      else
        err_ << "The func builtin can not be used with '" << attach_point->provider
             << "' probes" << std::endl;
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
        err_ << "The " << builtin.ident << " builtin can only be used with "
             << "'kprobes', 'uprobes' and 'usdt' probes" << std::endl;
    }
    int arg_num = atoi(builtin.ident.substr(3).c_str());
    if (arg_num > arch::max_arg())
      err_ << arch::name() << " doesn't support " << builtin.ident << std::endl;
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
      if (type != ProbeType::tracepoint)
        err_ << "The args builtin can only be used with tracepoint probes"
             << "(" << attach_point->provider << " used here)" << std::endl;

      /*
       * tracepoint wildcard expansion, part 2 of 3. This:
       * 1. expands the wildcard, then sets args to be the first matched probe.
       *    This is so that enough of the type information is available to
       *    survive the later semantic analyser checks.
       * 2. sets is_tparg so that codegen does the real type setting after
       *    expansion.
       */
      std::set<std::string> matches;
      matches = bpftrace_.find_wildcard_matches(attach_point->target,
                                                attach_point->func,
                                                "/sys/kernel/debug/tracing/available_events");
      for (auto &match : matches) {
        std::string tracepoint_struct = TracepointFormatParser::get_struct_name(attach_point->target, match);
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
    err_ << "Unknown builtin variable: '" << builtin.ident << "'" << std::endl;
  }
}

void SemanticAnalyser::visit(Call &call)
{
  // needed for positional parameters context:
  call_ = &call;

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
    check_nargs(call, 4);
    check_arg(call, Type::integer, 0);
    check_arg(call, Type::integer, 1);
    check_arg(call, Type::integer, 2);
    check_arg(call, Type::integer, 3);

    if (is_final_pass()) {
      Expression &min_arg = *call.vargs->at(1);
      Expression &max_arg = *call.vargs->at(2);
      Expression &step_arg = *call.vargs->at(3);
      Integer &min = static_cast<Integer&>(min_arg);
      Integer &max = static_cast<Integer&>(max_arg);
      Integer &step = static_cast<Integer&>(step_arg);
      if (step.n <= 0)
        err_ << "lhist() step must be >= 1 (" << step.n << " provided)" << std::endl;
      else
      {
        int buckets = (max.n - min.n) / step.n;
        if (buckets > 1000)
          err_ << "lhist() too many buckets, must be <= 1000 (would need " << buckets << ")" << std::endl;
      }
      if (min.n > max.n)
        err_ << "lhist() min must be less than max (provided min " << min.n << " and max " << max.n << ")" << std::endl;
      if ((max.n - min.n) < step.n)
        err_ << "lhist() step is too large for the given range (provided step " << step.n << " for range " << (max.n - min.n) << ")" << std::endl;

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
        err_ << "delete() expects a map to be provided" << std::endl;
    }

    call.type = SizedType(Type::none, 0);
  }
  else if (call.func == "str") {
    if (check_varargs(call, 1, 2)) {
      check_arg(call, Type::integer, 0);
      call.type = SizedType(Type::string, bpftrace_.strlen_);
      if (is_final_pass()) {
        if (call.vargs->size() > 1) {
          check_arg(call, Type::integer, 1, false);
        }
      }
    }
  }
  else if (call.func == "ksym" || call.func == "usym") {
    if (check_nargs(call, 1)) {
      // allow symbol lookups on casts (eg, function pointers)
      auto &arg = *call.vargs->at(0);
      if (arg.type.type != Type::integer && arg.type.type != Type::cast)
        err_ << call.func << "() expects an integer or pointer argument" << std::endl;
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
      err_ << call.func << "() expects an integer or array argument, got " << arg->type.type << std::endl;

    // Kind of:
    //
    // struct {
    //   int af_type;
    //   union {
    //     char[4] inet4;
    //     char[16] inet6;
    //   }
    // }
    int buffer_size = 8;
    if (arg->type.type == Type::array) {
      if (arg->type.elem_type != Type::integer || arg->type.pointee_size != 1 || !(arg->type.size == 4 || arg->type.size == 16)) {
        err_ << call.func << "() invalid array" << std::endl;
      }
      if (arg->type.size == 16)
        buffer_size = 20;
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
      if (check_arg(call, Type::string, 0, true)) {
        auto &arg = *call.vargs->at(0);
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
  else if (call.func == "kaddr") {
    if (check_nargs(call, 1)) {
      if (check_arg(call, Type::string, 0, true)) {
         ;
      }
    }
    call.type = SizedType(Type::integer, 8);
  }
   else if (call.func == "uaddr")
   {
    if (check_nargs(call, 1)) {
      if (check_arg(call, Type::string, 0, true)) {
        if (check_alpha_numeric(call, 0)) {
         ;
        }
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
  else if (call.func == "printf" || call.func == "system") {
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
        err_ << verify_format_string(fmt.str, args);

        if (call.func == "printf")
          bpftrace_.printf_args_.emplace_back(fmt.str, args);
        else
          bpftrace_.system_args_.emplace_back(fmt.str, args);
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
      if (is_final_pass()) {
        auto &arg = *call.vargs->at(0);
        if (!arg.is_map)
          err_ << "print() expects a map to be provided" << std::endl;
        if (call.vargs->size() > 1)
          check_arg(call, Type::integer, 1, true);
        if (call.vargs->size() > 2)
          check_arg(call, Type::integer, 2, true);
      }
    }
  }
  else if (call.func == "clear") {
    check_assignment(call, false, false);
    check_nargs(call, 1);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        err_ << "clear() expects a map to be provided" << std::endl;
    }
  }
  else if (call.func == "zero") {
    check_assignment(call, false, false);
    check_nargs(call, 1);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        err_ << "zero() expects a map to be provided" << std::endl;
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
  else if (call.func == "cat") {
    check_assignment(call, false, false);
    if (check_nargs(call, 1)) {
      if (check_arg(call, Type::string, 0, true)) {
        if (is_final_pass()) {
          auto &arg = *call.vargs->at(0);
          bpftrace_.cat_args_.push_back(static_cast<String&>(arg).str);
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
    err_ << "Unknown function: '" << call.func << "'" << std::endl;
    call.type = SizedType(Type::none, 0);
  }
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

    auto search = map_key_.find(map.ident);
    if (search != map_key_.end()) {
      /*
      * TODO: this code ensures that map keys are consistent, but
      * currently prevents print() and clear() being used, since
      * for example "@x[pid] = count(); ... print(@x)" is detected
      * as having inconsistent keys. We need a way to do this check
      * differently for print() and clear() calls. I've commented it
      * out for now - Brendan.
      *
      if (search->second != key) {
        err_ << "Argument mismatch for " << map.ident << ": ";
        err_ << "trying to access with arguments: ";
        err_ << key.argument_type_list();
        err_ << "\n\twhen map expects arguments: ";
        err_ << search->second.argument_type_list();
        err_ << "\n" << std::endl;
      }
      */
    }
    else {
      map_key_.insert({map.ident, key});
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

  if (is_final_pass()) {
    if ((lhs != rhs) &&
      // allow integer to cast pointer comparisons (eg, ptr != 0):
      !(lhs == Type::cast && rhs == Type::integer) &&
      !(lhs == Type::integer && rhs == Type::cast)) {
      err_ << "TYpe mismatch for '" << opstr(binop) << "': ";
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
  else if (unroll.var == 0)
  {
    err_ << "unroll minimum value is 1.\n" << std::endl;
  }

  for (Statement *stmt : *unroll.stmts)
  {
    stmt->accept(*this);
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

      std::set<std::string> matches = bpftrace_.find_wildcard_matches(
          attach_point->target, attach_point->func,
          "/sys/kernel/debug/tracing/available_events");
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
    if (map_val_[map_ident].type == Type::integer) {
      // Store all integer values as 64-bit in maps, so that there will
      // be space for any integer to be assigned to the map later
      map_val_[map_ident].size = 8;
    }
  }

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
      err_ << "uprobe target file " << ap.target << " does not exist" << std::endl;
  }
  else if (ap.provider == "usdt") {
    if (ap.func == "")
      err_ << "usdt probe must have a func" << std::endl;
    if (ap.target == "") {
      if (bpftrace_.pid_ > 0) {
        auto const &u = USDTHelper::find(nullptr, bpftrace_.pid_, ap.func);
        ap.target = std::get<1>(u);

        if (ap.target == "")
          err_ << "usdt probe " << ap.func << " not found in pid " << bpftrace_.pid_ << std::endl;
      }

      if (ap.target == "")
        err_ << "usdt probes must have a target path defined or discovered from a pid" << std::endl;
    }
    ap.target = resolve_binary_path(ap.target);
    struct stat s;
    if (stat(ap.target.c_str(), &s) != 0)
      err_ << "usdt target file " << ap.target << " does not exist" << std::endl;
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
  for (auto &map_val : map_val_)
  {
    std::string map_name = map_val.first;
    SizedType type = map_val.second;

    auto search_args = map_key_.find(map_name);
    if (search_args == map_key_.end())
    {
      std::cerr << "map key \"" << map_name << "\" not found" << std::endl;
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
          std::cerr << "map arg \"" << map_name << "\" not found" << std::endl;
          abort();
        }

        Expression &min_arg = *map_args->second.at(1);
        Expression &max_arg = *map_args->second.at(2);
        Expression &step_arg = *map_args->second.at(3);
        Integer &min = static_cast<Integer&>(min_arg);
        Integer &max = static_cast<Integer&>(max_arg);
        Integer &step = static_cast<Integer&>(step_arg);
        bpftrace_.maps_[map_name] = std::make_unique<bpftrace::Map>(map_name, type, key, min.n, max.n, step.n);
      }
      else
        bpftrace_.maps_[map_name] = std::make_unique<bpftrace::Map>(map_name, type, key);
    }
  }

  for (StackType stack_type : needs_stackid_maps_) {
    // The stack type doesn't matter here, so we use kstack to force SizedType
    // to set stack_size.
    if (debug)
      bpftrace_.stackid_maps_[stack_type] = std::make_unique<bpftrace::FakeMap>(SizedType(Type::kstack, stack_type));
    else
      bpftrace_.stackid_maps_[stack_type] = std::make_unique<bpftrace::Map>(SizedType(Type::kstack, stack_type));
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
      bpftrace_.join_map_ = std::make_unique<bpftrace::Map>(map_ident, type, key);
    }
    bpftrace_.perf_event_map_ = std::make_unique<bpftrace::Map>(BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  }

  return 0;
}

bool SemanticAnalyser::is_final_pass() const
{
  return pass_ == num_passes_;
}

bool SemanticAnalyser::check_assignment(const Call &call, bool want_map, bool want_var)
{
  if (want_map && want_var)
  {
    if (!call.map && !call.var)
    {
      err_ << call.func << "() should be assigned to a map or a variable" << std::endl;
      return false;
    }
  }
  else if (want_map)
  {
    if (!call.map)
    {
      err_ << call.func << "() should be assigned to a map" << std::endl;
      return false;
    }
  }
  else if (want_var)
  {
    if (!call.var)
    {
      err_ << call.func << "() should be assigned to a variable" << std::endl;
      return false;
    }
  }
  else
  {
    if (call.map || call.var)
    {
      err_ << call.func << "() should not be used in an assignment" << std::endl;
      return false;
    }
  }
  return true;
}

bool SemanticAnalyser::check_nargs(const Call &call, size_t expected_nargs)
{
  std::vector<Expression*>::size_type nargs = 0;
  if (call.vargs)
    nargs = call.vargs->size();

  if (nargs != expected_nargs)
  {
    err_ << call.func << "() should take " << expected_nargs << " arguments ("; // TODO plural
    err_ << nargs << " provided)" << std::endl;
    return false;
  }
  return true;
}

bool SemanticAnalyser::check_varargs(const Call &call, size_t min_nargs, size_t max_nargs)
{
  std::vector<Expression*>::size_type nargs = 0;
  if (call.vargs)
    nargs = call.vargs->size();

  if (nargs < min_nargs)
  {
    err_ << call.func << "() requires at least " << min_nargs << " argument ("; // TODO plural
    err_ << nargs << " provided)" << std::endl;
    return false;
  }
  else if (nargs > max_nargs)
  {
    err_ << call.func << "() can only take up to " << max_nargs << " arguments (";
    err_ << nargs << " provided)" << std::endl;
    return false;
  }
  return true;
}

bool SemanticAnalyser::check_arg(const Call &call, Type type, int arg_num, bool want_literal)
{
  if (!call.vargs)
    return false;

  auto &arg = *call.vargs->at(arg_num);
  if (want_literal && (!arg.is_literal || arg.type.type != type))
  {
    err_ << call.func << "() expects a " << type << " literal";
    err_ << " (" << arg.type.type << " provided)" << std::endl;
    return false;
  }
  else if (is_final_pass() && arg.type.type != type) {
    err_ << call.func << "() only supports " << type << " arguments";
    err_ << " (" << arg.type.type << " provided)" << std::endl;
    return false;
  }
  return true;
}

bool SemanticAnalyser::check_alpha_numeric(const Call &call, int arg_num __attribute__((unused)))
{
  if (!call.vargs)
    return false;

  auto &arg = static_cast<String&>(*call.vargs->at(0)).str;

  bool is_alpha = std::regex_match(arg, std::regex("^[a-zA-Z0-9_-]+$"));
  if (!is_alpha)
  {
    err_ << call.func << "() expects an alpha numeric string as input";
    err_ << " (\"" << arg << "\" provided)" << std::endl;
    return false;
  }

  return true;
}

} // namespace ast
} // namespace bpftrace
