#include <map>

#include "ast/ast.h"
#include "types.h"

namespace bpftrace::ast {

struct arg_type_spec {
  Type type = Type::integer;
  bool literal = false;

  // This indicates that this is just a placeholder as we use the index in the
  // vector of arg_type_spec as the number argument to check.
  bool skip_check = false;
};

struct map_type_spec {
  // This indicates that the argument must be a map type. The given function
  // may be called to determine the map type.
  std::function<SizedType(const Call &call)> type;
};

struct map_key_spec {
  // This indicates that the argument is a key expression for another map
  // argument, which is found in argument `map_index`.
  size_t map_index;
};

struct call_spec {
  size_t min_args = 0;
  size_t max_args = 0;
  bool discard_ret_warn = false;
  // NOLINTBEGIN(readability-redundant-member-init)
  std::vector<std::variant<arg_type_spec, map_type_spec, map_key_spec>>
      arg_types = {};
  // NOLINTEND(readability-redundant-member-init)
};

static const std::map<std::string, call_spec> CALL_SPEC = {
  { "avg",
    { .min_args = 3,
      .max_args = 3,
      .arg_types = { map_type_spec{
                         .type = std::function<SizedType(const ast::Call &)>(
                             [](const ast::Call &call) -> SizedType {
                               return CreateAvg(
                                   call.vargs.at(2).type().IsSigned());
                             }) },
                     map_key_spec{ .map_index = 0 },
                     arg_type_spec{ .type = Type::integer } } } },
  { "bswap", { .min_args = 1, .max_args = 1, .discard_ret_warn = true } },
  { "buf",
    { .min_args=1,
      .max_args=2,
      .discard_ret_warn = true,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "cat",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "cgroupid",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "cgroup_path",
    { .min_args=1,
      .max_args=2,
      .discard_ret_warn = true,
      .arg_types={
        arg_type_spec{ .type=Type::integer },
        arg_type_spec{ .type=Type::string } } } },
  { "clear",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        map_type_spec{},
      }
      } },
  { "count",
    { .min_args=2,
      .max_args=2,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const Call&)>([](const ast::Call&) -> SizedType { return CreateCount(); })
        },
        map_key_spec{ .map_index=0 },
      }
       } },
  { "debugf",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "delete",
    { .min_args=2,
      .max_args=2,
      .arg_types={
        map_type_spec{},
        map_key_spec{ .map_index=0 },
      }
       } },
  { "errorf",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "exit",
    { .min_args=0,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::integer } } } },
  { "has_key",
    { .min_args=2,
      .max_args=2,
      .discard_ret_warn = true,
      .arg_types={
        map_type_spec{},
        map_key_spec{ .map_index=0 },
      }
    } },
  { "hist",
    { .min_args=3,
      .max_args=4,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([]([[maybe_unused]] const ast::Call &call) -> SizedType { return CreateHist(); })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer },
        arg_type_spec{ .type=Type::integer, .literal=true } } } },
  { "join",
    { .min_args=1,
      .max_args=2,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "kaddr",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "kptr",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true, } },
  { "kstack",
    { .min_args=0,
      .max_args=2,
      .discard_ret_warn = true, } },
  { "ksym",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true, } },
  { "len",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true,
      // This cannot be checked without overloading: it requires *either* a
      // stack type, or a non-scalar map.
    } },
  { "lhist",
    { .min_args=6,
      .max_args=6,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([]([[maybe_unused]] const ast::Call &call) -> SizedType { return CreateLhist(); })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::integer, .literal=true } } } },
  { "tseries",
    { .min_args=5,
      .max_args=6,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([]([[maybe_unused]] const ast::Call &call) -> SizedType { return CreateTSeries(); })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "macaddr",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true, } },
  { "max",
    { .min_args=3,
      .max_args=3,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([](const ast::Call &call) -> SizedType { return CreateMax(call.vargs.at(2).type().IsSigned()); })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer } } } },
  { "min",
    { .min_args=3,
      .max_args=3,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([](const ast::Call &call) -> SizedType { return CreateMin(call.vargs.at(2).type().IsSigned()); })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer } } } },
  { "nsecs",
    { .min_args=0,
      .max_args=1,
      .discard_ret_warn = true,
      .arg_types={
        arg_type_spec{ .type=Type::timestamp_mode } } } },
  { "ntop",
    { .min_args=1,
      .max_args=2,
      .discard_ret_warn = true, } },
  { "offsetof",
    { .min_args=2,
      .max_args=2,
      .discard_ret_warn = true, } },
  { "override",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::integer } } } },
  { "path",
    { .min_args=1,
      .max_args=2,
      .discard_ret_warn = true,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer, .literal=true } } } },
  { "percpu_kaddr",
    { .min_args=1,
      .max_args=2,
      .discard_ret_warn = true,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "print",
    { .min_args=1,
      .max_args=3,
      .arg_types={
        // This may be a pure map or not.
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::integer, .literal=true } } } },

  { "printf",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "pton",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true, } },
  { "reg",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "signal",
    { .min_args=1,
      .max_args=1,
       } },
  { "sizeof",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true, } },
  { "skboutput",
    { .min_args=4,
      .max_args=4,
      .discard_ret_warn = true,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true }, // pcap file name
        arg_type_spec{ .type=Type::pointer },      // *skb
        arg_type_spec{ .type=Type::integer },      // cap length
        // cap offset, default is 0
        // some tracepoints like dev_queue_xmit will output ethernet header,
        // set offset to 14 bytes can exclude this header
        arg_type_spec{ .type=Type::integer } } } },
  { "stats",
    { .min_args=3,
      .max_args=3,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([](const ast::Call &call) -> SizedType { return CreateStats(call.vargs.at(2).type().IsSigned()); })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer } } } },
  { "str",
    { .min_args=1,
      .max_args=2,
      .discard_ret_warn = true,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "strerror",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true,
      .arg_types={
        arg_type_spec{ .type=Type::integer } } } },
  { "strftime",
    { .min_args=2,
      .max_args=2,
      .discard_ret_warn = true,
      .arg_types={
          arg_type_spec{ .type=Type::string, .literal=true },
          arg_type_spec{ .type=Type::integer } } } },
  { "strcontains",
    { .min_args=2,
      .max_args=2,
      .discard_ret_warn = true,
      .arg_types={
          arg_type_spec{ .type=Type::string, .literal=false },
          arg_type_spec{ .type=Type::string, .literal=false } } } },
  { "strncmp",
    { .min_args=3,
      .max_args=3,
      .discard_ret_warn = true,
      .arg_types={
          arg_type_spec{ .type=Type::string },
          arg_type_spec{ .type=Type::string },
          arg_type_spec{ .type=Type::integer, .literal=true } } } },
  { "sum",
    { .min_args=3,
      .max_args=3,
      .arg_types={
        map_type_spec{
          .type = std::function<SizedType(const ast::Call&)>([](const ast::Call &call) -> SizedType { return CreateSum(call.vargs.at(2).type().IsSigned()); })
        },
        map_key_spec{ .map_index=0 },
        arg_type_spec{ .type=Type::integer } } } },
  { "system",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "time",
    { .min_args=0,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "uaddr",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "unwatch",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::integer } } } },
  { "uptr",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true, } },
  { "ustack",
    { .min_args=0,
      .max_args=2,
      .discard_ret_warn = true, } },
  { "usym",
    { .min_args=1,
      .max_args=1,
      .discard_ret_warn = true, } },
  { "zero",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        map_type_spec{},
      } } },
  { "pid",
    { .min_args=0,
      .max_args=1,
      .discard_ret_warn = true },
  },
  { "socket_cookie",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::pointer }, // struct sock *
      } } },
};

} // namespace bpftrace::ast
