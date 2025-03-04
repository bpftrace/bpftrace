#include <cstdint>
#include <string>

namespace bpftrace::ast::int_parser {

//   String -> int conversion specific to bpftrace
//
//   - error when trailing characters are found
//   - supports scientific notation, e.g. 1e6
//    - error when out of int range (1e20)
//    - error when base > 9 (12e3)
//   - support underscore as separator, e.g. 1_234_000
//
//   All errors are raised as std::invalid_argument exception
int64_t to_int(const std::string &num, int base);
uint64_t to_uint(const std::string &num, int base);

} // namespace bpftrace::ast::int_parser
