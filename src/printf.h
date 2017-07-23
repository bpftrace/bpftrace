#include <sstream>

#include "ast.h"
#include "types.h"

namespace bpftrace {

std::string verify_format_string(const std::string &fmt, std::vector<SizedType> args);

} // namespace bpftrace
