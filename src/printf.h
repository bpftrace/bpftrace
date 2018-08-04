#include <sstream>

#include "ast.h"
#include "types.h"

namespace bpftrace {

struct Field;

std::string verify_format_string(const std::string &fmt, std::vector<Field> args);

} // namespace bpftrace
