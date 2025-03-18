#include <sstream>

#include "util/env.h"
#include "util/exceptions.h"

namespace bpftrace::util {

void get_uint64_env_var(const ::std::string &str,
                        const std::function<void(uint64_t)> &cb)
{
  uint64_t dest;
  if (const char *env_p = std::getenv(str.c_str())) {
    std::istringstream stringstream(env_p);
    if (!(stringstream >> dest)) {
      throw FatalUserException(
          "Env var '" + str +
          "' did not contain a valid uint64_t, or was zero-valued.");
      return;
    }
    cb(dest);
  }
}

void get_bool_env_var(const ::std::string &str,
                      const std::function<void(bool)> &cb)
{
  if (const char *env_p = std::getenv(str.c_str())) {
    bool dest;
    std::string s(env_p);
    if (s == "1")
      dest = true;
    else if (s == "0")
      dest = false;
    else {
      throw FatalUserException("Env var '" + str +
                               "' did not contain a valid value (0 or 1).");
    }
    cb(dest);
  }
}

} // namespace bpftrace::util
