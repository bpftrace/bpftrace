#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace bpftrace::util {

void get_uint64_env_var(const ::std::string &str,
                        const std::function<void(uint64_t)> &cb);
void get_bool_env_var(const ::std::string &str,
                      const std::function<void(bool)> &cb);

} // namespace bpftrace::util
