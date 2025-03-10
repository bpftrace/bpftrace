#pragma once

#include <string>
#include <vector>

namespace bpftrace::util {

bool has_wildcard(const std::string &str);

bool wildcard_match(std::string_view str,
                    const std::vector<std::string> &tokens,
                    bool start_wildcard,
                    bool end_wildcard);

std::vector<std::string> get_wildcard_tokens(const std::string &input,
                                             bool &start_wildcard,
                                             bool &end_wildcard);

} // namespace bpftrace::util
