#pragma once

#include <bpf/bpf.h>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

std::ostream &operator<<(std::ostream &out, const bpf_func_id &id);

// Returns the id of the helper with the given name, e.g. "bpf_send_signal".
std::optional<bpf_func_id> bpf_func_id_from_name(std::string_view name);

// Returns the names of all helpers with an id, e.g. "bpf_send_signal".
std::vector<std::string> bpf_func_names();
