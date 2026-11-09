#pragma once

#include <bpf/bpf.h>
#include <iostream>
#include <optional>
#include <string_view>

std::ostream &operator<<(std::ostream &out, const bpf_func_id &id);

std::optional<bpf_func_id> helper_id_from_name(std::string_view name);
