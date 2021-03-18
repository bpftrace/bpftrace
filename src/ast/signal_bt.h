// This file is name "signal_bt.h" so it doesn't shadow "<signal.h>"

#pragma once

#include <csignal>
#include <string>

namespace bpftrace {

int signal_name_to_num(const std::string &signal);

} // namespace bpftrace
