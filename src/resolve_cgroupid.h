#pragma once

#include <cstdint>
#include <string>

namespace bpftrace_linux
{

std::uint64_t resolve_cgroupid(const std::string &path);

}
