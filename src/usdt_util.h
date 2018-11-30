#pragma once

#include <tuple>

typedef std::tuple<std::string, std::string> usdt_probe_pair;

namespace bpftrace {

class USDTHelper
{
public:
  static usdt_probe_pair find(void *ctx, int pid, std::string name);
};

}
