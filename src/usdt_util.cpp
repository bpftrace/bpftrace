#include <map>
#include <string>
#include <tuple>
#include "usdt_util.h"
#include "bcc_usdt.h"

namespace bpftrace {

static bool usdt_probe_cached = false;
static std::map<std::string, usdt_probe_pair> usdt_probe_cache_outer;

static void usdt_probe_each(struct bcc_usdt *usdt_probe) {
  usdt_probe_cache_outer[usdt_probe->name] = std::make_tuple(usdt_probe->provider, usdt_probe->bin_path);
}

usdt_probe_pair USDTHelper::find(void *ctx, int pid, std::string name) {
  bool ctx_created = false;

  if (!usdt_probe_cached) {
    if (ctx == nullptr) {
      ctx_created = true;
      ctx = bcc_usdt_new_frompid(pid, nullptr);
      if (ctx == nullptr)
        return std::make_tuple("", "");
    }

    bcc_usdt_foreach(ctx, usdt_probe_each);
    usdt_probe_cached = true;

    if (ctx_created)
      bcc_usdt_close(ctx);
  }

  std::map<std::string, usdt_probe_pair>::iterator p = usdt_probe_cache_outer.find(name);
  if (p == usdt_probe_cache_outer.end())
    return std::make_tuple("", "");
  else
    return p->second;
}

}
