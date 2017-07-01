#pragma once

#include "types.h"

namespace bpftrace {

class AttachedProbe
{
public:
  AttachedProbe(Probe &probe, std::tuple<uint8_t *, uintptr_t> &func);
  ~AttachedProbe();
  AttachedProbe(const AttachedProbe &) = delete;
  AttachedProbe& operator=(const AttachedProbe &) = delete;

private:
  std::string eventprefix() const;
  const char *eventname() const;
  uint64_t offset() const;
  void load_prog();
  void attach_kprobe();
  void attach_uprobe();

  Probe &probe_;
  std::tuple<uint8_t *, uintptr_t> &func_;
  void *perf_reader_;
  int progfd_;
};

} // namespace bpftrace
