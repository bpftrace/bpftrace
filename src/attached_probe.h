#pragma once

#include "bpftrace.h"

namespace bpftrace {

class AttachedProbe
{
public:
  AttachedProbe(Probe &probe, std::tuple<uint8_t *, uintptr_t> &func);
  ~AttachedProbe();
  AttachedProbe(const AttachedProbe &) = delete;
  AttachedProbe& operator=(const AttachedProbe &) = delete;

private:
  const char *eventname() const;
  void load_prog();
  void attach_kprobe();

  Probe &probe_;
  std::tuple<uint8_t *, uintptr_t> &func_;
  void *perf_reader_;
  int progfd_;
};

} // namespace bpftrace
