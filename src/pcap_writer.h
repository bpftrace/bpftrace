#pragma once

#include <cstdint>
#include <string>

struct pcap;
using pcap_t = struct pcap;

struct pcap_dumper;
using pcap_dumper_t = struct pcap_dumper;

namespace bpftrace {

class PCAPwriter {
public:
  PCAPwriter() = default;
  ~PCAPwriter() = default;

  bool open(std::string file);
  void close();

  bool write(uint64_t ns, const void *pkt, unsigned int size);

private:
  pcap_t *pd_;
  pcap_dumper_t *pdumper_;
};

}; // namespace bpftrace
