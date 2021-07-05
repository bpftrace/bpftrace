#pragma once

#include <string>

struct pcap;
typedef struct pcap pcap_t;

struct pcap_dumper;
typedef struct pcap_dumper pcap_dumper_t;

namespace bpftrace {

class PCAPwriter {
public:
  PCAPwriter() { }
  ~PCAPwriter() { }

  bool open(std::string file);
  void close(void);

  bool write(uint64_t ns, void *pkt, unsigned int size);

private:
  pcap_t          *pd_;
  pcap_dumper_t   *pdumper_;
};

}; // namespace bpftrace
