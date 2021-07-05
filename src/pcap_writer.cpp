#include "pcap_writer.h"

#ifdef HAVE_LIBPCAP
#include <pcap/pcap.h>

namespace bpftrace {

bool PCAPwriter::open(std::string file)
{
  pd_ = pcap_open_dead(DLT_RAW, 65535);
  if (!pd_)
    return false;

  pdumper_ = pcap_dump_open(pd_, file.c_str());
  return true;
}

void PCAPwriter::close(void)
{
  pcap_close(pd_);
  pcap_dump_close(pdumper_);
}

#define NSEC_PER_SEC    1000000000L
#define NSEC_PER_USEC   1000L

bool PCAPwriter::write(uint64_t ns, void *pkt, unsigned int size)
{
  time_t secs, usecs, nsecs = ns;

  secs   = nsecs / NSEC_PER_SEC;
  nsecs -= secs  * NSEC_PER_SEC;
  usecs  = nsecs / NSEC_PER_USEC;

  struct pcap_pkthdr hdr = {
    .ts     = {
      .tv_sec  = secs,
      .tv_usec = usecs,
    },
    .caplen = size,
    .len    = size,
  };

  pcap_dump((u_char*) pdumper_, &hdr, (const u_char*) pkt);
  return true;
}

}; // namespace bpftrace

#else

namespace bpftrace {

bool PCAPwriter::open(std::string file __attribute__((__unused__)),
                      unsigned int caplen __attribute__((__unused__)))
{
  return false;
}

void PCAPwriter::close(void)
{
}

bool PCAPwriter::write(uint64_t ns __attribute__((__unused__)),
                       void *pkt __attribute__((__unused__)))
{
  return false;
}

}; // namespace bpftrace

#endif // HAVE_LIBPCAP
