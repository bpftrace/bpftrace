#include <sstream>

namespace bpftrace {

void list_probes(const std::string &search = "", int pid = 0);
//void list_probes(int pid = 0);

} // namespace bpftrace
