#include "gmock/gmock.h"
#include "bpftrace.h"

namespace bpftrace {
namespace test {

class MockBPFtrace : public BPFtrace {
public:
  MOCK_CONST_METHOD1(get_symbols_from_file,
      std::unique_ptr<std::istream>(const std::string &path));
  MOCK_CONST_METHOD2(get_symbols_from_usdt,
      std::unique_ptr<std::istream>(int pid, const std::string &target));
  MOCK_CONST_METHOD1(extract_func_symbols_from_path,
      std::string(const std::string &path));
  std::vector<Probe> get_probes()
  {
    return probes_;
  }
  std::vector<Probe> get_special_probes()
  {
    return special_probes_;
  }
};

std::unique_ptr<MockBPFtrace> get_mock_bpftrace();
std::unique_ptr<MockBPFtrace> get_strict_mock_bpftrace();

} // namespace test
} // namespace bpftrace
