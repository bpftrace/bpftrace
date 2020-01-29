#pragma once

#include "bpffeature.h"
#include "bpftrace.h"
#include "gmock/gmock.h"

namespace bpftrace {
namespace test {

class MockBPFtrace : public BPFtrace {
public:
#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Winconsistent-missing-override"
#endif
  MOCK_CONST_METHOD1(get_symbols_from_file,
      std::unique_ptr<std::istream>(const std::string &path));
  MOCK_CONST_METHOD2(get_symbols_from_usdt,
      std::unique_ptr<std::istream>(int pid, const std::string &target));
  MOCK_CONST_METHOD1(extract_func_symbols_from_path,
      std::string(const std::string &path));
#pragma GCC diagnostic pop
  std::vector<Probe> get_probes()
  {
    return probes_;
  }
  std::vector<Probe> get_special_probes()
  {
    return special_probes_;
  }

  int resolve_uname(const std::string &name,
                    struct symbol *sym,
                    const std::string &path) const override
  {
    (void)path;
    sym->name = name;
    if (name == "cpp_mangled" || name == "cpp_mangled(int)")
    {
      return -1;
    }
    else if (name[0] > 'A' && name[0] < 'z')
    {
      sym->address = 12345;
      sym->size = 4;
    }
    else
    {
      auto fields = split_string(name, '_');
      sym->address = std::stoull(fields.at(0));
      sym->size = std::stoull(fields.at(1));
    }
    return 0;
  }
};

std::unique_ptr<MockBPFtrace> get_mock_bpftrace();
std::unique_ptr<MockBPFtrace> get_strict_mock_bpftrace();

class MockBPFfeature : public BPFfeature
{
public:
  MockBPFfeature(bool has_features = true)
  {
    has_loop_ = has_signal_ = has_get_current_cgroup_id_ =
        has_override_return_ = has_features;
  };
};

} // namespace test
} // namespace bpftrace
