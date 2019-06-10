#include <sys/stat.h>
#include <iostream>
#include <regex>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "bpftrace.h"
#include "mocks.h"
#include "list.h"

namespace bpftrace {
namespace test {
namespace list {

using ::testing::ContainerEq;
using ::testing::StrictMock;
using namespace std;

void vector_from_output(std::stringstream &ss, std::regex ex, std::vector<string>& results, bool fail_on_mismatch) {
  string tmp;
  while (getline(ss, tmp)) {
    if (!ss) {
      return;
    } else {
      if (std::regex_match(tmp, ex)) {
        auto pos = tmp.find(':');
        auto s = tmp.substr(pos + 1, (tmp.length() - pos - 2));
        results.push_back(s);
      } else if(fail_on_mismatch) {
        FAIL() << "mismatch found: " << tmp << endl;
      }
    }
  }
}

void compare_probe_list(std::vector<ProbeListItem> pList, std::vector<string> sList)
{
  EXPECT_EQ(pList.size(), sList.size());
  for (auto i=0; i<pList.size(); i++)
  {
    EXPECT_EQ(pList[i].path, sList[i]);
  }
}

TEST(list, empty_arg_test)
{
  BPFtrace bpftrace;
  testing::internal::CaptureStdout();
  list_probes(bpftrace, "");
  std::string output = testing::internal::GetCapturedStdout();
  std::stringstream sw_out(output);
  std::stringstream hw_out(output);
  std::vector<string> sw_results;
  std::vector<string> hw_results;
  vector_from_output(sw_out, regex("software:.*"), sw_results, false);
  vector_from_output(hw_out, regex("hardware:.*"), hw_results, false);
  compare_probe_list(SW_PROBE_LIST, sw_results);
  compare_probe_list(HW_PROBE_LIST, hw_results);
}
TEST(list, software_test)
{
  BPFtrace bpftrace;
  testing::internal::CaptureStdout();
  list_probes(bpftrace, "software*");
  std::string output = testing::internal::GetCapturedStdout();
  std::stringstream ss(output);
  std::vector<string> results;
  vector_from_output(ss, regex("software:.*"),results, true);
  compare_probe_list(SW_PROBE_LIST, results);
}
TEST(list, hardware_test)
{
  BPFtrace bpftrace;
  testing::internal::CaptureStdout();
  list_probes(bpftrace, "hardware*");
  std::string output = testing::internal::GetCapturedStdout();
  std::stringstream ss(output);
  std::vector<string> results;
  vector_from_output(ss, regex("hardware:.*"),results, true);
  compare_probe_list(HW_PROBE_LIST, results);
}
TEST(list, expect_empty)
{
  BPFtrace bpftrace;
  testing::internal::CaptureStdout();
  list_probes(bpftrace, "xxxx");
  std::string output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(0, output.length());
}
TEST(list, find_cpu)
{
  vector<ProbeListItem> expected_results;
  ProbeListItem p1 = {"cpu-clock"};
  ProbeListItem p2 = {"cpu-migrations"};
  ProbeListItem p3 = {"cpu-cycles"};
  expected_results.push_back(p1);
  expected_results.push_back(p2);
  expected_results.push_back(p3);
  BPFtrace bpftrace;
  testing::internal::CaptureStdout();
  list_probes(bpftrace, "*cpu*");
  std::string output = testing::internal::GetCapturedStdout();
  std::stringstream ss(output);
  std::vector<string> results;
  vector_from_output(ss, regex(".*cpu.*"), results, false);
  compare_probe_list(expected_results, results);
}
}
}
}
