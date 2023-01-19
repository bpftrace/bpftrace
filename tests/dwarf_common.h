#pragma once

#include "data/dwarf_data.h"
#include <fcntl.h>

class test_dwarf : public ::testing::Test
{
protected:
  void SetUp() override
  {
    std::string bin = "/tmp/bpftrace-test-dwarf-data";
    std::ofstream file(bin, std::ios::trunc | std::ios::binary);
    file.write(reinterpret_cast<const char *>(dwarf_data), dwarf_data_len);
    file.close();

    if (file)
      bin_ = bin;
  }

  void TearDown() override
  {
    bin_.clear();
  }

public:
  std::string bin_;
};
