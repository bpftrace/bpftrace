#pragma once

#include <sys/stat.h>

#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <stdexcept>

namespace {
#include "data/dwarf_data.h"
} // namespace

class test_dwarf : public ::testing::Test {
protected:
  static void SetUpTestSuite()
  {
    std::ofstream file(bin_, std::ios::trunc | std::ios::binary);
    file.write(reinterpret_cast<const char *>(dwarf_data), dwarf_data_len);
    file.close();
    ASSERT_TRUE(file);

    // Give executable permissions to everyone
    ASSERT_EQ(::chmod(bin_, 0755), 0);
  }

  static void TearDownTestSuite()
  {
    std::remove(bin_);
  }

  static constexpr const char *bin_ = "/tmp/bpftrace-test-dwarf-data";
};
