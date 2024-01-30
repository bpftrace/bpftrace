#pragma once

#include <sys/stat.h>

#include <cstdio>
#include <fcntl.h>
#include <stdexcept>

#include "data/dwarf_data.h"

class test_dwarf : public ::testing::Test {
protected:
  static void SetUpTestSuite()
  {
    std::ofstream file(bin_, std::ios::trunc | std::ios::binary);
    file.write(reinterpret_cast<const char *>(dwarf_data), dwarf_data_len);
    file.close();

    if (!file)
      throw std::runtime_error("Failed to create dwarf data file");

    // Give executable permissions to everyone
    int err = chmod(bin_, 0755);
    if (err)
      throw std::runtime_error("Failed to chmod dwarf data file: " +
                               std::to_string(err));
  }

  static void TearDownTestSuite()
  {
    std::remove(bin_);
  }

  static constexpr const char *bin_ = "/tmp/bpftrace-test-dwarf-data";
};
