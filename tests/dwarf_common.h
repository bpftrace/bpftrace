#pragma once

#include "data/dwarf_data.h"
#include <fcntl.h>

class test_dwarf : public ::testing::Test
{
protected:
  void SetUp() override
  {
    char *bin = strdup("/tmp/dwarf_dataXXXXXX");
    int fd = mkstemp(bin);
    if (fd < 0)
      return;

    fchmod(fd, S_IRUSR | S_IWUSR | S_IXUSR);

    if (write(fd, dwarf_data, dwarf_data_len) != dwarf_data_len)
    {
      close(fd);
      std::remove(bin);
      return;
    }

    close(fd);
    bin_ = bin;
  }

  void TearDown() override
  {
    if (bin_)
      std::remove(bin_);
  }

public:
  char *bin_ = nullptr;
};