#pragma once

#include "data/btf_data.h"

class test_btf : public ::testing::Test
{
protected:
  void SetUp() override
  {
    char *path = strdup("/tmp/XXXXXX");
    if (!path)
      return;

    int fd = mkstemp(path);
    if (fd < 0)
    {
      std::remove(path);
      return;
    }

    if (write(fd, btf_data, btf_data_len) != btf_data_len)
    {
      close(fd);
      std::remove(path);
      return;
    }

    close(fd);
    setenv("BPFTRACE_BTF", path, true);
    path_ = path;
  }

  void TearDown() override
  {
    // clear the environment and remove the temp file
    unsetenv("BPFTRACE_BTF");
    if (path_)
      std::remove(path_);
  }

  char *path_ = nullptr;
};
