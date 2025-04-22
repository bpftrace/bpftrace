#pragma once

#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <stdexcept>
#include <sys/stat.h>

#include "util/temp.h"

namespace {
#include "data/data_source_dwarf.h"
} // namespace

class test_dwarf : public ::testing::Test {
protected:
  void SetUp() override
  {
    auto r = bpftrace::util::TempFile::create();
    ASSERT_TRUE(bool(r));
    std::span<const char> bytes(reinterpret_cast<const char *>(dwarf_data),
                                sizeof(dwarf_data));
    ASSERT_TRUE(bool(r->write_all(bytes)));
    file.emplace(std::move(*r));
    path = file->path().string();
    bin_ = path.c_str();

    // Ensure that it is executable.
    ASSERT_EQ(::chmod(bin_, 0755), 0);
  }

  std::optional<bpftrace::util::TempFile> file;
  std::string path;
  const char *bin_; // Reference to path.c_str().
};
