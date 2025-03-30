#pragma once

#include <array>
#include <cstdint>
#include <unistd.h>

#include "data/btf_data.h"
#include "util/temp.h"
#include "gtest/gtest.h"

using bpftrace::util::TempFile;

class test_btf : public ::testing::Test {
protected:
  void SetUp() override
  {
    auto f1 = TempFile::create();
    ASSERT_TRUE(bool(f1));
    ASSERT_TRUE(bool(f1->write_all({ btf_data, btf_data_len })));
    setenv("BPFTRACE_BTF", f1->path().c_str(), true);
    btf_path.emplace(std::move(*f1));

    auto f2 = TempFile::create();
    ASSERT_TRUE(bool(f2));
    ASSERT_TRUE(bool(f2->write_all({ func_list, func_list_len })));
    funcs_path.emplace(std::move(*f1));
    setenv("BPFTRACE_AVAILABLE_FUNCTIONS_TEST", f2->path().c_str(), true);
  }

  void TearDown() override
  {
    // clear the environment and remove the temp files.
    unsetenv("BPFTRACE_BTF");
    btf_path.reset();
    unsetenv("BPFTRACE_AVAILABLE_FUNCTIONS_TEST");
    funcs_path.reset();
  }

  std::optional<TempFile> btf_path;
  std::optional<TempFile> funcs_path;
};

class test_bad_btf : public ::testing::Test {
protected:
  void SetUp() override
  {
    auto f1 = TempFile::create();
    ASSERT_TRUE(bool(f1));
    static std::vector<char> invalid = { 0xDE, 0xAD, 0xBE, 0xEF };
    ASSERT_TRUE(bool(f1->write_all({ invalid.data(), invalid.size() })));
    setenv("BPFTRACE_BTF", f1->path().c_str(), true);
    btf_path.emplace(std::move(*f1));
  }

  void TearDown() override
  {
    // clear the environment and remove the temp files.
    unsetenv("BPFTRACE_BTF");
    btf_path.reset();
  }

  std::optional<TempFile> btf_path;
};
