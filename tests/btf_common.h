#pragma once

#include <unistd.h>

#include "data/data_source_btf.h"
#include "data/data_source_funcs.h"
#include "util/temp.h"
#include "gtest/gtest.h"

using bpftrace::util::TempFile;

namespace bpftrace::test {

class test_btf : public ::testing::Test {
protected:
  void SetUp() override
  {
    auto f1 = TempFile::create();
    ASSERT_TRUE(bool(f1));
    ASSERT_TRUE(bool(f1->write_all(
        { reinterpret_cast<const char *>(btf_data), sizeof(btf_data) })));
    setenv("BPFTRACE_BTF", f1->path().c_str(), true);
    btf_path.emplace(std::move(*f1));

    auto f2 = TempFile::create();
    ASSERT_TRUE(bool(f2));
    ASSERT_TRUE(bool(f2->write_all(
        { reinterpret_cast<const char *>(func_list), sizeof(func_list) })));
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
    static std::vector<unsigned char> invalid = { 0xDE, 0xAD, 0xBE, 0xEF };
    ASSERT_TRUE(bool(f1->write_all(
        { reinterpret_cast<const char *>(invalid.data()), invalid.size() })));
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

} // namespace bpftrace::test
