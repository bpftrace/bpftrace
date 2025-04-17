#include "gtest/gtest.h"
#include <cstdlib>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

class ThrowListener : public testing::EmptyTestEventListener {
  void OnTestPartResult(const testing::TestPartResult& result) override
  {
    if (result.type() == testing::TestPartResult::kFatalFailure) {
      throw testing::AssertionException(result);
    }
  }
};

class OutputSuppressorListener : public testing::EmptyTestEventListener {
public:
  void OnTestStart(const testing::TestInfo& /*test_info*/) override
  {
    // stash original stderr
    original_stderr_ = dup(STDERR_FILENO);
    if (original_stderr_ == -1) {
      return;
    }

    // create a temp file
    constexpr unsigned int NO_FLAGS = 0;
    memfd_ = memfd_create("stderr_capture", NO_FLAGS);
    if (memfd_ == -1) {
      close(original_stderr_);
      original_stderr_ = -1;
      return;
    }

    // redirect stderr to temp file
    dup2(memfd_, STDERR_FILENO);
  }

  void OnTestEnd(const testing::TestInfo& test_info) override
  {
    if (original_stderr_ != -1) {
      // restore output if test failed
      if (test_info.result()->Failed()) {
        restore_output();
      }

      if (original_stderr_ != -1) {
        dup2(original_stderr_, STDERR_FILENO);
        close(original_stderr_);
        original_stderr_ = -1;
      }
    }
  }

private:
  void restore_output()
  {
    if (memfd_ && original_stderr_ != -1) {
      // temporarily switch back to original stderr
      int old = dup(STDERR_FILENO);
      dup2(original_stderr_, STDERR_FILENO);

      // reset file pointer and output content
      lseek(memfd_, 0, SEEK_SET);
      char buffer[1024];
      ssize_t n;
      while ((n = read(memfd_, buffer, sizeof(buffer))) > 0) {
        std::cerr << buffer;
      }

      // restore to temp file
      dup2(old, STDERR_FILENO);
      close(old);
    }
  }

  int memfd_ = -1;
  int original_stderr_ = -1;
};

int main(int argc, char* argv[])
{
  ::testing::InitGoogleTest(&argc, argv);
  ::testing::UnitTest::GetInstance()->listeners().Append(new ThrowListener);
  ::testing::UnitTest::GetInstance()->listeners().Append(
      new OutputSuppressorListener);
  return RUN_ALL_TESTS();
}
