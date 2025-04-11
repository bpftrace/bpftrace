#include "gtest/gtest.h"
#include <cstdio>
#include <cstdlib>
#include <string>
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
    temp_stderr_ = tmpfile();
    if (!temp_stderr_) {
      close(original_stderr_);
      original_stderr_ = -1;
      return;
    }

    // redirect stderr to temp file
    dup2(fileno(temp_stderr_), STDERR_FILENO);
  }

  void OnTestEnd(const testing::TestInfo& test_info) override
  {
    if (original_stderr_ != -1) {
      // restore output if test failed
      if (test_info.result()->Failed()) {
        restore_output();
      }

      if (temp_stderr_) {
        fclose(temp_stderr_);
        temp_stderr_ = nullptr;
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
    if (temp_stderr_ && original_stderr_ != -1) {
      // temporarily switch back to original stderr
      int old = dup(STDERR_FILENO);
      dup2(original_stderr_, STDERR_FILENO);

      // reset file pointer and output content
      rewind(temp_stderr_);
      char buffer[1024];
      while (fgets(buffer, sizeof(buffer), temp_stderr_)) {
        std::cerr << buffer;
      }

      // restore to temp file
      dup2(old, STDERR_FILENO);
      close(old);
    }
  }

  FILE* temp_stderr_ = nullptr;
  int original_stderr_ = -1;
};

int main(int argc, char* argv[])
{
  ::testing::InitGoogleTest(&argc, argv);
  ::testing::UnitTest::GetInstance()->listeners().Append(new ThrowListener);
  const char* env = getenv("BPFTRACE_HIDE_LOG_MSG");
  if (env && std::string(env) == "1") {
    ::testing::UnitTest::GetInstance()->listeners().Append(
        new OutputSuppressorListener);
  }
  return RUN_ALL_TESTS();
}
