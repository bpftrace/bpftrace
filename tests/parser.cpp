#include "gtest/gtest.h"

TEST(test1, aaa)
{
}

int main(int argc, char *argv[])
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
