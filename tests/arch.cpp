#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>
#include <sstream>

#include "arch/arch.h"

namespace bpftrace::test::arch {

using namespace bpftrace::arch;
using ::testing::AnyOf;
using ::testing::Eq;

template <typename T>
class ArchTest : public testing::Test {
  using Arch = T;
};

class ArchTestNameGenerator {
public:
  template <typename T>
  static std::string GetName([[maybe_unused]] int index)
  {
    std::stringstream ss;
    ss << T::Machine;
    return ss.str();
  }
};

using MachineTypes = ::testing::Types<Arch<Machine::X86_64>,
                                      Arch<Machine::ARM>,
                                      Arch<Machine::ARM64>,
                                      Arch<Machine::S390X>,
                                      Arch<Machine::PPC64>,
                                      Arch<Machine::MIPS64>,
                                      Arch<Machine::RISCV64>,
                                      Arch<Machine::LOONGARCH64>>;
TYPED_TEST_SUITE(ArchTest, MachineTypes, ArchTestNameGenerator);

TYPED_TEST(ArchTest, Sanity)
{
  EXPECT_GT(TypeParam::kernel_ptr_width(), 0);
  EXPECT_TRUE(!TypeParam::asm_arch().empty());
}

TYPED_TEST(ArchTest, CDefs)
{
  EXPECT_TRUE(!TypeParam::c_defs().empty());
}

TYPED_TEST(ArchTest, ValidArguments)
{
  for (const auto &reg : TypeParam::arguments()) {
    EXPECT_TRUE(TypeParam::register_to_pt_regs_expr(reg).has_value());
    EXPECT_TRUE(TypeParam::register_to_pt_regs_offset(reg).has_value());
  }
}

TYPED_TEST(ArchTest, InvalidRegister)
{
  EXPECT_FALSE(TypeParam::register_to_pt_regs_expr("invalid").has_value());
  EXPECT_FALSE(TypeParam::register_to_pt_regs_offset("invalid").has_value());
}

TYPED_TEST(ArchTest, ValidReturnValue)
{
  EXPECT_TRUE(!TypeParam::return_value().empty());
  EXPECT_TRUE(TypeParam::register_to_pt_regs_expr(TypeParam::return_value())
                  .has_value());
  EXPECT_TRUE(TypeParam::register_to_pt_regs_offset(TypeParam::return_value())
                  .has_value());
}

TYPED_TEST(ArchTest, ValidProgramCounter)
{
  EXPECT_TRUE(!TypeParam::pc_value().empty());
  EXPECT_TRUE(
      TypeParam::register_to_pt_regs_expr(TypeParam::pc_value()).has_value());
  EXPECT_TRUE(
      TypeParam::register_to_pt_regs_offset(TypeParam::pc_value()).has_value());
}

TYPED_TEST(ArchTest, ValidStackPointer)
{
  EXPECT_TRUE(!TypeParam::sp_value().empty());
  EXPECT_TRUE(
      TypeParam::register_to_pt_regs_expr(TypeParam::sp_value()).has_value());
  EXPECT_TRUE(
      TypeParam::register_to_pt_regs_offset(TypeParam::sp_value()).has_value());
}

TYPED_TEST(ArchTest, ValidWatchpointModes)
{
  for (const auto &mode : TypeParam::watchpoint_modes()) {
    for (const auto &c : mode) {
      EXPECT_THAT(c, AnyOf(Eq('r'), Eq('w'), Eq('x')));
    }
  }
}

} // namespace bpftrace::test::arch
