#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_kstack)
{
  auto result = R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@y_val" = alloca i64, align 8
  %"@y_key" = alloca i64, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 4)
  %get_stackid = tail call i64 inttoptr (i64 27 to i64 (i8*, i8*, i64)*)(i8* %0, i64 %pseudo, i64 0)
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, i64* %"@x_key", align 8
  %2 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 %get_stackid, i64* %"@x_val", align 8
  %pseudo1 = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %get_stackid3 = call i64 inttoptr (i64 27 to i64 (i8*, i8*, i64)*)(i8* %0, i64 %pseudo2, i64 0)
  %3 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 0, i64* %"@y_key", align 8
  %4 = bitcast i64* %"@y_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 %get_stackid3, i64* %"@y_val", align 8
  %pseudo4 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem5 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo4, i64* nonnull %"@y_key", i64* nonnull %"@y_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED";

  // Mode doesn't directly affect codegen, so the programs below should
  // generate the same IR
  test("kprobe:f { @x = kstack(); @y = kstack(6) }", result);
  test("kprobe:f { @x = kstack(perf); @y = kstack(perf, 6) }", result);
  test("kprobe:f { @x = kstack(perf); @y = kstack(bpftrace) }", result);
}

TEST(codegen, call_kstack_mapids)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  FakeMap::next_mapfd_ = 1;

  ASSERT_EQ(driver.parse_str("kprobe:f { @x = kstack(5); @y = kstack(6); @z = kstack(6) }"), 0);

  ClangParser clang;
  clang.parse(driver.root_, bpftrace);

  ast::SemanticAnalyser semantics(driver.root_, bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);
  ASSERT_EQ(semantics.create_maps(true), 0);

  ast::CodegenLLVM codegen(driver.root_, bpftrace);
  codegen.compile();

  ASSERT_EQ(FakeMap::next_mapfd_, 7);
  ASSERT_EQ(bpftrace.stackid_maps_.size(), 2U);

  StackType stack_type;
  stack_type.limit = 5;
  ASSERT_EQ(bpftrace.stackid_maps_.count(stack_type), 1U);
  stack_type.limit = 6;
  ASSERT_EQ(bpftrace.stackid_maps_.count(stack_type), 1U);
}

TEST(codegen, call_kstack_modes_mapids)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  FakeMap::next_mapfd_ = 1;

  ASSERT_EQ(driver.parse_str("kprobe:f { @x = kstack(perf); @y = kstack(bpftrace); @z = kstack() }"), 0);

  ClangParser clang;
  clang.parse(driver.root_, bpftrace);

  ast::SemanticAnalyser semantics(driver.root_, bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);
  ASSERT_EQ(semantics.create_maps(true), 0);

  ast::CodegenLLVM codegen(driver.root_, bpftrace);
  codegen.compile();

  ASSERT_EQ(FakeMap::next_mapfd_, 7);
  ASSERT_EQ(bpftrace.stackid_maps_.size(), 2U);

  StackType stack_type;
  stack_type.mode = StackMode::perf;
  ASSERT_EQ(bpftrace.stackid_maps_.count(stack_type), 1U);
  stack_type.mode = StackMode::bpftrace;
  ASSERT_EQ(bpftrace.stackid_maps_.count(stack_type), 1U);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
