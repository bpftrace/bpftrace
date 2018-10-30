#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_username)
{
  test("kprobe:f { @x = username; @y = gid}",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@y_val" = alloca i64, align 8
  %"@y_key" = alloca i64, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %get_uid_gid = tail call i64 inttoptr (i64 15 to i64 ()*)()
  %1 = and i64 %get_uid_gid, 4294967295
  %2 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 0, i64* %"@x_key", align 8
  %3 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 %1, i64* %"@x_val", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  %get_uid_gid1 = call i64 inttoptr (i64 15 to i64 ()*)()
  %4 = lshr i64 %get_uid_gid1, 32
  %5 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  store i64 0, i64* %"@y_key", align 8
  %6 = bitcast i64* %"@y_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 %4, i64* %"@y_val", align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem3 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo2, i64* nonnull %"@y_key", i64* nonnull %"@y_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
