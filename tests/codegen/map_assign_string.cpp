#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, map_assign_string)
{
  test("kprobe:f { @x = \"blah\"; }",

#if LLVM_VERSION_MAJOR > 6
R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca i64, align 8
  %str = alloca [64 x i8], align 1
  %1 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i8 98, i8* %1, align 1
  %str.repack1 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 1
  store i8 108, i8* %str.repack1, align 1
  %str.repack2 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 2
  store i8 97, i8* %str.repack2, align 1
  %str.repack3 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 3
  store i8 104, i8* %str.repack3, align 1
  %str.repack4 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 4
  %2 = bitcast i64* %"@x_key" to i8*
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %str.repack4, i8 0, i64 60, i1 false)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 0, i64* %"@x_key", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", [64 x i8]* nonnull %str, i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#elif LLVM_VERSION_MAJOR == 6
R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca i64, align 8
  %str = alloca [64 x i8], align 1
  %1 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i8 98, i8* %1, align 1
  %str.repack1 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 1
  store i8 108, i8* %str.repack1, align 1
  %str.repack2 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 2
  store i8 97, i8* %str.repack2, align 1
  %str.repack3 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 3
  store i8 104, i8* %str.repack3, align 1
  %str.repack4 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 4
  %2 = bitcast i64* %"@x_key" to i8*
  call void @llvm.memset.p0i8.i64(i8* nonnull %str.repack4, i8 0, i64 60, i32 1, i1 false)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 0, i64* %"@x_key", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", [64 x i8]* nonnull %str, i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#else
R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca i64, align 8
  %str = alloca [64 x i8], align 1
  %1 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i8 98, i8* %1, align 1
  %str.repack1 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 1
  store i8 108, i8* %str.repack1, align 1
  %str.repack2 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 2
  store i8 97, i8* %str.repack2, align 1
  %str.repack3 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 3
  store i8 104, i8* %str.repack3, align 1
  %str.repack4 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 4
  %2 = bitcast i64* %"@x_key" to i8*
  call void @llvm.memset.p0i8.i64(i8* %str.repack4, i8 0, i64 60, i32 1, i1 false)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 0, i64* %"@x_key", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", [64 x i8]* nonnull %str, i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#endif
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
