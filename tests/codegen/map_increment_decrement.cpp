#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, map_increment_decrement)
{
  test("BEGIN { @x = 10; @x++; ++@x; @x--; --@x; }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @BEGIN(i8* nocapture readnone) local_unnamed_addr section "s_BEGIN_1" {
entry:
  %"@x_newval35" = alloca i64, align 8
  %"@x_key27" = alloca i64, align 8
  %"@x_newval24" = alloca i64, align 8
  %"@x_key16" = alloca i64, align 8
  %"@x_newval13" = alloca i64, align 8
  %"@x_key5" = alloca i64, align 8
  %"@x_newval" = alloca i64, align 8
  %"@x_key1" = alloca i64, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, i64* %"@x_key", align 8
  %2 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 10, i64* %"@x_val", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  %3 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 0, i64* %"@x_key1", align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo2, i64* nonnull %"@x_key1")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %4 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %4, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %5 = bitcast i64* %"@x_newval" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  store i64 %lookup_elem_val.0, i64* %"@x_newval", align 8
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo3, i64* nonnull %"@x_key1", i64* nonnull %"@x_newval", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  %6 = bitcast i64* %"@x_key5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 0, i64* %"@x_key5", align 8
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem7 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo6, i64* nonnull %"@x_key5")
  %map_lookup_cond12 = icmp eq i8* %lookup_elem7, null
  br i1 %map_lookup_cond12, label %lookup_merge10, label %lookup_success8

lookup_success8:                                  ; preds = %lookup_merge
  %7 = load i64, i8* %lookup_elem7, align 8
  %phitmp38 = add i64 %7, 1
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_merge, %lookup_success8
  %lookup_elem_val11.0 = phi i64 [ %phitmp38, %lookup_success8 ], [ 1, %lookup_merge ]
  %8 = bitcast i64* %"@x_newval13" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %8)
  store i64 %lookup_elem_val11.0, i64* %"@x_newval13", align 8
  %pseudo14 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem15 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo14, i64* nonnull %"@x_key5", i64* nonnull %"@x_newval13", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %8)
  %9 = bitcast i64* %"@x_key16" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 0, i64* %"@x_key16", align 8
  %pseudo17 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem18 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo17, i64* nonnull %"@x_key16")
  %map_lookup_cond23 = icmp eq i8* %lookup_elem18, null
  br i1 %map_lookup_cond23, label %lookup_merge21, label %lookup_success19

lookup_success19:                                 ; preds = %lookup_merge10
  %10 = load i64, i8* %lookup_elem18, align 8
  %phitmp39 = add i64 %10, -1
  br label %lookup_merge21

lookup_merge21:                                   ; preds = %lookup_merge10, %lookup_success19
  %lookup_elem_val22.0 = phi i64 [ %phitmp39, %lookup_success19 ], [ -1, %lookup_merge10 ]
  %11 = bitcast i64* %"@x_newval24" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %11)
  store i64 %lookup_elem_val22.0, i64* %"@x_newval24", align 8
  %pseudo25 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem26 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo25, i64* nonnull %"@x_key16", i64* nonnull %"@x_newval24", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %11)
  %12 = bitcast i64* %"@x_key27" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %12)
  store i64 0, i64* %"@x_key27", align 8
  %pseudo28 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem29 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo28, i64* nonnull %"@x_key27")
  %map_lookup_cond34 = icmp eq i8* %lookup_elem29, null
  br i1 %map_lookup_cond34, label %lookup_merge32, label %lookup_success30

lookup_success30:                                 ; preds = %lookup_merge21
  %13 = load i64, i8* %lookup_elem29, align 8
  %phitmp40 = add i64 %13, -1
  br label %lookup_merge32

lookup_merge32:                                   ; preds = %lookup_merge21, %lookup_success30
  %lookup_elem_val33.0 = phi i64 [ %phitmp40, %lookup_success30 ], [ -1, %lookup_merge21 ]
  %14 = bitcast i64* %"@x_newval35" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %14)
  store i64 %lookup_elem_val33.0, i64* %"@x_newval35", align 8
  %pseudo36 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem37 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo36, i64* nonnull %"@x_key27", i64* nonnull %"@x_newval35", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %12)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %14)
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
