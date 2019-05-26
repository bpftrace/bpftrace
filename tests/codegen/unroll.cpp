#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, unroll)
{
  test("BEGIN { @i = 0; unroll(5) { @i += 1 } }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @BEGIN(i8* nocapture readnone) local_unnamed_addr section "s_BEGIN_1" {
entry:
  %"@i_val52" = alloca i64, align 8
  %"@i_key51" = alloca i64, align 8
  %"@i_key43" = alloca i64, align 8
  %"@i_val40" = alloca i64, align 8
  %"@i_key39" = alloca i64, align 8
  %"@i_key31" = alloca i64, align 8
  %"@i_val28" = alloca i64, align 8
  %"@i_key27" = alloca i64, align 8
  %"@i_key19" = alloca i64, align 8
  %"@i_val16" = alloca i64, align 8
  %"@i_key15" = alloca i64, align 8
  %"@i_key7" = alloca i64, align 8
  %"@i_val4" = alloca i64, align 8
  %"@i_key3" = alloca i64, align 8
  %"@i_key1" = alloca i64, align 8
  %"@i_val" = alloca i64, align 8
  %"@i_key" = alloca i64, align 8
  %1 = bitcast i64* %"@i_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, i64* %"@i_key", align 8
  %2 = bitcast i64* %"@i_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 0, i64* %"@i_val", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@i_key", i64* nonnull %"@i_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  %3 = bitcast i64* %"@i_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 0, i64* %"@i_key1", align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo2, i64* nonnull %"@i_key1")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %4 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %4, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  %5 = bitcast i64* %"@i_key3" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  store i64 0, i64* %"@i_key3", align 8
  %6 = bitcast i64* %"@i_val4" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 %lookup_elem_val.0, i64* %"@i_val4", align 8
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem6 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo5, i64* nonnull %"@i_key3", i64* nonnull %"@i_val4", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  %7 = bitcast i64* %"@i_key7" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  store i64 0, i64* %"@i_key7", align 8
  %pseudo8 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem9 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo8, i64* nonnull %"@i_key7")
  %map_lookup_cond14 = icmp eq i8* %lookup_elem9, null
  br i1 %map_lookup_cond14, label %lookup_merge12, label %lookup_success10

lookup_success10:                                 ; preds = %lookup_merge
  %8 = load i64, i8* %lookup_elem9, align 8
  %phitmp55 = add i64 %8, 1
  br label %lookup_merge12

lookup_merge12:                                   ; preds = %lookup_merge, %lookup_success10
  %lookup_elem_val13.0 = phi i64 [ %phitmp55, %lookup_success10 ], [ 1, %lookup_merge ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  %9 = bitcast i64* %"@i_key15" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 0, i64* %"@i_key15", align 8
  %10 = bitcast i64* %"@i_val16" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %10)
  store i64 %lookup_elem_val13.0, i64* %"@i_val16", align 8
  %pseudo17 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem18 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo17, i64* nonnull %"@i_key15", i64* nonnull %"@i_val16", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %10)
  %11 = bitcast i64* %"@i_key19" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %11)
  store i64 0, i64* %"@i_key19", align 8
  %pseudo20 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem21 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo20, i64* nonnull %"@i_key19")
  %map_lookup_cond26 = icmp eq i8* %lookup_elem21, null
  br i1 %map_lookup_cond26, label %lookup_merge24, label %lookup_success22

lookup_success22:                                 ; preds = %lookup_merge12
  %12 = load i64, i8* %lookup_elem21, align 8
  %phitmp56 = add i64 %12, 1
  br label %lookup_merge24

lookup_merge24:                                   ; preds = %lookup_merge12, %lookup_success22
  %lookup_elem_val25.0 = phi i64 [ %phitmp56, %lookup_success22 ], [ 1, %lookup_merge12 ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %11)
  %13 = bitcast i64* %"@i_key27" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %13)
  store i64 0, i64* %"@i_key27", align 8
  %14 = bitcast i64* %"@i_val28" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %14)
  store i64 %lookup_elem_val25.0, i64* %"@i_val28", align 8
  %pseudo29 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem30 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo29, i64* nonnull %"@i_key27", i64* nonnull %"@i_val28", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %13)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %14)
  %15 = bitcast i64* %"@i_key31" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %15)
  store i64 0, i64* %"@i_key31", align 8
  %pseudo32 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem33 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo32, i64* nonnull %"@i_key31")
  %map_lookup_cond38 = icmp eq i8* %lookup_elem33, null
  br i1 %map_lookup_cond38, label %lookup_merge36, label %lookup_success34

lookup_success34:                                 ; preds = %lookup_merge24
  %16 = load i64, i8* %lookup_elem33, align 8
  %phitmp57 = add i64 %16, 1
  br label %lookup_merge36

lookup_merge36:                                   ; preds = %lookup_merge24, %lookup_success34
  %lookup_elem_val37.0 = phi i64 [ %phitmp57, %lookup_success34 ], [ 1, %lookup_merge24 ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %15)
  %17 = bitcast i64* %"@i_key39" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %17)
  store i64 0, i64* %"@i_key39", align 8
  %18 = bitcast i64* %"@i_val40" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %18)
  store i64 %lookup_elem_val37.0, i64* %"@i_val40", align 8
  %pseudo41 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem42 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo41, i64* nonnull %"@i_key39", i64* nonnull %"@i_val40", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %17)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %18)
  %19 = bitcast i64* %"@i_key43" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %19)
  store i64 0, i64* %"@i_key43", align 8
  %pseudo44 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem45 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo44, i64* nonnull %"@i_key43")
  %map_lookup_cond50 = icmp eq i8* %lookup_elem45, null
  br i1 %map_lookup_cond50, label %lookup_merge48, label %lookup_success46

lookup_success46:                                 ; preds = %lookup_merge36
  %20 = load i64, i8* %lookup_elem45, align 8
  %phitmp58 = add i64 %20, 1
  br label %lookup_merge48

lookup_merge48:                                   ; preds = %lookup_merge36, %lookup_success46
  %lookup_elem_val49.0 = phi i64 [ %phitmp58, %lookup_success46 ], [ 1, %lookup_merge36 ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %19)
  %21 = bitcast i64* %"@i_key51" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %21)
  store i64 0, i64* %"@i_key51", align 8
  %22 = bitcast i64* %"@i_val52" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %22)
  store i64 %lookup_elem_val49.0, i64* %"@i_val52", align 8
  %pseudo53 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem54 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo53, i64* nonnull %"@i_key51", i64* nonnull %"@i_val52", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %21)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %22)
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
