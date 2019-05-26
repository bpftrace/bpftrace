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
  %"@x_newval67" = alloca i64, align 8
  %"@x_key59" = alloca i64, align 8
  %"@x_key51" = alloca i64, align 8
  %"@x_newval48" = alloca i64, align 8
  %"@x_key40" = alloca i64, align 8
  %"@x_key32" = alloca i64, align 8
  %"@x_newval29" = alloca i64, align 8
  %"@x_key21" = alloca i64, align 8
  %"@x_key13" = alloca i64, align 8
  %"@x_newval" = alloca i64, align 8
  %"@x_key3" = alloca i64, align 8
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
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  %4 = bitcast i64* %"@x_key3" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 0, i64* %"@x_key3", align 8
  %pseudo4 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem5 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo4, i64* nonnull %"@x_key3")
  %map_lookup_cond10 = icmp eq i8* %lookup_elem5, null
  br i1 %map_lookup_cond10, label %lookup_merge8, label %lookup_success6

lookup_success6:                                  ; preds = %entry
  %5 = load i64, i8* %lookup_elem5, align 8
  %phitmp = add i64 %5, 1
  br label %lookup_merge8

lookup_merge8:                                    ; preds = %entry, %lookup_success6
  %lookup_elem_val9.0 = phi i64 [ %phitmp, %lookup_success6 ], [ 1, %entry ]
  %6 = bitcast i64* %"@x_newval" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 %lookup_elem_val9.0, i64* %"@x_newval", align 8
  %pseudo11 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem12 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo11, i64* nonnull %"@x_key3", i64* nonnull %"@x_newval", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  %7 = bitcast i64* %"@x_key13" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  store i64 0, i64* %"@x_key13", align 8
  %pseudo14 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem15 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo14, i64* nonnull %"@x_key13")
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  %8 = bitcast i64* %"@x_key21" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %8)
  store i64 0, i64* %"@x_key21", align 8
  %pseudo22 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem23 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo22, i64* nonnull %"@x_key21")
  %map_lookup_cond28 = icmp eq i8* %lookup_elem23, null
  br i1 %map_lookup_cond28, label %lookup_merge26, label %lookup_success24

lookup_success24:                                 ; preds = %lookup_merge8
  %9 = load i64, i8* %lookup_elem23, align 8
  %phitmp70 = add i64 %9, 1
  br label %lookup_merge26

lookup_merge26:                                   ; preds = %lookup_merge8, %lookup_success24
  %lookup_elem_val27.0 = phi i64 [ %phitmp70, %lookup_success24 ], [ 1, %lookup_merge8 ]
  %10 = bitcast i64* %"@x_newval29" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %10)
  store i64 %lookup_elem_val27.0, i64* %"@x_newval29", align 8
  %pseudo30 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem31 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo30, i64* nonnull %"@x_key21", i64* nonnull %"@x_newval29", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %8)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %10)
  %11 = bitcast i64* %"@x_key32" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %11)
  store i64 0, i64* %"@x_key32", align 8
  %pseudo33 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem34 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo33, i64* nonnull %"@x_key32")
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %11)
  %12 = bitcast i64* %"@x_key40" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %12)
  store i64 0, i64* %"@x_key40", align 8
  %pseudo41 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem42 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo41, i64* nonnull %"@x_key40")
  %map_lookup_cond47 = icmp eq i8* %lookup_elem42, null
  br i1 %map_lookup_cond47, label %lookup_merge45, label %lookup_success43

lookup_success43:                                 ; preds = %lookup_merge26
  %13 = load i64, i8* %lookup_elem42, align 8
  %phitmp71 = add i64 %13, -1
  br label %lookup_merge45

lookup_merge45:                                   ; preds = %lookup_merge26, %lookup_success43
  %lookup_elem_val46.0 = phi i64 [ %phitmp71, %lookup_success43 ], [ -1, %lookup_merge26 ]
  %14 = bitcast i64* %"@x_newval48" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %14)
  store i64 %lookup_elem_val46.0, i64* %"@x_newval48", align 8
  %pseudo49 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem50 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo49, i64* nonnull %"@x_key40", i64* nonnull %"@x_newval48", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %12)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %14)
  %15 = bitcast i64* %"@x_key51" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %15)
  store i64 0, i64* %"@x_key51", align 8
  %pseudo52 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem53 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo52, i64* nonnull %"@x_key51")
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %15)
  %16 = bitcast i64* %"@x_key59" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %16)
  store i64 0, i64* %"@x_key59", align 8
  %pseudo60 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem61 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo60, i64* nonnull %"@x_key59")
  %map_lookup_cond66 = icmp eq i8* %lookup_elem61, null
  br i1 %map_lookup_cond66, label %lookup_merge64, label %lookup_success62

lookup_success62:                                 ; preds = %lookup_merge45
  %17 = load i64, i8* %lookup_elem61, align 8
  %phitmp72 = add i64 %17, -1
  br label %lookup_merge64

lookup_merge64:                                   ; preds = %lookup_merge45, %lookup_success62
  %lookup_elem_val65.0 = phi i64 [ %phitmp72, %lookup_success62 ], [ -1, %lookup_merge45 ]
  %18 = bitcast i64* %"@x_newval67" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %18)
  store i64 %lookup_elem_val65.0, i64* %"@x_newval67", align 8
  %pseudo68 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem69 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo68, i64* nonnull %"@x_key59", i64* nonnull %"@x_newval67", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %18)
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
