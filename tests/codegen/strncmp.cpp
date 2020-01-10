#include "../mocks.h"
#include "common.h"

using ::testing::_;
using ::testing::Return;

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, strncmp)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace,
       "t:file:filename /str(args->filename) == comm/ { @=1 }",
#if LLVM_VERSION_MAJOR > 6
       R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:file:filename"(i8*) local_unnamed_addr section "s_tracepoint:file:filename_1" {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %strcmp.char_r = alloca i8, align 1
  %strcmp.char_l = alloca i8, align 1
  %"struct _tracepoint_file_filename.filename" = alloca i64, align 8
  %str = alloca [64 x i8], align 1
  %comm = alloca [16 x i8], align 1
  %1 = getelementptr inbounds [16 x i8], [16 x i8]* %comm, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %1, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 (i8*, i64)*)([16 x i8]* nonnull %comm, i64 16)
  %2 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %2, i8 0, i64 64, i1 false)
  %3 = add i8* %0, i64 8
  %4 = bitcast i64* %"struct _tracepoint_file_filename.filename" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %"struct _tracepoint_file_filename.filename", i64 8, i8* %3)
  %5 = load i64, i64* %"struct _tracepoint_file_filename.filename", align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  %probe_read_str = call i64 inttoptr (i64 45 to i64 (i8*, i64, i8*)*)([64 x i8]* nonnull %str, i64 64, i64 %5)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %strcmp.char_l)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %strcmp.char_r)
  %probe_read1 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* nonnull %str)
  %6 = load i8, i8* %strcmp.char_l, align 1
  %probe_read2 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* nonnull %comm)
  %7 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp = icmp eq i8 %6, %7
  br i1 %strcmp.cmp, label %strcmp.loop_null_cmp, label %pred_false.critedge

pred_false.critedge:                              ; preds = %entry
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_l)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_r)
  br label %pred_false

pred_false:                                       ; preds = %strcmp.false, %pred_false.critedge
  ret i64 0

pred_true.critedge:                               ; preds = %strcmp.loop87, %strcmp.loop_null_cmp, %strcmp.loop_null_cmp4, %strcmp.loop_null_cmp10, %strcmp.loop_null_cmp16, %strcmp.loop_null_cmp22, %strcmp.loop_null_cmp28, %strcmp.loop_null_cmp34, %strcmp.loop_null_cmp40, %strcmp.loop_null_cmp46, %strcmp.loop_null_cmp52, %strcmp.loop_null_cmp58, %strcmp.loop_null_cmp64, %strcmp.loop_null_cmp70, %strcmp.loop_null_cmp76, %strcmp.loop_null_cmp82, %strcmp.loop_null_cmp88
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_l)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_r)
  %8 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %8)
  store i64 0, i64* %"@_key", align 8
  %9 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 1, i64* %"@_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %8)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
  ret i64 0

strcmp.false:                                     ; preds = %strcmp.loop87, %strcmp.loop81, %strcmp.loop75, %strcmp.loop69, %strcmp.loop63, %strcmp.loop57, %strcmp.loop51, %strcmp.loop45, %strcmp.loop39, %strcmp.loop33, %strcmp.loop27, %strcmp.loop21, %strcmp.loop15, %strcmp.loop9, %strcmp.loop3, %strcmp.loop
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_l)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_r)
  br label %pred_false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %10 = add [64 x i8]* %str, i64 1
  %probe_read5 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %10)
  %11 = load i8, i8* %strcmp.char_l, align 1
  %12 = add [16 x i8]* %comm, i64 1
  %probe_read6 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %12)
  %13 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp7 = icmp eq i8 %11, %13
  br i1 %strcmp.cmp7, label %strcmp.loop_null_cmp4, label %strcmp.false

strcmp.loop_null_cmp:                             ; preds = %entry
  %strcmp.cmp_null = icmp eq i8 %6, 0
  br i1 %strcmp.cmp_null, label %pred_true.critedge, label %strcmp.loop

strcmp.loop3:                                     ; preds = %strcmp.loop_null_cmp4
  %14 = add [64 x i8]* %str, i64 2
  %probe_read11 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %14)
  %15 = load i8, i8* %strcmp.char_l, align 1
  %16 = add [16 x i8]* %comm, i64 2
  %probe_read12 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %16)
  %17 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp13 = icmp eq i8 %15, %17
  br i1 %strcmp.cmp13, label %strcmp.loop_null_cmp10, label %strcmp.false

strcmp.loop_null_cmp4:                            ; preds = %strcmp.loop
  %strcmp.cmp_null8 = icmp eq i8 %11, 0
  br i1 %strcmp.cmp_null8, label %pred_true.critedge, label %strcmp.loop3

strcmp.loop9:                                     ; preds = %strcmp.loop_null_cmp10
  %18 = add [64 x i8]* %str, i64 3
  %probe_read17 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %18)
  %19 = load i8, i8* %strcmp.char_l, align 1
  %20 = add [16 x i8]* %comm, i64 3
  %probe_read18 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %20)
  %21 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp19 = icmp eq i8 %19, %21
  br i1 %strcmp.cmp19, label %strcmp.loop_null_cmp16, label %strcmp.false

strcmp.loop_null_cmp10:                           ; preds = %strcmp.loop3
  %strcmp.cmp_null14 = icmp eq i8 %15, 0
  br i1 %strcmp.cmp_null14, label %pred_true.critedge, label %strcmp.loop9

strcmp.loop15:                                    ; preds = %strcmp.loop_null_cmp16
  %22 = add [64 x i8]* %str, i64 4
  %probe_read23 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %22)
  %23 = load i8, i8* %strcmp.char_l, align 1
  %24 = add [16 x i8]* %comm, i64 4
  %probe_read24 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %24)
  %25 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp25 = icmp eq i8 %23, %25
  br i1 %strcmp.cmp25, label %strcmp.loop_null_cmp22, label %strcmp.false

strcmp.loop_null_cmp16:                           ; preds = %strcmp.loop9
  %strcmp.cmp_null20 = icmp eq i8 %19, 0
  br i1 %strcmp.cmp_null20, label %pred_true.critedge, label %strcmp.loop15

strcmp.loop21:                                    ; preds = %strcmp.loop_null_cmp22
  %26 = add [64 x i8]* %str, i64 5
  %probe_read29 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %26)
  %27 = load i8, i8* %strcmp.char_l, align 1
  %28 = add [16 x i8]* %comm, i64 5
  %probe_read30 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %28)
  %29 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp31 = icmp eq i8 %27, %29
  br i1 %strcmp.cmp31, label %strcmp.loop_null_cmp28, label %strcmp.false

strcmp.loop_null_cmp22:                           ; preds = %strcmp.loop15
  %strcmp.cmp_null26 = icmp eq i8 %23, 0
  br i1 %strcmp.cmp_null26, label %pred_true.critedge, label %strcmp.loop21

strcmp.loop27:                                    ; preds = %strcmp.loop_null_cmp28
  %30 = add [64 x i8]* %str, i64 6
  %probe_read35 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %30)
  %31 = load i8, i8* %strcmp.char_l, align 1
  %32 = add [16 x i8]* %comm, i64 6
  %probe_read36 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %32)
  %33 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp37 = icmp eq i8 %31, %33
  br i1 %strcmp.cmp37, label %strcmp.loop_null_cmp34, label %strcmp.false

strcmp.loop_null_cmp28:                           ; preds = %strcmp.loop21
  %strcmp.cmp_null32 = icmp eq i8 %27, 0
  br i1 %strcmp.cmp_null32, label %pred_true.critedge, label %strcmp.loop27

strcmp.loop33:                                    ; preds = %strcmp.loop_null_cmp34
  %34 = add [64 x i8]* %str, i64 7
  %probe_read41 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %34)
  %35 = load i8, i8* %strcmp.char_l, align 1
  %36 = add [16 x i8]* %comm, i64 7
  %probe_read42 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %36)
  %37 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp43 = icmp eq i8 %35, %37
  br i1 %strcmp.cmp43, label %strcmp.loop_null_cmp40, label %strcmp.false

strcmp.loop_null_cmp34:                           ; preds = %strcmp.loop27
  %strcmp.cmp_null38 = icmp eq i8 %31, 0
  br i1 %strcmp.cmp_null38, label %pred_true.critedge, label %strcmp.loop33

strcmp.loop39:                                    ; preds = %strcmp.loop_null_cmp40
  %38 = add [64 x i8]* %str, i64 8
  %probe_read47 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %38)
  %39 = load i8, i8* %strcmp.char_l, align 1
  %40 = add [16 x i8]* %comm, i64 8
  %probe_read48 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %40)
  %41 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp49 = icmp eq i8 %39, %41
  br i1 %strcmp.cmp49, label %strcmp.loop_null_cmp46, label %strcmp.false

strcmp.loop_null_cmp40:                           ; preds = %strcmp.loop33
  %strcmp.cmp_null44 = icmp eq i8 %35, 0
  br i1 %strcmp.cmp_null44, label %pred_true.critedge, label %strcmp.loop39

strcmp.loop45:                                    ; preds = %strcmp.loop_null_cmp46
  %42 = add [64 x i8]* %str, i64 9
  %probe_read53 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %42)
  %43 = load i8, i8* %strcmp.char_l, align 1
  %44 = add [16 x i8]* %comm, i64 9
  %probe_read54 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %44)
  %45 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp55 = icmp eq i8 %43, %45
  br i1 %strcmp.cmp55, label %strcmp.loop_null_cmp52, label %strcmp.false

strcmp.loop_null_cmp46:                           ; preds = %strcmp.loop39
  %strcmp.cmp_null50 = icmp eq i8 %39, 0
  br i1 %strcmp.cmp_null50, label %pred_true.critedge, label %strcmp.loop45

strcmp.loop51:                                    ; preds = %strcmp.loop_null_cmp52
  %46 = add [64 x i8]* %str, i64 10
  %probe_read59 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %46)
  %47 = load i8, i8* %strcmp.char_l, align 1
  %48 = add [16 x i8]* %comm, i64 10
  %probe_read60 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %48)
  %49 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp61 = icmp eq i8 %47, %49
  br i1 %strcmp.cmp61, label %strcmp.loop_null_cmp58, label %strcmp.false

strcmp.loop_null_cmp52:                           ; preds = %strcmp.loop45
  %strcmp.cmp_null56 = icmp eq i8 %43, 0
  br i1 %strcmp.cmp_null56, label %pred_true.critedge, label %strcmp.loop51

strcmp.loop57:                                    ; preds = %strcmp.loop_null_cmp58
  %50 = add [64 x i8]* %str, i64 11
  %probe_read65 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %50)
  %51 = load i8, i8* %strcmp.char_l, align 1
  %52 = add [16 x i8]* %comm, i64 11
  %probe_read66 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %52)
  %53 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp67 = icmp eq i8 %51, %53
  br i1 %strcmp.cmp67, label %strcmp.loop_null_cmp64, label %strcmp.false

strcmp.loop_null_cmp58:                           ; preds = %strcmp.loop51
  %strcmp.cmp_null62 = icmp eq i8 %47, 0
  br i1 %strcmp.cmp_null62, label %pred_true.critedge, label %strcmp.loop57

strcmp.loop63:                                    ; preds = %strcmp.loop_null_cmp64
  %54 = add [64 x i8]* %str, i64 12
  %probe_read71 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %54)
  %55 = load i8, i8* %strcmp.char_l, align 1
  %56 = add [16 x i8]* %comm, i64 12
  %probe_read72 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %56)
  %57 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp73 = icmp eq i8 %55, %57
  br i1 %strcmp.cmp73, label %strcmp.loop_null_cmp70, label %strcmp.false

strcmp.loop_null_cmp64:                           ; preds = %strcmp.loop57
  %strcmp.cmp_null68 = icmp eq i8 %51, 0
  br i1 %strcmp.cmp_null68, label %pred_true.critedge, label %strcmp.loop63

strcmp.loop69:                                    ; preds = %strcmp.loop_null_cmp70
  %58 = add [64 x i8]* %str, i64 13
  %probe_read77 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %58)
  %59 = load i8, i8* %strcmp.char_l, align 1
  %60 = add [16 x i8]* %comm, i64 13
  %probe_read78 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %60)
  %61 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp79 = icmp eq i8 %59, %61
  br i1 %strcmp.cmp79, label %strcmp.loop_null_cmp76, label %strcmp.false

strcmp.loop_null_cmp70:                           ; preds = %strcmp.loop63
  %strcmp.cmp_null74 = icmp eq i8 %55, 0
  br i1 %strcmp.cmp_null74, label %pred_true.critedge, label %strcmp.loop69

strcmp.loop75:                                    ; preds = %strcmp.loop_null_cmp76
  %62 = add [64 x i8]* %str, i64 14
  %probe_read83 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %62)
  %63 = load i8, i8* %strcmp.char_l, align 1
  %64 = add [16 x i8]* %comm, i64 14
  %probe_read84 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %64)
  %65 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp85 = icmp eq i8 %63, %65
  br i1 %strcmp.cmp85, label %strcmp.loop_null_cmp82, label %strcmp.false

strcmp.loop_null_cmp76:                           ; preds = %strcmp.loop69
  %strcmp.cmp_null80 = icmp eq i8 %59, 0
  br i1 %strcmp.cmp_null80, label %pred_true.critedge, label %strcmp.loop75

strcmp.loop81:                                    ; preds = %strcmp.loop_null_cmp82
  %66 = add [64 x i8]* %str, i64 15
  %probe_read89 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %66)
  %67 = load i8, i8* %strcmp.char_l, align 1
  %68 = add [16 x i8]* %comm, i64 15
  %probe_read90 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %68)
  %69 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp91 = icmp eq i8 %67, %69
  br i1 %strcmp.cmp91, label %strcmp.loop_null_cmp88, label %strcmp.false

strcmp.loop_null_cmp82:                           ; preds = %strcmp.loop75
  %strcmp.cmp_null86 = icmp eq i8 %63, 0
  br i1 %strcmp.cmp_null86, label %pred_true.critedge, label %strcmp.loop81

strcmp.loop87:                                    ; preds = %strcmp.loop_null_cmp88
  %70 = add [64 x i8]* %str, i64 16
  %probe_read95 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %70)
  %71 = load i8, i8* %strcmp.char_l, align 1
  %72 = add [16 x i8]* %comm, i64 16
  %probe_read96 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %72)
  %73 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp97 = icmp eq i8 %71, %73
  br i1 %strcmp.cmp97, label %pred_true.critedge, label %strcmp.false

strcmp.loop_null_cmp88:                           ; preds = %strcmp.loop81
  %strcmp.cmp_null92 = icmp eq i8 %67, 0
  br i1 %strcmp.cmp_null92, label %pred_true.critedge, label %strcmp.loop87
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#else
       R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:file:filename"(i8*) local_unnamed_addr section "s_tracepoint:file:filename_1" {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %strcmp.char_r = alloca i8, align 1
  %strcmp.char_l = alloca i8, align 1
  %"struct _tracepoint_file_filename.filename" = alloca i64, align 8
  %str = alloca [64 x i8], align 1
  %comm = alloca [16 x i8], align 1
  %1 = getelementptr inbounds [16 x i8], [16 x i8]* %comm, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.memset.p0i8.i64(i8* nonnull %1, i8 0, i64 16, i32 1, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 (i8*, i64)*)([16 x i8]* nonnull %comm, i64 16)
  %2 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.memset.p0i8.i64(i8* nonnull %2, i8 0, i64 64, i32 1, i1 false)
  %3 = add i8* %0, i64 8
  %4 = bitcast i64* %"struct _tracepoint_file_filename.filename" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %"struct _tracepoint_file_filename.filename", i64 8, i8* %3)
  %5 = load i64, i64* %"struct _tracepoint_file_filename.filename", align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  %probe_read_str = call i64 inttoptr (i64 45 to i64 (i8*, i64, i8*)*)([64 x i8]* nonnull %str, i64 64, i64 %5)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %strcmp.char_l)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %strcmp.char_r)
  %probe_read1 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* nonnull %str)
  %6 = load i8, i8* %strcmp.char_l, align 1
  %probe_read2 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* nonnull %comm)
  %7 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp = icmp eq i8 %6, %7
  br i1 %strcmp.cmp, label %strcmp.loop_null_cmp, label %pred_false.critedge

pred_false.critedge:                              ; preds = %entry
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_l)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_r)
  br label %pred_false

pred_false:                                       ; preds = %strcmp.false, %pred_false.critedge
  ret i64 0

pred_true.critedge:                               ; preds = %strcmp.loop87, %strcmp.loop_null_cmp, %strcmp.loop_null_cmp4, %strcmp.loop_null_cmp10, %strcmp.loop_null_cmp16, %strcmp.loop_null_cmp22, %strcmp.loop_null_cmp28, %strcmp.loop_null_cmp34, %strcmp.loop_null_cmp40, %strcmp.loop_null_cmp46, %strcmp.loop_null_cmp52, %strcmp.loop_null_cmp58, %strcmp.loop_null_cmp64, %strcmp.loop_null_cmp70, %strcmp.loop_null_cmp76, %strcmp.loop_null_cmp82, %strcmp.loop_null_cmp88
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_l)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_r)
  %8 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %8)
  store i64 0, i64* %"@_key", align 8
  %9 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 1, i64* %"@_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %8)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
  ret i64 0

strcmp.false:                                     ; preds = %strcmp.loop87, %strcmp.loop81, %strcmp.loop75, %strcmp.loop69, %strcmp.loop63, %strcmp.loop57, %strcmp.loop51, %strcmp.loop45, %strcmp.loop39, %strcmp.loop33, %strcmp.loop27, %strcmp.loop21, %strcmp.loop15, %strcmp.loop9, %strcmp.loop3, %strcmp.loop
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_l)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_r)
  br label %pred_false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %10 = add [64 x i8]* %str, i64 1
  %probe_read5 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %10)
  %11 = load i8, i8* %strcmp.char_l, align 1
  %12 = add [16 x i8]* %comm, i64 1
  %probe_read6 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %12)
  %13 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp7 = icmp eq i8 %11, %13
  br i1 %strcmp.cmp7, label %strcmp.loop_null_cmp4, label %strcmp.false

strcmp.loop_null_cmp:                             ; preds = %entry
  %strcmp.cmp_null = icmp eq i8 %6, 0
  br i1 %strcmp.cmp_null, label %pred_true.critedge, label %strcmp.loop

strcmp.loop3:                                     ; preds = %strcmp.loop_null_cmp4
  %14 = add [64 x i8]* %str, i64 2
  %probe_read11 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %14)
  %15 = load i8, i8* %strcmp.char_l, align 1
  %16 = add [16 x i8]* %comm, i64 2
  %probe_read12 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %16)
  %17 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp13 = icmp eq i8 %15, %17
  br i1 %strcmp.cmp13, label %strcmp.loop_null_cmp10, label %strcmp.false

strcmp.loop_null_cmp4:                            ; preds = %strcmp.loop
  %strcmp.cmp_null8 = icmp eq i8 %11, 0
  br i1 %strcmp.cmp_null8, label %pred_true.critedge, label %strcmp.loop3

strcmp.loop9:                                     ; preds = %strcmp.loop_null_cmp10
  %18 = add [64 x i8]* %str, i64 3
  %probe_read17 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %18)
  %19 = load i8, i8* %strcmp.char_l, align 1
  %20 = add [16 x i8]* %comm, i64 3
  %probe_read18 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %20)
  %21 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp19 = icmp eq i8 %19, %21
  br i1 %strcmp.cmp19, label %strcmp.loop_null_cmp16, label %strcmp.false

strcmp.loop_null_cmp10:                           ; preds = %strcmp.loop3
  %strcmp.cmp_null14 = icmp eq i8 %15, 0
  br i1 %strcmp.cmp_null14, label %pred_true.critedge, label %strcmp.loop9

strcmp.loop15:                                    ; preds = %strcmp.loop_null_cmp16
  %22 = add [64 x i8]* %str, i64 4
  %probe_read23 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %22)
  %23 = load i8, i8* %strcmp.char_l, align 1
  %24 = add [16 x i8]* %comm, i64 4
  %probe_read24 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %24)
  %25 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp25 = icmp eq i8 %23, %25
  br i1 %strcmp.cmp25, label %strcmp.loop_null_cmp22, label %strcmp.false

strcmp.loop_null_cmp16:                           ; preds = %strcmp.loop9
  %strcmp.cmp_null20 = icmp eq i8 %19, 0
  br i1 %strcmp.cmp_null20, label %pred_true.critedge, label %strcmp.loop15

strcmp.loop21:                                    ; preds = %strcmp.loop_null_cmp22
  %26 = add [64 x i8]* %str, i64 5
  %probe_read29 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %26)
  %27 = load i8, i8* %strcmp.char_l, align 1
  %28 = add [16 x i8]* %comm, i64 5
  %probe_read30 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %28)
  %29 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp31 = icmp eq i8 %27, %29
  br i1 %strcmp.cmp31, label %strcmp.loop_null_cmp28, label %strcmp.false

strcmp.loop_null_cmp22:                           ; preds = %strcmp.loop15
  %strcmp.cmp_null26 = icmp eq i8 %23, 0
  br i1 %strcmp.cmp_null26, label %pred_true.critedge, label %strcmp.loop21

strcmp.loop27:                                    ; preds = %strcmp.loop_null_cmp28
  %30 = add [64 x i8]* %str, i64 6
  %probe_read35 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %30)
  %31 = load i8, i8* %strcmp.char_l, align 1
  %32 = add [16 x i8]* %comm, i64 6
  %probe_read36 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %32)
  %33 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp37 = icmp eq i8 %31, %33
  br i1 %strcmp.cmp37, label %strcmp.loop_null_cmp34, label %strcmp.false

strcmp.loop_null_cmp28:                           ; preds = %strcmp.loop21
  %strcmp.cmp_null32 = icmp eq i8 %27, 0
  br i1 %strcmp.cmp_null32, label %pred_true.critedge, label %strcmp.loop27

strcmp.loop33:                                    ; preds = %strcmp.loop_null_cmp34
  %34 = add [64 x i8]* %str, i64 7
  %probe_read41 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %34)
  %35 = load i8, i8* %strcmp.char_l, align 1
  %36 = add [16 x i8]* %comm, i64 7
  %probe_read42 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %36)
  %37 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp43 = icmp eq i8 %35, %37
  br i1 %strcmp.cmp43, label %strcmp.loop_null_cmp40, label %strcmp.false

strcmp.loop_null_cmp34:                           ; preds = %strcmp.loop27
  %strcmp.cmp_null38 = icmp eq i8 %31, 0
  br i1 %strcmp.cmp_null38, label %pred_true.critedge, label %strcmp.loop33

strcmp.loop39:                                    ; preds = %strcmp.loop_null_cmp40
  %38 = add [64 x i8]* %str, i64 8
  %probe_read47 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %38)
  %39 = load i8, i8* %strcmp.char_l, align 1
  %40 = add [16 x i8]* %comm, i64 8
  %probe_read48 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %40)
  %41 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp49 = icmp eq i8 %39, %41
  br i1 %strcmp.cmp49, label %strcmp.loop_null_cmp46, label %strcmp.false

strcmp.loop_null_cmp40:                           ; preds = %strcmp.loop33
  %strcmp.cmp_null44 = icmp eq i8 %35, 0
  br i1 %strcmp.cmp_null44, label %pred_true.critedge, label %strcmp.loop39

strcmp.loop45:                                    ; preds = %strcmp.loop_null_cmp46
  %42 = add [64 x i8]* %str, i64 9
  %probe_read53 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %42)
  %43 = load i8, i8* %strcmp.char_l, align 1
  %44 = add [16 x i8]* %comm, i64 9
  %probe_read54 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %44)
  %45 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp55 = icmp eq i8 %43, %45
  br i1 %strcmp.cmp55, label %strcmp.loop_null_cmp52, label %strcmp.false

strcmp.loop_null_cmp46:                           ; preds = %strcmp.loop39
  %strcmp.cmp_null50 = icmp eq i8 %39, 0
  br i1 %strcmp.cmp_null50, label %pred_true.critedge, label %strcmp.loop45

strcmp.loop51:                                    ; preds = %strcmp.loop_null_cmp52
  %46 = add [64 x i8]* %str, i64 10
  %probe_read59 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %46)
  %47 = load i8, i8* %strcmp.char_l, align 1
  %48 = add [16 x i8]* %comm, i64 10
  %probe_read60 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %48)
  %49 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp61 = icmp eq i8 %47, %49
  br i1 %strcmp.cmp61, label %strcmp.loop_null_cmp58, label %strcmp.false

strcmp.loop_null_cmp52:                           ; preds = %strcmp.loop45
  %strcmp.cmp_null56 = icmp eq i8 %43, 0
  br i1 %strcmp.cmp_null56, label %pred_true.critedge, label %strcmp.loop51

strcmp.loop57:                                    ; preds = %strcmp.loop_null_cmp58
  %50 = add [64 x i8]* %str, i64 11
  %probe_read65 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %50)
  %51 = load i8, i8* %strcmp.char_l, align 1
  %52 = add [16 x i8]* %comm, i64 11
  %probe_read66 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %52)
  %53 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp67 = icmp eq i8 %51, %53
  br i1 %strcmp.cmp67, label %strcmp.loop_null_cmp64, label %strcmp.false

strcmp.loop_null_cmp58:                           ; preds = %strcmp.loop51
  %strcmp.cmp_null62 = icmp eq i8 %47, 0
  br i1 %strcmp.cmp_null62, label %pred_true.critedge, label %strcmp.loop57

strcmp.loop63:                                    ; preds = %strcmp.loop_null_cmp64
  %54 = add [64 x i8]* %str, i64 12
  %probe_read71 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %54)
  %55 = load i8, i8* %strcmp.char_l, align 1
  %56 = add [16 x i8]* %comm, i64 12
  %probe_read72 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %56)
  %57 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp73 = icmp eq i8 %55, %57
  br i1 %strcmp.cmp73, label %strcmp.loop_null_cmp70, label %strcmp.false

strcmp.loop_null_cmp64:                           ; preds = %strcmp.loop57
  %strcmp.cmp_null68 = icmp eq i8 %51, 0
  br i1 %strcmp.cmp_null68, label %pred_true.critedge, label %strcmp.loop63

strcmp.loop69:                                    ; preds = %strcmp.loop_null_cmp70
  %58 = add [64 x i8]* %str, i64 13
  %probe_read77 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %58)
  %59 = load i8, i8* %strcmp.char_l, align 1
  %60 = add [16 x i8]* %comm, i64 13
  %probe_read78 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %60)
  %61 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp79 = icmp eq i8 %59, %61
  br i1 %strcmp.cmp79, label %strcmp.loop_null_cmp76, label %strcmp.false

strcmp.loop_null_cmp70:                           ; preds = %strcmp.loop63
  %strcmp.cmp_null74 = icmp eq i8 %55, 0
  br i1 %strcmp.cmp_null74, label %pred_true.critedge, label %strcmp.loop69

strcmp.loop75:                                    ; preds = %strcmp.loop_null_cmp76
  %62 = add [64 x i8]* %str, i64 14
  %probe_read83 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %62)
  %63 = load i8, i8* %strcmp.char_l, align 1
  %64 = add [16 x i8]* %comm, i64 14
  %probe_read84 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %64)
  %65 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp85 = icmp eq i8 %63, %65
  br i1 %strcmp.cmp85, label %strcmp.loop_null_cmp82, label %strcmp.false

strcmp.loop_null_cmp76:                           ; preds = %strcmp.loop69
  %strcmp.cmp_null80 = icmp eq i8 %59, 0
  br i1 %strcmp.cmp_null80, label %pred_true.critedge, label %strcmp.loop75

strcmp.loop81:                                    ; preds = %strcmp.loop_null_cmp82
  %66 = add [64 x i8]* %str, i64 15
  %probe_read89 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %66)
  %67 = load i8, i8* %strcmp.char_l, align 1
  %68 = add [16 x i8]* %comm, i64 15
  %probe_read90 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %68)
  %69 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp91 = icmp eq i8 %67, %69
  br i1 %strcmp.cmp91, label %strcmp.loop_null_cmp88, label %strcmp.false

strcmp.loop_null_cmp82:                           ; preds = %strcmp.loop75
  %strcmp.cmp_null86 = icmp eq i8 %63, 0
  br i1 %strcmp.cmp_null86, label %pred_true.critedge, label %strcmp.loop81

strcmp.loop87:                                    ; preds = %strcmp.loop_null_cmp88
  %70 = add [64 x i8]* %str, i64 16
  %probe_read95 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %70)
  %71 = load i8, i8* %strcmp.char_l, align 1
  %72 = add [16 x i8]* %comm, i64 16
  %probe_read96 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %72)
  %73 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp97 = icmp eq i8 %71, %73
  br i1 %strcmp.cmp97, label %pred_true.critedge, label %strcmp.false

strcmp.loop_null_cmp88:                           ; preds = %strcmp.loop81
  %strcmp.cmp_null92 = icmp eq i8 %67, 0
  br i1 %strcmp.cmp_null92, label %pred_true.critedge, label %strcmp.loop87
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#endif
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
