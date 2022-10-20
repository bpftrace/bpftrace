; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !3 {
entry:
  %ctx_stack = alloca [16 x i8], align 1
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca [16 x i8], align 1
  %1 = bitcast [16 x i8]* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = getelementptr [16 x i8], [16 x i8]* %"@x_key", i64 0, i64 0
  %3 = bitcast i8* %2 to i64*
  store i64 10, i64* %3, align 8
  %4 = getelementptr [16 x i8], [16 x i8]* %"@x_key", i64 0, i64 8
  %5 = bitcast i8* %4 to i64*
  store i64 10, i64* %5, align 8
  %6 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  store i64 1, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, [16 x i8]*, i64*, i64)*)(i64 %pseudo, [16 x i8]* %"@x_key", i64* %"@x_val", i64 0)
  %7 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  %8 = bitcast [16 x i8]* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast [16 x i8]* %ctx_stack to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %10 = bitcast [16 x i8]* %ctx_stack to i64*
  store i64 8, i64* %10, align 8
  %11 = getelementptr i64, i64* %10, i64 1
  store i64 10, i64* %11, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %12 = bitcast i64* %10 to i8*
  %for_each_map_elem = call i64 inttoptr (i64 164 to i64 (i64, i64 (i8*, i8*, i8*, i8*)*, i8*, i64)*)(i64 %pseudo1, i64 (i8*, i8*, i8*, i8*)* @delete_filtered_cb, i8* %12, i64 0)
  %13 = bitcast [16 x i8]* %ctx_stack to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: noinline
define internal i64 @delete_filtered_cb(i8* %0, i8* %1, i8* %2, i8* %3) #2 section ".text" !dbg !12 {
param_check:
  %4 = icmp eq i8* %3, null
  %5 = icmp eq i8* %2, null
  %6 = or i1 %5, %4
  %7 = icmp eq i8* %1, null
  %8 = icmp eq i8* %0, null
  %9 = or i1 %8, %7
  %10 = or i1 %9, %6
  %11 = zext i1 %10 to i32
  %12 = icmp eq i32 %11, 1
  br i1 %12, label %null_param, label %entry

null_param:                                       ; preds = %param_check
  ret i64 0

entry:                                            ; preds = %param_check
  %13 = bitcast i8* %3 to i64*
  %14 = getelementptr i64, i64* %13, i32 0
  %ctx_key_offset = load i64, i64* %14, align 8
  %15 = bitcast i8* %3 to i64*
  %16 = getelementptr i64, i64* %15, i32 1
  %17 = getelementptr i8, i8* %1, i64 %ctx_key_offset
  %18 = bitcast i8* %17 to i64*
  %load_key_value = load i64, i64* %18, align 8
  %load_ctx_value = load i64, i64* %16, align 8
  %cmp_key_vs_ctx = icmp eq i64 %load_key_value, %load_ctx_value
  br i1 %cmp_key_vs_ctx, label %eq, label %retzero

retzero:                                          ; preds = %eq, %entry
  ret i64 0

eq:                                               ; preds = %entry
  %delete_call = call i64 inttoptr (i64 3 to i64 (i8*, i8*)*)(i8* %0, i8* %1)
  br label %retzero
}

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { noinline }

!llvm.dbg.cu = !{!0}

!0 = distinct !DICompileUnit(language: DW_LANG_C, file: !1, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !2)
!1 = !DIFile(filename: "bpftrace", directory: ".")
!2 = !{}
!3 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !1, file: !1, type: !4, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !9)
!4 = !DISubroutineType(types: !5)
!5 = !{!6, !7}
!6 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!7 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !8, size: 64)
!8 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!9 = !{!10, !11}
!10 = !DILocalVariable(name: "var0", scope: !3, file: !1, type: !6)
!11 = !DILocalVariable(name: "var1", arg: 1, scope: !3, file: !1, type: !7)
!12 = distinct !DISubprogram(name: "delete_filtered_cb", linkageName: "delete_filtered_cb", scope: !1, file: !1, type: !13, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !15)
!13 = !DISubroutineType(types: !14)
!14 = !{!6, !7, !7, !7, !7}
!15 = !{!16, !17, !18, !19, !20}
!16 = !DILocalVariable(name: "var0", scope: !12, file: !1, type: !6)
!17 = !DILocalVariable(name: "var1", arg: 1, scope: !12, file: !1, type: !7)
!18 = !DILocalVariable(name: "var2", arg: 2, scope: !12, file: !1, type: !7)
!19 = !DILocalVariable(name: "var3", arg: 3, scope: !12, file: !1, type: !7)
!20 = !DILocalVariable(name: "var4", arg: 4, scope: !12, file: !1, type: !7)
