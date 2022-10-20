; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%ctx_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !4 {
entry:
  %ctx_stack = alloca %ctx_t, align 8
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
  %9 = bitcast %ctx_t* %ctx_stack to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %10 = getelementptr %ctx_t, %ctx_t* %ctx_stack, i64 0, i32 0
  store i64 8, i64* %10, align 8
  %11 = getelementptr %ctx_t, %ctx_t* %ctx_stack, i64 0, i32 1
  store i64 10, i64* %11, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %12 = bitcast %ctx_t* %ctx_stack to i8*
  %for_each_map_elem = call i64 inttoptr (i64 164 to i64 (i64, i64 (i8*, i8*, i8*, i8*)*, i8*, i64)*)(i64 %pseudo1, i64 (i8*, i8*, i8*, i8*)* @delete_filtered_cb, i8* %12, i64 0)
  %13 = bitcast %ctx_t* %ctx_stack to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

define internal i64 @delete_filtered_cb(i8* %0, i8* %1, i8* %2, i8* %3) section ".text" !dbg !13 {
param_check:
  %4 = icmp eq i8* %3, null
  %5 = icmp eq i8* %2, null
  %6 = or i1 %5, %4
  %7 = icmp eq i8* %1, null
  %8 = icmp eq i8* %0, null
  %9 = or i1 %8, %7
  %10 = or i1 %9, %6
  %11 = icmp eq i1 %10, true
  br i1 %11, label %null_param, label %entry

null_param:                                       ; preds = %param_check
  ret i64 0

entry:                                            ; preds = %param_check
  %12 = bitcast i8* %3 to %ctx_t*
  %13 = getelementptr %ctx_t, %ctx_t* %12, i64 0, i32 0
  %ctx_key_offset = load i64, i64* %13, align 8
  %14 = bitcast i8* %3 to %ctx_t*
  %15 = getelementptr %ctx_t, %ctx_t* %14, i64 0, i32 1
  %context_key_value = load i64, i64* %15, align 8
  %16 = getelementptr i8, i8* %1, i64 %ctx_key_offset
  %17 = bitcast i8* %16 to i64*
  %key_value = load i64, i64* %17, align 8
  %cmp_key_vs_ctx = icmp eq i64 %key_value, %context_key_value
  br i1 %cmp_key_vs_ctx, label %eq, label %retzero

retzero:                                          ; preds = %eq, %entry
  ret i64 0

eq:                                               ; preds = %entry
  %delete_call = call i64 inttoptr (i64 3 to i64 (i8*, i8*)*)(i8* %0, i8* %1)
  br label %retzero
}

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3}

!0 = distinct !DICompileUnit(language: DW_LANG_C, file: !1, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !2)
!1 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!2 = !{}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !10)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !8}
!7 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!10 = !{!11, !12}
!11 = !DILocalVariable(name: "var0", scope: !4, file: !1, type: !7)
!12 = !DILocalVariable(name: "var1", arg: 1, scope: !4, file: !1, type: !8)
!13 = distinct !DISubprogram(name: "delete_filtered_cb", linkageName: "delete_filtered_cb", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !14)
!14 = !{!15, !16}
!15 = !DILocalVariable(name: "var0", scope: !13, file: !1, type: !7)
!16 = !DILocalVariable(name: "var1", arg: 1, scope: !13, file: !1, type: !8)
