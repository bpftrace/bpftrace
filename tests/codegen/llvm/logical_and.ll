; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !4 {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %"&&_result" = alloca i64, align 8
  %1 = bitcast i64* %"&&_result" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %2 = lshr i64 %get_pid_tgid, 32
  %3 = icmp ne i64 %2, 1234
  %4 = zext i1 %3 to i64
  %lhs_true_cond = icmp ne i64 %4, 0
  br i1 %lhs_true_cond, label %"&&_lhs_true", label %"&&_false"

"&&_lhs_true":                                    ; preds = %entry
  %get_pid_tgid1 = call i64 inttoptr (i64 14 to i64 ()*)()
  %5 = lshr i64 %get_pid_tgid1, 32
  %6 = icmp ne i64 %5, 1235
  %7 = zext i1 %6 to i64
  %rhs_true_cond = icmp ne i64 %7, 0
  br i1 %rhs_true_cond, label %"&&_true", label %"&&_false"

"&&_true":                                        ; preds = %"&&_lhs_true"
  store i64 1, i64* %"&&_result", align 8
  br label %"&&_merge"

"&&_false":                                       ; preds = %"&&_lhs_true", %entry
  store i64 0, i64* %"&&_result", align 8
  br label %"&&_merge"

"&&_merge":                                       ; preds = %"&&_false", %"&&_true"
  %8 = load i64, i64* %"&&_result", align 8
  %9 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i64 0, i64* %"@x_key", align 8
  %10 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 %8, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@x_key", i64* %"@x_val", i64 0)
  %11 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

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
