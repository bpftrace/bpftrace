; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !4 {
entry:
  %initial_value11 = alloca i64, align 8
  %lookup_elem_val8 = alloca i64, align 8
  %"@x_key2" = alloca i64, align 8
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@x_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo, i64* %"@x_key")
  %2 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %3 = load i64, i64* %cast, align 8
  %4 = add i64 %3, 1
  store i64 %4, i64* %cast, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  %5 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 1, i64* %initial_value, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* %"@x_key", i64* %initial_value, i64 1)
  %6 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %7 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  %8 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast i64* %"@x_key2" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i64 1, i64* %"@x_key2", align 8
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %10 = lshr i64 %get_pid_tgid, 32
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem4 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo3, i64* %"@x_key2")
  %11 = bitcast i64* %lookup_elem_val8 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  %map_lookup_cond9 = icmp ne i8* %lookup_elem4, null
  br i1 %map_lookup_cond9, label %lookup_success5, label %lookup_failure6

lookup_success5:                                  ; preds = %lookup_merge
  %cast10 = bitcast i8* %lookup_elem4 to i64*
  %12 = load i64, i64* %cast10, align 8
  %13 = add i64 %12, %10
  store i64 %13, i64* %cast10, align 8
  br label %lookup_merge7

lookup_failure6:                                  ; preds = %lookup_merge
  %14 = bitcast i64* %initial_value11 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i64 %10, i64* %initial_value11, align 8
  %pseudo12 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem13 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo12, i64* %"@x_key2", i64* %initial_value11, i64 1)
  %15 = bitcast i64* %initial_value11 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  br label %lookup_merge7

lookup_merge7:                                    ; preds = %lookup_failure6, %lookup_success5
  %16 = bitcast i64* %lookup_elem_val8 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast i64* %"@x_key2" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
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
