; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"tracepoint:syscalls:sys_enter_openat"(i8* %0) section "s_tracepoint:syscalls:sys_enter_openat_1" !dbg !4 {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %get_cgroup_id = call i64 inttoptr (i64 80 to i64 ()*)()
  %1 = icmp eq i64 %get_cgroup_id, 4294967297
  %2 = zext i1 %1 to i64
  %predcond = icmp eq i64 %2, 0
  br i1 %predcond, label %pred_false, label %pred_true

pred_false:                                       ; preds = %entry
  ret i64 1

pred_true:                                        ; preds = %entry
  %get_cgroup_id1 = call i64 inttoptr (i64 80 to i64 ()*)()
  %3 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i64 0, i64* %"@x_key", align 8
  %4 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i64 %get_cgroup_id1, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@x_key", i64* %"@x_val", i64 0)
  %5 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  ret i64 1
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
!4 = distinct !DISubprogram(name: "tracepoint_syscalls_sys_enter_openat", linkageName: "tracepoint_syscalls_sys_enter_openat", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !10)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !8}
!7 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!10 = !{!11, !12}
!11 = !DILocalVariable(name: "var0", scope: !4, file: !1, type: !7)
!12 = !DILocalVariable(name: "var1", arg: 1, scope: !4, file: !1, type: !8)
