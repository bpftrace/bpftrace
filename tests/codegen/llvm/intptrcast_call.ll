; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kretprobe:f"(i8* %0) section "s_kretprobe:f_1" !dbg !4 {
entry:
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %deref = alloca i8, align 1
  %"@_key" = alloca i64, align 8
  %1 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@_key", align 8
  %2 = bitcast i8* %0 to i64*
  %3 = getelementptr i64, i64* %2, i64 4
  %reg_bp = load volatile i64, i64* %3, align 8
  %4 = sub i64 %reg_bp, 1
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %deref)
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i8*, i32, i64)*)(i8* %deref, i32 1, i64 %4)
  %5 = load i8, i8* %deref, align 1
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %deref)
  %6 = sext i8 %5 to i64
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo, i64* %"@_key")
  %7 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %8 = load i64, i64* %cast, align 8
  %9 = add i64 %8, %6
  store i64 %9, i64* %cast, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  %10 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 %6, i64* %initial_value, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* %"@_key", i64* %initial_value, i64 1)
  %11 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %12 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  %13 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
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
!4 = distinct !DISubprogram(name: "kretprobe_f", linkageName: "kretprobe_f", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !10)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !8}
!7 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!10 = !{!11, !12}
!11 = !DILocalVariable(name: "var0", scope: !4, file: !1, type: !7)
!12 = !DILocalVariable(name: "var1", arg: 1, scope: !4, file: !1, type: !8)
