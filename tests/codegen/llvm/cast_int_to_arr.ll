; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !4 {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %"$a" = alloca i64, align 8
  %1 = bitcast i64* %"$a" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$a", align 8
  %2 = alloca i64, align 8
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %3 = lshr i64 %get_pid_tgid, 32
  %4 = bitcast i64* %2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i64 %3, i64* %2, align 8
  %5 = bitcast i64* %2 to [8 x i8]*
  %6 = ptrtoint [8 x i8]* %5 to i64
  store i64 %6, i64* %"$a", align 8
  %7 = load i64, i64* %"$a", align 8
  %8 = inttoptr i64 %7 to [8 x i8]*
  %9 = getelementptr [8 x i8], [8 x i8]* %8, i32 0, i64 0
  %10 = load volatile i8, i8* %9, align 1
  %11 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i64 0, i64* %"@_key", align 8
  %12 = zext i8 %10 to i64
  %13 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i64 %12, i64* %"@_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@_key", i64* %"@_val", i64 0)
  %14 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  %15 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
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
