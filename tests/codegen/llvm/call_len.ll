; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN(i8* %0) section "s_BEGIN_1" !dbg !4 {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 1, i64* %"@x_key", align 8
  %2 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 1, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@x_key", i64* %"@x_val", i64 0)
  %3 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_2" !dbg !13 {
entry:
  %"$s" = alloca i64, align 8
  %1 = bitcast i64* %"$s" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$s", align 8
  %len = alloca i64, align 8
  %2 = bitcast i64* %len to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %len, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %3 = bitcast i64* %len to i8*
  %for_each_map_elem = call i64 inttoptr (i64 164 to i64 (i64, i64 (i8*, i8*, i8*, i8*)*, i8*, i64)*)(i64 %pseudo, i64 (i8*, i8*, i8*, i8*)* @map_len_cb, i8* %3, i64 0)
  %4 = load i64, i64* %len, align 8
  %5 = bitcast i64* %len to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  store i64 %4, i64* %"$s", align 8
  ret i64 0
}

define internal i64 @map_len_cb(i8* %0, i8* %1, i8* %2, i8* %3) section ".text" !dbg !17 {
  %5 = bitcast i8* %3 to i64*
  %6 = load i64, i64* %5, align 8
  %7 = add i64 %6, 1
  store i64 %7, i64* %5, align 8
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3}

!0 = distinct !DICompileUnit(language: DW_LANG_C, file: !1, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !2)
!1 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!2 = !{}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "BEGIN", linkageName: "BEGIN", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !10)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !8}
!7 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!10 = !{!11, !12}
!11 = !DILocalVariable(name: "var0", scope: !4, file: !1, type: !7)
!12 = !DILocalVariable(name: "var1", arg: 1, scope: !4, file: !1, type: !8)
!13 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !14)
!14 = !{!15, !16}
!15 = !DILocalVariable(name: "var0", scope: !13, file: !1, type: !7)
!16 = !DILocalVariable(name: "var1", arg: 1, scope: !13, file: !1, type: !8)
!17 = distinct !DISubprogram(name: "map_len_cb", linkageName: "map_len_cb", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !18)
!18 = !{!19, !20}
!19 = !DILocalVariable(name: "var0", scope: !17, file: !1, type: !7)
!20 = !DILocalVariable(name: "var1", arg: 1, scope: !17, file: !1, type: !8)
