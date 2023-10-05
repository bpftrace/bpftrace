; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%inet_t = type { i64, [16 x i8] }

@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !29 {
entry:
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %inet = alloca %inet_t, align 8
  %1 = bitcast %inet_t* %inet to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = getelementptr %inet_t, %inet_t* %inet, i64 0, i32 0
  store i64 2, i64* %2, align 8
  %3 = getelementptr %inet_t, %inet_t* %inet, i32 0, i32 1
  %4 = bitcast [16 x i8]* %3 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %4, i8 0, i64 16, i1 false)
  %5 = bitcast [16 x i8]* %3 to i32*
  store i32 -1, i32* %5, align 4
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, %inet_t*)*)(i64 %pseudo, %inet_t* %inet)
  %6 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %7 = load i64, i64* %cast, align 8
  %8 = add i64 %7, 1
  store i64 %8, i64* %cast, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  %9 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i64 1, i64* %initial_value, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, %inet_t*, i64*, i64)*)(i64 %pseudo1, %inet_t* %inet, i64* %initial_value, i64 1)
  %10 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %11 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast %inet_t* %inet to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!25}
!llvm.module.flags = !{!28}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !22}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 160, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 5, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 131072, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 4096, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DICompositeType(tag: DW_TAG_array_type, baseType: !19, size: 192, elements: !20)
!19 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!20 = !{!21}
!21 = !DISubrange(count: 24, lowerBound: 0)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !23, size: 64, offset: 192)
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!25 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !26, globals: !27)
!26 = !{}
!27 = !{!0}
!28 = !{i32 2, !"Debug Info Version", i32 3}
!29 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !2, file: !2, type: !30, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !25, retainedNodes: !33)
!30 = !DISubroutineType(types: !31)
!31 = !{!24, !32}
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!33 = !{!34, !35}
!34 = !DILocalVariable(name: "var0", scope: !29, file: !2, type: !24)
!35 = !DILocalVariable(name: "var1", arg: 1, scope: !29, file: !2, type: !32)
