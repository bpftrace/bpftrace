; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }
%stack_t = type { i64, i32, i32 }

@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !31 {
entry:
  %"@y_key" = alloca i64, align 8
  %stack_args4 = alloca %stack_t, align 8
  %"@x_key" = alloca i64, align 8
  %stack_args = alloca %stack_t, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %get_stackid = call i64 inttoptr (i64 27 to i64 (i8*, i64, i64)*)(i8* %0, i64 %pseudo, i64 256)
  %1 = bitcast %stack_t* %stack_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 0
  store i64 %get_stackid, i64* %2, align 8
  %3 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 1
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %4 = trunc i64 %get_pid_tgid to i32
  store i32 %4, i32* %3, align 4
  %5 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 2
  store i32 0, i32* %5, align 4
  %6 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  store i64 0, i64* %"@x_key", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %stack_t*, i64)*)(i64 %pseudo1, i64* %"@x_key", %stack_t* %stack_args, i64 0)
  %7 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %get_stackid3 = call i64 inttoptr (i64 27 to i64 (i8*, i64, i64)*)(i8* %0, i64 %pseudo2, i64 256)
  %8 = bitcast %stack_t* %stack_args4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %9 = getelementptr %stack_t, %stack_t* %stack_args4, i64 0, i32 0
  store i64 %get_stackid3, i64* %9, align 8
  %10 = getelementptr %stack_t, %stack_t* %stack_args4, i64 0, i32 1
  %get_pid_tgid5 = call i64 inttoptr (i64 14 to i64 ()*)()
  %11 = trunc i64 %get_pid_tgid5 to i32
  store i32 %11, i32* %10, align 4
  %12 = getelementptr %stack_t, %stack_t* %stack_args4, i64 0, i32 2
  store i32 0, i32* %12, align 4
  %13 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i64 0, i64* %"@y_key", align 8
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem7 = call i64 inttoptr (i64 2 to i64 (i64, i64*, %stack_t*, i64)*)(i64 %pseudo6, i64* %"@y_key", %stack_t* %stack_args4, i64 0)
  %14 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }

!llvm.dbg.cu = !{!27}
!llvm.module.flags = !{!30}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 131072, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 4096, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !20, size: 64, offset: 192)
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!21 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 128, elements: !23)
!22 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!23 = !{!24}
!24 = !DISubrange(count: 16, lowerBound: 0)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!27 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !28, globals: !29)
!28 = !{}
!29 = !{!0, !25}
!30 = !{i32 2, !"Debug Info Version", i32 3}
!31 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !2, file: !2, type: !32, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !27, retainedNodes: !35)
!32 = !DISubroutineType(types: !33)
!33 = !{!18, !34}
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!35 = !{!36, !37}
!36 = !DILocalVariable(name: "var0", scope: !31, file: !2, type: !18)
!37 = !DILocalVariable(name: "var1", arg: 1, scope: !31, file: !2, type: !34)
