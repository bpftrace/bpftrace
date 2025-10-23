; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.163" = type { ptr, ptr }
%"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_func_1_args" = type { i32, ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_ = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_internal_repr_t.163" zeroinitializer, section ".maps", !dbg !26
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !40
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !44

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @uprobe__tmp_bpftrace_test_dwarf_data_func_1_1(ptr %0) #0 section "s_uprobe__tmp_bpftrace_test_dwarf_data_func_1_1" !dbg !50 {
entry:
  %"@_key" = alloca i64, align 8
  %args = alloca %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_func_1_args", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %args)
  %1 = call ptr @llvm.preserve.static.offset(ptr %0)
  %2 = getelementptr i8, ptr %1, i64 112
  %arg0 = load volatile i64, ptr %2, align 8
  %3 = trunc i64 %arg0 to i32
  %4 = getelementptr %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_func_1_args", ptr %args, i64 0, i32 0
  store i32 %3, ptr %4, align 4
  %5 = call ptr @llvm.preserve.static.offset(ptr %0)
  %6 = getelementptr i8, ptr %5, i64 104
  %arg1 = load volatile i64, ptr %6, align 8
  %7 = getelementptr %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_func_1_args", ptr %args, i64 0, i32 1
  store i64 %arg1, ptr %7, align 8
  %8 = call ptr @llvm.preserve.static.offset(ptr %0)
  %9 = getelementptr i8, ptr %8, i64 96
  %arg2 = load volatile i64, ptr %9, align 8
  %10 = getelementptr %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_func_1_args", ptr %args, i64 0, i32 2
  store i64 %arg2, ptr %10, align 8
  %11 = call ptr @llvm.preserve.static.offset(ptr %0)
  %12 = getelementptr i8, ptr %11, i64 88
  %arg3 = load volatile i64, ptr %12, align 8
  %13 = getelementptr %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_func_1_args", ptr %args, i64 0, i32 3
  store i64 %arg3, ptr %13, align 8
  %14 = call ptr @llvm.preserve.static.offset(ptr %0)
  %15 = getelementptr i8, ptr %14, i64 72
  %arg4 = load volatile i64, ptr %15, align 8
  %16 = getelementptr %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_func_1_args", ptr %args, i64 0, i32 4
  store i64 %arg4, ptr %16, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key")
  store i64 0, ptr %"@_key", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_, ptr %"@_key", ptr %args, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }

!llvm.dbg.cu = !{!46}
!llvm.module.flags = !{!48, !49}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !10)
!10 = !{!11, !17, !18, !21}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 1, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !19, size: 64, offset: 128)
!19 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !20, size: 64)
!20 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !22, size: 64, offset: 192)
!22 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !23, size: 64)
!23 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 288, elements: !24)
!24 = !{!25}
!25 = !DISubrange(count: 36, lowerBound: 0)
!26 = !DIGlobalVariableExpression(var: !27, expr: !DIExpression())
!27 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !28, isLocal: false, isDefinition: true)
!28 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !29)
!29 = !{!30, !35}
!30 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !31, size: 64)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !33)
!33 = !{!34}
!34 = !DISubrange(count: 27, lowerBound: 0)
!35 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !36, size: 64, offset: 64)
!36 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !37, size: 64)
!37 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !38)
!38 = !{!39}
!39 = !DISubrange(count: 262144, lowerBound: 0)
!40 = !DIGlobalVariableExpression(var: !41, expr: !DIExpression())
!41 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !42, isLocal: false, isDefinition: true)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !43, size: 64, elements: !15)
!43 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 64, elements: !15)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!46 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !47)
!47 = !{!0, !7, !26, !40, !44}
!48 = !{i32 2, !"Debug Info Version", i32 3}
!49 = !{i32 7, !"uwtable", i32 0}
!50 = distinct !DISubprogram(name: "uprobe__tmp_bpftrace_test_dwarf_data_func_1_1", linkageName: "uprobe__tmp_bpftrace_test_dwarf_data_func_1_1", scope: !2, file: !2, type: !51, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !46, retainedNodes: !54)
!51 = !DISubroutineType(types: !52)
!52 = !{!20, !53}
!53 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!54 = !{!55}
!55 = !DILocalVariable(name: "ctx", arg: 1, scope: !50, file: !2, type: !53)
