; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29
@__bt__var_buf = dso_local externally_initialized global [1 x [2 x [8 x i8]]] zeroinitializer, section ".data.var_buf", !dbg !31

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !44 {
entry:
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)() #4
  %1 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %1
  %2 = getelementptr [1 x [2 x [8 x i8]]], ptr @__bt__var_buf, i64 0, i64 %cpu.id.bounded2, i64 1, i64 0
  store i64 0, ptr %2, align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #4
  %3 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %3
  %4 = getelementptr [1 x [2 x [8 x i8]]], ptr @__bt__var_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  store i64 0, ptr %4, align 8
  %5 = alloca i8, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %5)
  call void @llvm.memset.p0.i64(ptr align 1 %5, i8 0, i64 1, i1 false)
  %6 = call ptr @llvm.preserve.static.offset(ptr %0)
  %7 = getelementptr i8, ptr %6, i64 112
  %arg0 = load volatile i64, ptr %7, align 8
  %8 = icmp ugt i64 %arg0, 0
  %cond = icmp ne i1 %8, false
  br i1 %cond, label %true, label %false

true:                                             ; preds = %entry
  store i64 1, ptr %4, align 8
  store i8 1, ptr %5, align 1
  br label %done

false:                                            ; preds = %entry
  store i64 2, ptr %2, align 8
  store i8 1, ptr %5, align 1
  br label %done

done:                                             ; preds = %false, %true
  call void @llvm.lifetime.end.p0(i64 -1, ptr %5)
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #3

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #4 = { memory(none) }

!llvm.dbg.cu = !{!40}
!llvm.module.flags = !{!42, !43}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !10)
!10 = !{!11, !17}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 27, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !18, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !20)
!20 = !{!21}
!21 = !DISubrange(count: 262144, lowerBound: 0)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !25, size: 64, elements: !27)
!25 = !DICompositeType(tag: DW_TAG_array_type, baseType: !26, size: 64, elements: !27)
!26 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!27 = !{!28}
!28 = !DISubrange(count: 1, lowerBound: 0)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!31 = !DIGlobalVariableExpression(var: !32, expr: !DIExpression())
!32 = distinct !DIGlobalVariable(name: "__bt__var_buf", linkageName: "global", scope: !2, file: !2, type: !33, isLocal: false, isDefinition: true)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !34, size: 128, elements: !27)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !35, size: 128, elements: !38)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 64, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 8, lowerBound: 0)
!38 = !{!39}
!39 = !DISubrange(count: 2, lowerBound: 0)
!40 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !41)
!41 = !{!0, !7, !22, !29, !31}
!42 = !{i32 2, !"Debug Info Version", i32 3}
!43 = !{i32 7, !"uwtable", i32 0}
!44 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !45, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !40, retainedNodes: !48)
!45 = !DISubroutineType(types: !46)
!46 = !{!26, !47}
!47 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!48 = !{!49}
!49 = !DILocalVariable(name: "ctx", arg: 1, scope: !44, file: !2, type: !47)
