; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.163" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_ = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_internal_repr_t.163" zeroinitializer, section ".maps", !dbg !23
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !37
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !41

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @interval_s_1_1(ptr %0) #0 section "s_interval_s_1_1" !dbg !47 {
entry:
  %"@_newval" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@_key" = alloca i8, align 1
  %"$j" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$j")
  store i64 0, ptr %"$j", align 8
  %"$i" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$i")
  store i64 0, ptr %"$i", align 8
  store i64 1, ptr %"$i", align 8
  br label %while_cond

while_cond:                                       ; preds = %while_end3, %entry
  %1 = load i64, ptr %"$i", align 8
  %2 = icmp ule i64 %1, 100
  %true_cond = icmp ne i1 %2, false
  br i1 %true_cond, label %while_body, label %while_end, !llvm.loop !52

while_body:                                       ; preds = %while_cond
  store i64 0, ptr %"$j", align 8
  %3 = load i64, ptr %"$i", align 8
  %4 = add i64 %3, 1
  store i64 %4, ptr %"$i", align 8
  br label %while_cond1

while_end:                                        ; preds = %while_cond
  ret i64 0

while_cond1:                                      ; preds = %lookup_merge, %while_body
  %5 = load i64, ptr %"$j", align 8
  %6 = icmp ule i64 %5, 100
  %true_cond4 = icmp ne i1 %6, false
  br i1 %true_cond4, label %while_body2, label %while_end3, !llvm.loop !52

while_body2:                                      ; preds = %while_cond1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key")
  store i8 0, ptr %"@_key", align 1
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_, ptr %"@_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

while_end3:                                       ; preds = %while_cond1
  br label %while_cond

lookup_success:                                   ; preds = %while_body2
  %7 = load i64, ptr %lookup_elem, align 8
  store i64 %7, ptr %lookup_elem_val, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %while_body2
  store i64 0, ptr %lookup_elem_val, align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %8 = load i64, ptr %lookup_elem_val, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_newval")
  %9 = add i64 %8, 1
  store i64 %9, ptr %"@_newval", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_, ptr %"@_key", ptr %"@_newval", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_newval")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key")
  %10 = load i64, ptr %"$j", align 8
  %11 = add i64 %10, 1
  store i64 %11, ptr %"$j", align 8
  br label %while_cond1
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!43}
!llvm.module.flags = !{!45, !46}

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
!10 = !{!11, !17, !18, !20}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 1, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !19, size: 64, offset: 128)
!19 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!20 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !21, size: 64, offset: 192)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!23 = !DIGlobalVariableExpression(var: !24, expr: !DIExpression())
!24 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !25, isLocal: false, isDefinition: true)
!25 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !26)
!26 = !{!27, !32}
!27 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !28, size: 64)
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!29 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !30)
!30 = !{!31}
!31 = !DISubrange(count: 27, lowerBound: 0)
!32 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !33, size: 64, offset: 64)
!33 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !34, size: 64)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !35)
!35 = !{!36}
!36 = !DISubrange(count: 262144, lowerBound: 0)
!37 = !DIGlobalVariableExpression(var: !38, expr: !DIExpression())
!38 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !39, isLocal: false, isDefinition: true)
!39 = !DICompositeType(tag: DW_TAG_array_type, baseType: !40, size: 64, elements: !15)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 64, elements: !15)
!41 = !DIGlobalVariableExpression(var: !42, expr: !DIExpression())
!42 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !22, isLocal: false, isDefinition: true)
!43 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !44)
!44 = !{!0, !7, !23, !37, !41}
!45 = !{i32 2, !"Debug Info Version", i32 3}
!46 = !{i32 7, !"uwtable", i32 0}
!47 = distinct !DISubprogram(name: "interval_s_1_1", linkageName: "interval_s_1_1", scope: !2, file: !2, type: !48, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !43, retainedNodes: !50)
!48 = !DISubroutineType(types: !49)
!49 = !{!22, !19}
!50 = !{!51}
!51 = !DILocalVariable(name: "ctx", arg: 1, scope: !47, file: !2, type: !19)
!52 = distinct !{!52, !53}
!53 = !{!"llvm.loop.unroll.disable"}
