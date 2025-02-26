; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @interval_s_1_1(ptr %0) section "s_interval_s_1_1" !dbg !33 {
entry:
  %"@_newval" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@_key" = alloca i64, align 8
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
  %2 = icmp sle i64 %1, 100
  %true_cond = icmp ne i1 %2, false
  br i1 %true_cond, label %while_body, label %while_end, !llvm.loop !40

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
  %6 = icmp sle i64 %5, 100
  %true_cond4 = icmp ne i1 %6, false
  br i1 %true_cond4, label %while_body2, label %while_end3, !llvm.loop !40

while_body2:                                      ; preds = %while_cond1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key")
  store i64 0, ptr %"@_key", align 8
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

!llvm.dbg.cu = !{!30}
!llvm.module.flags = !{!32}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !12, !15}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !13, size: 64, offset: 128)
!13 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !14, size: 64)
!14 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!15 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !13, size: 64, offset: 192)
!16 = !DIGlobalVariableExpression(var: !17, expr: !DIExpression())
!17 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !19)
!19 = !{!20, !25}
!20 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !21, size: 64)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !23)
!23 = !{!24}
!24 = !DISubrange(count: 27, lowerBound: 0)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !26, size: 64, offset: 64)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 262144, lowerBound: 0)
!30 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !31)
!31 = !{!0, !16}
!32 = !{i32 2, !"Debug Info Version", i32 3}
!33 = distinct !DISubprogram(name: "interval_s_1_1", linkageName: "interval_s_1_1", scope: !2, file: !2, type: !34, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !30, retainedNodes: !38)
!34 = !DISubroutineType(types: !35)
!35 = !{!14, !36}
!36 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !37, size: 64)
!37 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!38 = !{!39}
!39 = !DILocalVariable(name: "ctx", arg: 1, scope: !33, file: !2, type: !36)
!40 = distinct !{!40, !41}
!41 = !{!"llvm.loop.unroll.disable"}
