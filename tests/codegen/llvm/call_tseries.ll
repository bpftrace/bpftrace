; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.163" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.164" = type { ptr, ptr }
%t_series_val = type { i64, i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_a = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_x = dso_local global %"struct map_internal_repr_t.163" zeroinitializer, section ".maps", !dbg !23
@ringbuf = dso_local global %"struct map_internal_repr_t.164" zeroinitializer, section ".maps", !dbg !49
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !63
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !67

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !73 {
entry:
  %lookup_elem_val = alloca i8, align 1
  %"@a_key1" = alloca i64, align 8
  %ts_struct = alloca %t_series_val, align 8
  %key_exists = alloca i8, align 1
  %"@x_key" = alloca [16 x i8], align 1
  %ts_struct_ptr = alloca ptr, align 8
  %"@a_val" = alloca i8, align 1
  %"@a_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_key")
  store i64 0, ptr %"@a_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_val")
  store i8 4, ptr %"@a_val", align 1
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_a, ptr %"@a_key", ptr %"@a_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ts_struct_ptr)
  %get_ns = call i64 inttoptr (i64 125 to ptr)()
  %1 = add i64 %get_ns, 0
  %2 = udiv i64 %1, 1000000000
  %3 = urem i64 %2, 20
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  %4 = getelementptr [16 x i8], ptr %"@x_key", i64 0, i64 0
  store i64 0, ptr %4, align 8
  %5 = getelementptr [16 x i8], ptr %"@x_key", i64 0, i64 8
  store i64 %3, ptr %5, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key_exists)
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key")
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  store ptr %lookup_elem, ptr %ts_struct_ptr, align 8
  store i8 1, ptr %key_exists, align 1
  br label %maybe_clear

lookup_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ts_struct)
  %6 = getelementptr %t_series_val, ptr %ts_struct, i64 0, i32 0
  store i64 0, ptr %6, align 8
  %7 = getelementptr %t_series_val, ptr %ts_struct, i64 0, i32 1
  store i64 0, ptr %7, align 8
  %8 = getelementptr %t_series_val, ptr %ts_struct, i64 0, i32 2
  store i64 %2, ptr %8, align 8
  store ptr %ts_struct, ptr %ts_struct_ptr, align 8
  store i8 0, ptr %key_exists, align 1
  br label %maybe_clear

maybe_clear:                                      ; preds = %lookup_failure, %lookup_success
  %9 = load ptr, ptr %ts_struct_ptr, align 8
  %10 = getelementptr %t_series_val, ptr %9, i64 0, i32 0
  %11 = getelementptr %t_series_val, ptr %9, i64 0, i32 1
  %12 = getelementptr %t_series_val, ptr %9, i64 0, i32 2
  br label %merge

merge:                                            ; preds = %maybe_clear
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_key1")
  store i64 0, ptr %"@a_key1", align 8
  %lookup_elem2 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_a, ptr %"@a_key1")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond5 = icmp ne ptr %lookup_elem2, null
  br i1 %map_lookup_cond5, label %lookup_success3, label %lookup_failure4

update:                                           ; preds = %lookup_merge
  %update_elem6 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %9, i64 0)
  br label %exit

exit:                                             ; preds = %update, %lookup_merge
  call void @llvm.lifetime.end.p0(i64 -1, ptr %ts_struct)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %ts_struct_ptr)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key_exists)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  ret i64 0

lookup_success3:                                  ; preds = %merge
  %13 = load i8, ptr %lookup_elem2, align 1
  store i8 %13, ptr %lookup_elem_val, align 1
  br label %lookup_merge

lookup_failure4:                                  ; preds = %merge
  store i8 0, ptr %lookup_elem_val, align 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure4, %lookup_success3
  %14 = load i8, ptr %lookup_elem_val, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_key1")
  %15 = zext i8 %14 to i64
  store i64 %15, ptr %10, align 8
  store i64 %1, ptr %11, align 8
  store i64 %2, ptr %12, align 8
  %16 = load i8, ptr %key_exists, align 1
  %needs_update = icmp ne i8 %16, 1
  br i1 %needs_update, label %update, label %exit
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!69}
!llvm.module.flags = !{!71, !72}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_a", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
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
!22 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!23 = !DIGlobalVariableExpression(var: !24, expr: !DIExpression())
!24 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !25, isLocal: false, isDefinition: true)
!25 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !26)
!26 = !{!27, !32, !37, !42}
!27 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !28, size: 64)
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!29 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 160, elements: !30)
!30 = !{!31}
!31 = !DISubrange(count: 5, lowerBound: 0)
!32 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !33, size: 64, offset: 64)
!33 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !34, size: 64)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 131072, elements: !35)
!35 = !{!36}
!36 = !DISubrange(count: 4096, lowerBound: 0)
!37 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !38, size: 64, offset: 128)
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !39, size: 64)
!39 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 128, elements: !40)
!40 = !{!41}
!41 = !DISubrange(count: 16, lowerBound: 0)
!42 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !43, size: 64, offset: 192)
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !44, size: 64)
!44 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 192, elements: !45)
!45 = !{!46, !47, !48}
!46 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !20, size: 64)
!47 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !20, size: 64, offset: 64)
!48 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !20, size: 64, offset: 128)
!49 = !DIGlobalVariableExpression(var: !50, expr: !DIExpression())
!50 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !51, isLocal: false, isDefinition: true)
!51 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !52)
!52 = !{!53, !58}
!53 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !54, size: 64)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !56)
!56 = !{!57}
!57 = !DISubrange(count: 27, lowerBound: 0)
!58 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !59, size: 64, offset: 64)
!59 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !60, size: 64)
!60 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !61)
!61 = !{!62}
!62 = !DISubrange(count: 262144, lowerBound: 0)
!63 = !DIGlobalVariableExpression(var: !64, expr: !DIExpression())
!64 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !65, isLocal: false, isDefinition: true)
!65 = !DICompositeType(tag: DW_TAG_array_type, baseType: !66, size: 64, elements: !15)
!66 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 64, elements: !15)
!67 = !DIGlobalVariableExpression(var: !68, expr: !DIExpression())
!68 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!69 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !70)
!70 = !{!0, !7, !23, !49, !63, !67}
!71 = !{i32 2, !"Debug Info Version", i32 3}
!72 = !{i32 7, !"uwtable", i32 0}
!73 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !74, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !69, retainedNodes: !76)
!74 = !DISubroutineType(types: !75)
!75 = !{!20, !22}
!76 = !{!77}
!77 = !DILocalVariable(name: "ctx", arg: 1, scope: !73, file: !2, type: !22)
