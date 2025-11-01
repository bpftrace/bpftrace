; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.616" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.617" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_y = dso_local global %"struct map_internal_repr_t.616" zeroinitializer, section ".maps", !dbg !27
@ringbuf = dso_local global %"struct map_internal_repr_t.617" zeroinitializer, section ".maps", !dbg !36
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !50
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !52
@__bt__num_cpus = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !58

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !64 {
entry:
  %"@x_key11" = alloca i8, align 1
  %"@x_key9" = alloca i8, align 1
  %initial_value7 = alloca i64, align 8
  %lookup_elem_val5 = alloca i64, align 8
  %"@y_key" = alloca [16 x i8], align 1
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key" = alloca i8, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i8 1, ptr %"@x_key", align 1
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %1 = load i64, ptr %lookup_elem, align 8
  %2 = add i64 %1, 1
  store i64 %2, ptr %lookup_elem, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %initial_value)
  store i64 1, ptr %initial_value, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %initial_value, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %initial_value)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  %log2 = call i64 @log2(i64 10, i64 0)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  %3 = getelementptr [16 x i8], ptr %"@y_key", i64 0, i64 0
  store i64 0, ptr %3, align 8
  %4 = getelementptr [16 x i8], ptr %"@y_key", i64 0, i64 8
  store i64 %log2, ptr %4, align 8
  %lookup_elem1 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_y, ptr %"@y_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val5)
  %map_lookup_cond6 = icmp ne ptr %lookup_elem1, null
  br i1 %map_lookup_cond6, label %lookup_success2, label %lookup_failure3

lookup_success2:                                  ; preds = %lookup_merge
  %5 = load i64, ptr %lookup_elem1, align 8
  %6 = add i64 %5, 1
  store i64 %6, ptr %lookup_elem1, align 8
  br label %lookup_merge4

lookup_failure3:                                  ; preds = %lookup_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %initial_value7)
  store i64 1, ptr %initial_value7, align 8
  %update_elem8 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %initial_value7, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %initial_value7)
  br label %lookup_merge4

lookup_merge4:                                    ; preds = %lookup_failure3, %lookup_success2
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val5)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key9")
  store i8 1, ptr %"@x_key9", align 1
  %lookup_elem10 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key9")
  %has_key = icmp ne ptr %lookup_elem10, null
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key9")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key11")
  store i8 1, ptr %"@x_key11", align 1
  %delete_elem = call i64 inttoptr (i64 3 to ptr)(ptr @AT_x, ptr %"@x_key11")
  %delete_ret = icmp eq i64 %delete_elem, 0
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key11")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: alwaysinline nounwind
define internal i64 @log2(i64 %0, i64 %1) #2 section "helpers" {
entry:
  %2 = alloca i64, align 8
  %3 = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %3)
  store i64 %0, ptr %3, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %2)
  store i64 %1, ptr %2, align 8
  %4 = load i64, ptr %3, align 8
  %5 = icmp slt i64 %4, 0
  br i1 %5, label %hist.is_less_than_zero, label %hist.is_not_less_than_zero

hist.is_less_than_zero:                           ; preds = %entry
  ret i64 0

hist.is_not_less_than_zero:                       ; preds = %entry
  %6 = load i64, ptr %2, align 8
  %7 = shl i64 1, %6
  %8 = sub i64 %7, 1
  %9 = icmp ule i64 %4, %8
  br i1 %9, label %hist.is_zero, label %hist.is_not_zero

hist.is_zero:                                     ; preds = %hist.is_not_less_than_zero
  %10 = add i64 %4, 1
  ret i64 %10

hist.is_not_zero:                                 ; preds = %hist.is_not_less_than_zero
  %11 = icmp sge i64 %4, 4294967296
  %12 = zext i1 %11 to i64
  %13 = shl i64 %12, 5
  %14 = lshr i64 %4, %13
  %15 = add i64 0, %13
  %16 = icmp sge i64 %14, 65536
  %17 = zext i1 %16 to i64
  %18 = shl i64 %17, 4
  %19 = lshr i64 %14, %18
  %20 = add i64 %15, %18
  %21 = icmp sge i64 %19, 256
  %22 = zext i1 %21 to i64
  %23 = shl i64 %22, 3
  %24 = lshr i64 %19, %23
  %25 = add i64 %20, %23
  %26 = icmp sge i64 %24, 16
  %27 = zext i1 %26 to i64
  %28 = shl i64 %27, 2
  %29 = lshr i64 %24, %28
  %30 = add i64 %25, %28
  %31 = icmp sge i64 %29, 4
  %32 = zext i1 %31 to i64
  %33 = shl i64 %32, 1
  %34 = lshr i64 %29, %33
  %35 = add i64 %30, %33
  %36 = icmp sge i64 %34, 2
  %37 = zext i1 %36 to i64
  %38 = shl i64 %37, 0
  %39 = lshr i64 %34, %38
  %40 = add i64 %35, %38
  %41 = sub i64 %40, %6
  %42 = load i64, ptr %3, align 8
  %43 = lshr i64 %42, %41
  %44 = and i64 %43, %8
  %45 = add i64 %41, 1
  %46 = shl i64 %45, %6
  %47 = add i64 %46, %44
  %48 = add i64 %47, 1
  ret i64 %48
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { alwaysinline nounwind }

!llvm.dbg.cu = !{!60}
!llvm.module.flags = !{!62, !63}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !10)
!10 = !{!11, !17, !22, !24}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 160, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 5, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !18, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 131072, elements: !20)
!20 = !{!21}
!21 = !DISubrange(count: 4096, lowerBound: 0)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !23, size: 64, offset: 128)
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!24 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !25, size: 64, offset: 192)
!25 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !26, size: 64)
!26 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!27 = !DIGlobalVariableExpression(var: !28, expr: !DIExpression())
!28 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !29, isLocal: false, isDefinition: true)
!29 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !30)
!30 = !{!11, !17, !31, !24}
!31 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !32, size: 64, offset: 128)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 128, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 16, lowerBound: 0)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !39)
!39 = !{!40, !45}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 27, lowerBound: 0)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !46, size: 64, offset: 64)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !48)
!48 = !{!49}
!49 = !DISubrange(count: 262144, lowerBound: 0)
!50 = !DIGlobalVariableExpression(var: !51, expr: !DIExpression())
!51 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!52 = !DIGlobalVariableExpression(var: !53, expr: !DIExpression())
!53 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !54, isLocal: false, isDefinition: true)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !55, size: 64, elements: !56)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !26, size: 64, elements: !56)
!56 = !{!57}
!57 = !DISubrange(count: 1, lowerBound: 0)
!58 = !DIGlobalVariableExpression(var: !59, expr: !DIExpression())
!59 = distinct !DIGlobalVariable(name: "__bt__num_cpus", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!60 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !61)
!61 = !{!0, !7, !27, !36, !50, !52, !58}
!62 = !{i32 2, !"Debug Info Version", i32 3}
!63 = !{i32 7, !"uwtable", i32 0}
!64 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !65, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !60, retainedNodes: !67)
!65 = !DISubroutineType(types: !66)
!66 = !{!26, !23}
!67 = !{!68}
!68 = !DILocalVariable(name: "ctx", arg: 1, scope: !64, file: !2, type: !23)
