; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.616" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_internal_repr_t.616" zeroinitializer, section ".maps", !dbg !30
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !44
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !50

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !56 {
entry:
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key" = alloca [16 x i8], align 1
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)() #3
  %1 = lshr i64 %get_pid_tgid, 32
  %pid = trunc i64 %1 to i32
  %2 = zext i32 %pid to i64
  %linear = call i64 @linear(i64 %2, i64 0, i64 100, i64 1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  %3 = getelementptr [16 x i8], ptr %"@x_key", i64 0, i64 0
  store i64 0, ptr %3, align 8
  %4 = getelementptr [16 x i8], ptr %"@x_key", i64 0, i64 8
  store i64 %linear, ptr %4, align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %5 = load i64, ptr %lookup_elem, align 8
  %6 = add i64 %5, 1
  store i64 %6, ptr %lookup_elem, align 8
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
  ret i64 0
}

; Function Attrs: alwaysinline nounwind
define internal i64 @linear(i64 %0, i64 %1, i64 %2, i64 %3) #1 section "helpers" {
entry:
  %4 = alloca i64, align 8
  %5 = alloca i64, align 8
  %6 = alloca i64, align 8
  %7 = alloca i64, align 8
  %8 = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %8)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %7)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %6)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %5)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %4)
  store i64 %0, ptr %8, align 8
  store i64 %1, ptr %7, align 8
  store i64 %2, ptr %6, align 8
  store i64 %3, ptr %5, align 8
  %9 = load i64, ptr %7, align 8
  %10 = load i64, ptr %8, align 8
  %11 = icmp slt i64 %10, %9
  br i1 %11, label %lhist.lt_min, label %lhist.ge_min

lhist.lt_min:                                     ; preds = %entry
  ret i64 0

lhist.ge_min:                                     ; preds = %entry
  %12 = load i64, ptr %6, align 8
  %13 = load i64, ptr %8, align 8
  %14 = icmp sgt i64 %13, %12
  br i1 %14, label %lhist.gt_max, label %lhist.le_max

lhist.le_max:                                     ; preds = %lhist.ge_min
  %15 = load i64, ptr %5, align 8
  %16 = load i64, ptr %7, align 8
  %17 = load i64, ptr %8, align 8
  %18 = sub i64 %17, %16
  %19 = udiv i64 %18, %15
  %20 = add i64 %19, 1
  store i64 %20, ptr %4, align 8
  %21 = load i64, ptr %4, align 8
  ret i64 %21

lhist.gt_max:                                     ; preds = %lhist.ge_min
  %22 = load i64, ptr %5, align 8
  %23 = load i64, ptr %7, align 8
  %24 = load i64, ptr %6, align 8
  %25 = sub i64 %24, %23
  %26 = udiv i64 %25, %22
  %27 = add i64 %26, 1
  store i64 %27, ptr %4, align 8
  %28 = load i64, ptr %4, align 8
  ret i64 %28
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

attributes #0 = { nounwind }
attributes #1 = { alwaysinline nounwind }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { memory(none) }

!llvm.dbg.cu = !{!52}
!llvm.module.flags = !{!54, !55}

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
!10 = !{!11, !17, !22, !27}
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
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 128, elements: !25)
!25 = !{!26}
!26 = !DISubrange(count: 16, lowerBound: 0)
!27 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !28, size: 64, offset: 192)
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!29 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())
!31 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !32, isLocal: false, isDefinition: true)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !33)
!33 = !{!34, !39}
!34 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !35, size: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 27, lowerBound: 0)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !40, size: 64, offset: 64)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 262144, lowerBound: 0)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !47, size: 64, elements: !48)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !29, size: 64, elements: !48)
!48 = !{!49}
!49 = !DISubrange(count: 1, lowerBound: 0)
!50 = !DIGlobalVariableExpression(var: !51, expr: !DIExpression())
!51 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !29, isLocal: false, isDefinition: true)
!52 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !53)
!53 = !{!0, !7, !30, !44, !50}
!54 = !{i32 2, !"Debug Info Version", i32 3}
!55 = !{i32 7, !"uwtable", i32 0}
!56 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !57, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !52, retainedNodes: !60)
!57 = !DISubroutineType(types: !58)
!58 = !{!29, !59}
!59 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!60 = !{!61}
!61 = !DILocalVariable(name: "ctx", arg: 1, scope: !56, file: !2, type: !59)
