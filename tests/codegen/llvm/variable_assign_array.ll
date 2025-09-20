; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.140" = type { ptr, ptr }
%runtime_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_internal_repr_t.140" zeroinitializer, section ".maps", !dbg !22
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !36
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !40

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !46 {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %array_access = alloca i32, align 4
  %runtime_error_t = alloca %runtime_error_t, align 8
  %"$var" = alloca ptr, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var")
  store i0 0, ptr %"$var", align 1
  %1 = call ptr @llvm.preserve.static.offset(ptr %0)
  %2 = getelementptr i8, ptr %1, i64 112
  %arg0 = load volatile i64, ptr %2, align 8
  %3 = inttoptr i64 %arg0 to ptr
  %4 = call ptr @llvm.preserve.static.offset(ptr %3)
  %5 = getelementptr i8, ptr %4, i64 0
  %6 = ptrtoint ptr %5 to i64
  store i64 %6, ptr %"$var", align 8
  %7 = load ptr, ptr %"$var", align 8
  br i1 false, label %is_oob, label %oob_merge

is_oob:                                           ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %runtime_error_t)
  %8 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 0
  store i64 30006, ptr %8, align 8
  %9 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 1
  store i64 0, ptr %9, align 8
  %10 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 2
  store i64 0, ptr %10, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %runtime_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

oob_merge:                                        ; preds = %counter_merge, %entry
  %11 = ptrtoint ptr %7 to i64
  %12 = inttoptr i64 %11 to ptr
  %13 = call ptr @llvm.preserve.static.offset(ptr %12)
  %14 = getelementptr i8, ptr %13, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %array_access)
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %array_access, i32 4, ptr %14)
  %15 = load i32, ptr %array_access, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %array_access)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_val")
  %16 = sext i32 %15 to i64
  store i64 %16, ptr %"@x_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  ret i64 0

event_loss_counter:                               ; preds = %is_oob
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #3
  %17 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %17
  %18 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %19 = load i64, ptr %18, align 8
  %20 = add i64 %19, 1
  store i64 %20, ptr %18, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %is_oob
  call void @llvm.lifetime.end.p0(i64 -1, ptr %runtime_error_t)
  br label %oob_merge
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { memory(none) }

!llvm.dbg.cu = !{!42}
!llvm.module.flags = !{!44, !45}

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
!21 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !19, size: 64, offset: 192)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !25)
!25 = !{!26, !31}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 27, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !32, size: 64, offset: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 262144, lowerBound: 0)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_array_type, baseType: !39, size: 64, elements: !15)
!39 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 64, elements: !15)
!40 = !DIGlobalVariableExpression(var: !41, expr: !DIExpression())
!41 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!42 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !43)
!43 = !{!0, !7, !22, !36, !40}
!44 = !{i32 2, !"Debug Info Version", i32 3}
!45 = !{i32 7, !"uwtable", i32 0}
!46 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !47, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !42, retainedNodes: !50)
!47 = !DISubroutineType(types: !48)
!48 = !{!20, !49}
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!50 = !{!51}
!51 = !DILocalVariable(name: "ctx", arg: 1, scope: !46, file: !2, type: !49)
