; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29
@__bt__var_buf = dso_local externally_initialized global [1 x [4 x [1024 x i8]]] zeroinitializer, section ".data.var_buf", !dbg !31
@__bt__get_str_buf = dso_local externally_initialized global [1 x [2 x [1024 x i8]]] zeroinitializer, section ".data.get_str_buf", !dbg !38

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_foo_1(ptr %0) #0 section "s_kprobe_foo_1" !dbg !48 {
entry:
  %array_access = alloca i8, align 1
  %"$$strstr_4_$needle_size" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strstr_4_$needle_size")
  store i64 0, ptr %"$$strstr_4_$needle_size", align 8
  %"$$strstr_4_$haystack_size" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strstr_4_$haystack_size")
  store i64 0, ptr %"$$strstr_4_$haystack_size", align 8
  %get_cpu_id9 = call i64 inttoptr (i64 8 to ptr)() #4
  %1 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded10 = and i64 %get_cpu_id9, %1
  %2 = getelementptr [1 x [4 x [1024 x i8]]], ptr @__bt__var_buf, i64 0, i64 %cpu.id.bounded10, i64 1, i64 0
  %probe_read_kernel11 = call i64 inttoptr (i64 113 to ptr)(ptr %2, i32 1024, ptr null)
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)() #4
  %3 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %3
  %4 = getelementptr [1 x [4 x [1024 x i8]]], ptr @__bt__var_buf, i64 0, i64 %cpu.id.bounded2, i64 0, i64 0
  %probe_read_kernel3 = call i64 inttoptr (i64 113 to ptr)(ptr %4, i32 1024, ptr null)
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #4
  %5 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %5
  %6 = getelementptr [1 x [2 x [1024 x i8]]], ptr @__bt__get_str_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %6, i32 1024, ptr null)
  %7 = call ptr @llvm.preserve.static.offset(ptr %0)
  %8 = getelementptr i8, ptr %7, i64 112
  %arg0 = load volatile i64, ptr %8, align 8
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to ptr)(ptr %6, i32 1024, i64 %arg0)
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to ptr)(ptr %4, i32 1024, ptr %6)
  %get_cpu_id5 = call i64 inttoptr (i64 8 to ptr)() #4
  %9 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded6 = and i64 %get_cpu_id5, %9
  %10 = getelementptr [1 x [2 x [1024 x i8]]], ptr @__bt__get_str_buf, i64 0, i64 %cpu.id.bounded6, i64 1, i64 0
  %probe_read_kernel7 = call i64 inttoptr (i64 113 to ptr)(ptr %10, i32 1024, ptr null)
  %11 = call ptr @llvm.preserve.static.offset(ptr %0)
  %12 = getelementptr i8, ptr %11, i64 104
  %arg1 = load volatile i64, ptr %12, align 8
  %probe_read_kernel_str8 = call i64 inttoptr (i64 115 to ptr)(ptr %10, i32 1024, i64 %arg1)
  %probe_read_kernel12 = call i64 inttoptr (i64 113 to ptr)(ptr %2, i32 1024, ptr %10)
  store i64 1024, ptr %"$$strstr_4_$haystack_size", align 8
  store i64 1024, ptr %"$$strstr_4_$needle_size", align 8
  %13 = load i64, ptr %"$$strstr_4_$needle_size", align 8
  %14 = icmp eq i64 %13, 0
  %true_cond = icmp ne i1 %14, false
  br i1 %true_cond, label %left, label %right

left:                                             ; preds = %entry
  br label %done

right:                                            ; preds = %entry
  %15 = ptrtoint ptr %2 to i64
  %16 = inttoptr i64 %15 to ptr
  %17 = call ptr @llvm.preserve.static.offset(ptr %16)
  %18 = getelementptr i8, ptr %17, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %array_access)
  %probe_read_kernel15 = call i64 inttoptr (i64 113 to ptr)(ptr %array_access, i32 1, ptr %18)
  %19 = load i8, ptr %array_access, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %array_access)
  %20 = icmp eq i8 %19, 0
  %true_cond16 = icmp ne i1 %20, false
  br i1 %true_cond16, label %left13, label %right14

done:                                             ; preds = %done17, %left
  %result18 = phi i32 [ 0, %left ], [ %result, %done17 ]
  %21 = icmp sge i32 %result18, 0
  ret i64 0

left13:                                           ; preds = %right
  br label %done17

right14:                                          ; preds = %right
  %22 = load i64, ptr %"$$strstr_4_$haystack_size", align 8
  %23 = load i64, ptr %"$$strstr_4_$needle_size", align 8
  %__bpf_strnstr = call i32 @__bpf_strnstr(ptr %4, ptr %2, i64 %22, i64 %23), !dbg !54
  br label %done17

done17:                                           ; preds = %right14, %left13
  %result = phi i32 [ 0, %left13 ], [ %__bpf_strnstr, %right14 ]
  br label %done
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: alwaysinline nounwind
declare dso_local i32 @__bpf_strnstr(ptr noundef %0, ptr noundef %1, i64 noundef %2, i64 noundef %3) #3

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { alwaysinline nounwind }
attributes #4 = { memory(none) }

!llvm.dbg.cu = !{!44}
!llvm.module.flags = !{!46, !47}

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
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !34, size: 32768, elements: !27)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !35, size: 32768, elements: !5)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 8192, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 1024, lowerBound: 0)
!38 = !DIGlobalVariableExpression(var: !39, expr: !DIExpression())
!39 = distinct !DIGlobalVariable(name: "__bt__get_str_buf", linkageName: "global", scope: !2, file: !2, type: !40, isLocal: false, isDefinition: true)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !41, size: 16384, elements: !27)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !35, size: 16384, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 2, lowerBound: 0)
!44 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !45)
!45 = !{!0, !7, !22, !29, !31, !38}
!46 = !{i32 2, !"Debug Info Version", i32 3}
!47 = !{i32 7, !"uwtable", i32 0}
!48 = distinct !DISubprogram(name: "kprobe_foo_1", linkageName: "kprobe_foo_1", scope: !2, file: !2, type: !49, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !44, retainedNodes: !52)
!49 = !DISubroutineType(types: !50)
!50 = !{!26, !51}
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!52 = !{!53}
!53 = !DILocalVariable(name: "ctx", arg: 1, scope: !48, file: !2, type: !51)
!54 = !DILocation(line: 101, column: 5, scope: !48)
