; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29
@hello-test-world = global [17 x i8] c"hello-test-world\00"
@test = global [5 x i8] c"test\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_foo_1(ptr %0) #0 section "s_kprobe_foo_1" !dbg !35 {
entry:
  %array_access = alloca i8, align 1
  %"$$strstr_4_$needle_size" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strstr_4_$needle_size")
  store i64 0, ptr %"$$strstr_4_$needle_size", align 8
  %"$$strstr_4_$haystack_size" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strstr_4_$haystack_size")
  store i64 0, ptr %"$$strstr_4_$haystack_size", align 8
  %"$$strstr_3_$needle" = alloca [5 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strstr_3_$needle")
  call void @llvm.memset.p0.i64(ptr align 1 %"$$strstr_3_$needle", i8 0, i64 5, i1 false)
  %"$$strstr_2_$haystack" = alloca [17 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strstr_2_$haystack")
  call void @llvm.memset.p0.i64(ptr align 1 %"$$strstr_2_$haystack", i8 0, i64 17, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %"$$strstr_2_$haystack", ptr align 1 @hello-test-world, i64 17, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %"$$strstr_3_$needle", ptr align 1 @test, i64 5, i1 false)
  store i64 17, ptr %"$$strstr_4_$haystack_size", align 8
  store i64 5, ptr %"$$strstr_4_$needle_size", align 8
  %1 = load i64, ptr %"$$strstr_4_$needle_size", align 8
  %2 = icmp eq i64 %1, 0
  %true_cond = icmp ne i1 %2, false
  br i1 %true_cond, label %left, label %right

left:                                             ; preds = %entry
  br label %done

right:                                            ; preds = %entry
  %3 = ptrtoint ptr %"$$strstr_3_$needle" to i64
  %4 = inttoptr i64 %3 to ptr
  %5 = call ptr @llvm.preserve.static.offset(ptr %4)
  %6 = getelementptr i8, ptr %5, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %array_access)
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %array_access, i32 1, ptr %6)
  %7 = load i8, ptr %array_access, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %array_access)
  %8 = icmp eq i8 %7, 0
  %true_cond3 = icmp ne i1 %8, false
  br i1 %true_cond3, label %left1, label %right2

done:                                             ; preds = %done4, %left
  %result5 = phi i32 [ 0, %left ], [ %result, %done4 ]
  %9 = icmp sge i32 %result5, 0
  ret i64 0

left1:                                            ; preds = %right
  br label %done4

right2:                                           ; preds = %right
  %10 = load i64, ptr %"$$strstr_4_$haystack_size", align 8
  %11 = load i64, ptr %"$$strstr_4_$needle_size", align 8
  %__bpf_strnstr = call i32 @__bpf_strnstr(ptr %"$$strstr_2_$haystack", ptr %"$$strstr_3_$needle", i64 %10, i64 %11), !dbg !41
  br label %done4

done4:                                            ; preds = %right2, %left1
  %result = phi i32 [ 0, %left1 ], [ %__bpf_strnstr, %right2 ]
  br label %done
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #4

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: alwaysinline nounwind
declare dso_local i32 @__bpf_strnstr(ptr noundef %0, ptr noundef %1, i64 noundef %2, i64 noundef %3) #5

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #4 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #5 = { alwaysinline nounwind }

!llvm.dbg.cu = !{!31}
!llvm.module.flags = !{!33, !34}

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
!31 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !32)
!32 = !{!0, !7, !22, !29}
!33 = !{i32 2, !"Debug Info Version", i32 3}
!34 = !{i32 7, !"uwtable", i32 0}
!35 = distinct !DISubprogram(name: "kprobe_foo_1", linkageName: "kprobe_foo_1", scope: !2, file: !2, type: !36, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !31, retainedNodes: !39)
!36 = !DISubroutineType(types: !37)
!37 = !{!26, !38}
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!39 = !{!40}
!40 = !DILocalVariable(name: "ctx", arg: 1, scope: !35, file: !2, type: !38)
!41 = !DILocation(line: 101, column: 5, scope: !35)
