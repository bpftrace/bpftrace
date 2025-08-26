; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr }
%printf_t = type { i64, %printf_args_t }
%printf_args_t = type { i8, i8, i8, i8 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @begin_1(ptr %0) #0 section "s_begin_1" !dbg !35 {
entry:
  %"struct Foo.m16" = alloca i32, align 4
  %"||_result15" = alloca i1, align 1
  %"struct Foo.m8" = alloca i32, align 4
  %"||_result" = alloca i1, align 1
  %"struct Foo.m6" = alloca i32, align 4
  %"&&_result5" = alloca i1, align 1
  %"struct Foo.m" = alloca i32, align 4
  %"&&_result" = alloca i1, align 1
  %printf_args = alloca %printf_t, align 8
  %"$foo" = alloca ptr, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$foo")
  store i0 0, ptr %"$foo", align 1
  store i64 0, ptr %"$foo", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %printf_args)
  call void @llvm.memset.p0.i64(ptr align 1 %printf_args, i8 0, i64 16, i1 false)
  %1 = getelementptr %printf_t, ptr %printf_args, i32 0, i32 0
  store i64 0, ptr %1, align 8
  %2 = getelementptr %printf_t, ptr %printf_args, i32 0, i32 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"&&_result")
  %3 = load ptr, ptr %"$foo", align 8
  %4 = call ptr @llvm.preserve.static.offset(ptr %3)
  %5 = getelementptr i8, ptr %4, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.m")
  %probe_read = call i64 inttoptr (i64 4 to ptr)(ptr %"struct Foo.m", i32 4, ptr %5)
  %6 = load i32, ptr %"struct Foo.m", align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.m")
  %lhs_true_cond = icmp ne i32 %6, 0
  br i1 %lhs_true_cond, label %"&&_lhs_true", label %"&&_false"

"&&_lhs_true":                                    ; preds = %entry
  br i1 false, label %"&&_true", label %"&&_false"

"&&_true":                                        ; preds = %"&&_lhs_true"
  store i1 true, ptr %"&&_result", align 1
  br label %"&&_merge"

"&&_false":                                       ; preds = %"&&_lhs_true", %entry
  store i1 false, ptr %"&&_result", align 1
  br label %"&&_merge"

"&&_merge":                                       ; preds = %"&&_false", %"&&_true"
  %7 = load i1, ptr %"&&_result", align 1
  %8 = getelementptr %printf_args_t, ptr %2, i32 0, i32 0
  store i1 %7, ptr %8, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"&&_result5")
  br i1 true, label %"&&_lhs_true1", label %"&&_false3"

"&&_lhs_true1":                                   ; preds = %"&&_merge"
  %9 = load ptr, ptr %"$foo", align 8
  %10 = call ptr @llvm.preserve.static.offset(ptr %9)
  %11 = getelementptr i8, ptr %10, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.m6")
  %probe_read7 = call i64 inttoptr (i64 4 to ptr)(ptr %"struct Foo.m6", i32 4, ptr %11)
  %12 = load i32, ptr %"struct Foo.m6", align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.m6")
  %rhs_true_cond = icmp ne i32 %12, 0
  br i1 %rhs_true_cond, label %"&&_true2", label %"&&_false3"

"&&_true2":                                       ; preds = %"&&_lhs_true1"
  store i1 true, ptr %"&&_result5", align 1
  br label %"&&_merge4"

"&&_false3":                                      ; preds = %"&&_lhs_true1", %"&&_merge"
  store i1 false, ptr %"&&_result5", align 1
  br label %"&&_merge4"

"&&_merge4":                                      ; preds = %"&&_false3", %"&&_true2"
  %13 = load i1, ptr %"&&_result5", align 1
  %14 = getelementptr %printf_args_t, ptr %2, i32 0, i32 1
  store i1 %13, ptr %14, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"||_result")
  %15 = load ptr, ptr %"$foo", align 8
  %16 = call ptr @llvm.preserve.static.offset(ptr %15)
  %17 = getelementptr i8, ptr %16, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.m8")
  %probe_read9 = call i64 inttoptr (i64 4 to ptr)(ptr %"struct Foo.m8", i32 4, ptr %17)
  %18 = load i32, ptr %"struct Foo.m8", align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.m8")
  %lhs_true_cond10 = icmp ne i32 %18, 0
  br i1 %lhs_true_cond10, label %"||_true", label %"||_lhs_false"

"||_lhs_false":                                   ; preds = %"&&_merge4"
  br i1 false, label %"||_true", label %"||_false"

"||_false":                                       ; preds = %"||_lhs_false"
  store i1 false, ptr %"||_result", align 1
  br label %"||_merge"

"||_true":                                        ; preds = %"||_lhs_false", %"&&_merge4"
  store i1 true, ptr %"||_result", align 1
  br label %"||_merge"

"||_merge":                                       ; preds = %"||_true", %"||_false"
  %19 = load i1, ptr %"||_result", align 1
  %20 = getelementptr %printf_args_t, ptr %2, i32 0, i32 2
  store i1 %19, ptr %20, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"||_result15")
  br i1 false, label %"||_true13", label %"||_lhs_false11"

"||_lhs_false11":                                 ; preds = %"||_merge"
  %21 = load ptr, ptr %"$foo", align 8
  %22 = call ptr @llvm.preserve.static.offset(ptr %21)
  %23 = getelementptr i8, ptr %22, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.m16")
  %probe_read17 = call i64 inttoptr (i64 4 to ptr)(ptr %"struct Foo.m16", i32 4, ptr %23)
  %24 = load i32, ptr %"struct Foo.m16", align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.m16")
  %rhs_true_cond18 = icmp ne i32 %24, 0
  br i1 %rhs_true_cond18, label %"||_true13", label %"||_false12"

"||_false12":                                     ; preds = %"||_lhs_false11"
  store i1 false, ptr %"||_result15", align 1
  br label %"||_merge14"

"||_true13":                                      ; preds = %"||_lhs_false11", %"||_merge"
  store i1 true, ptr %"||_result15", align 1
  br label %"||_merge14"

"||_merge14":                                     ; preds = %"||_true13", %"||_false12"
  %25 = load i1, ptr %"||_result15", align 1
  %26 = getelementptr %printf_args_t, ptr %2, i32 0, i32 3
  store i1 %25, ptr %26, align 1
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %printf_args, i64 16, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %"||_merge14"
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #4
  %27 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %27
  %28 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %29 = load i64, ptr %28, align 8
  %30 = add i64 %29, 1
  store i64 %30, ptr %28, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %"||_merge14"
  call void @llvm.lifetime.end.p0(i64 -1, ptr %printf_args)
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
!35 = distinct !DISubprogram(name: "begin_1", linkageName: "begin_1", scope: !2, file: !2, type: !36, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !31, retainedNodes: !39)
!36 = !DISubroutineType(types: !37)
!37 = !{!26, !38}
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!39 = !{!40}
!40 = !DILocalVariable(name: "ctx", arg: 1, scope: !35, file: !2, type: !38)
