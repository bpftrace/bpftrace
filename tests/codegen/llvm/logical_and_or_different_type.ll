; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr }
%printf_t = type { i64, %printf_args_t }
%printf_args_t = type { i64, i64, i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29
@__bt__fmt_str_buf = dso_local externally_initialized global [1 x [1 x [40 x i8]]] zeroinitializer, section ".data.fmt_str_buf", !dbg !31

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @begin_1(ptr %0) #0 section "s_begin_1" !dbg !42 {
entry:
  %"struct Foo.m16" = alloca i32, align 4
  %"||_result15" = alloca i8, align 1
  %"struct Foo.m8" = alloca i32, align 4
  %"||_result" = alloca i8, align 1
  %"struct Foo.m6" = alloca i32, align 4
  %"&&_result5" = alloca i8, align 1
  %"struct Foo.m" = alloca i32, align 4
  %"&&_result" = alloca i8, align 1
  %"$foo" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$foo")
  store i64 0, ptr %"$foo", align 8
  store i64 0, ptr %"$foo", align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #4
  %1 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [1 x [40 x i8]]], ptr @__bt__fmt_str_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %2, i8 0, i64 40, i1 false)
  %3 = getelementptr %printf_t, ptr %2, i32 0, i32 0
  store i64 0, ptr %3, align 8
  %4 = getelementptr %printf_t, ptr %2, i32 0, i32 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"&&_result")
  %5 = load i64, ptr %"$foo", align 8
  %6 = inttoptr i64 %5 to ptr
  %7 = call ptr @llvm.preserve.static.offset(ptr %6)
  %8 = getelementptr i8, ptr %7, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.m")
  %probe_read = call i64 inttoptr (i64 4 to ptr)(ptr %"struct Foo.m", i32 4, ptr %8)
  %9 = load i32, ptr %"struct Foo.m", align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.m")
  %lhs_true_cond = icmp ne i32 %9, 0
  br i1 %lhs_true_cond, label %"&&_lhs_true", label %"&&_false"

"&&_lhs_true":                                    ; preds = %entry
  br i1 false, label %"&&_true", label %"&&_false"

"&&_true":                                        ; preds = %"&&_lhs_true"
  store i8 1, ptr %"&&_result", align 1
  br label %"&&_merge"

"&&_false":                                       ; preds = %"&&_lhs_true", %entry
  store i8 0, ptr %"&&_result", align 1
  br label %"&&_merge"

"&&_merge":                                       ; preds = %"&&_false", %"&&_true"
  %10 = load i8, ptr %"&&_result", align 1
  %11 = getelementptr %printf_args_t, ptr %4, i32 0, i32 0
  store i8 %10, ptr %11, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"&&_result5")
  br i1 true, label %"&&_lhs_true1", label %"&&_false3"

"&&_lhs_true1":                                   ; preds = %"&&_merge"
  %12 = load i64, ptr %"$foo", align 8
  %13 = inttoptr i64 %12 to ptr
  %14 = call ptr @llvm.preserve.static.offset(ptr %13)
  %15 = getelementptr i8, ptr %14, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.m6")
  %probe_read7 = call i64 inttoptr (i64 4 to ptr)(ptr %"struct Foo.m6", i32 4, ptr %15)
  %16 = load i32, ptr %"struct Foo.m6", align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.m6")
  %rhs_true_cond = icmp ne i32 %16, 0
  br i1 %rhs_true_cond, label %"&&_true2", label %"&&_false3"

"&&_true2":                                       ; preds = %"&&_lhs_true1"
  store i8 1, ptr %"&&_result5", align 1
  br label %"&&_merge4"

"&&_false3":                                      ; preds = %"&&_lhs_true1", %"&&_merge"
  store i8 0, ptr %"&&_result5", align 1
  br label %"&&_merge4"

"&&_merge4":                                      ; preds = %"&&_false3", %"&&_true2"
  %17 = load i8, ptr %"&&_result5", align 1
  %18 = getelementptr %printf_args_t, ptr %4, i32 0, i32 1
  store i8 %17, ptr %18, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"||_result")
  %19 = load i64, ptr %"$foo", align 8
  %20 = inttoptr i64 %19 to ptr
  %21 = call ptr @llvm.preserve.static.offset(ptr %20)
  %22 = getelementptr i8, ptr %21, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.m8")
  %probe_read9 = call i64 inttoptr (i64 4 to ptr)(ptr %"struct Foo.m8", i32 4, ptr %22)
  %23 = load i32, ptr %"struct Foo.m8", align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.m8")
  %lhs_true_cond10 = icmp ne i32 %23, 0
  br i1 %lhs_true_cond10, label %"||_true", label %"||_lhs_false"

"||_lhs_false":                                   ; preds = %"&&_merge4"
  br i1 false, label %"||_true", label %"||_false"

"||_false":                                       ; preds = %"||_lhs_false"
  store i8 0, ptr %"||_result", align 1
  br label %"||_merge"

"||_true":                                        ; preds = %"||_lhs_false", %"&&_merge4"
  store i8 1, ptr %"||_result", align 1
  br label %"||_merge"

"||_merge":                                       ; preds = %"||_true", %"||_false"
  %24 = load i8, ptr %"||_result", align 1
  %25 = getelementptr %printf_args_t, ptr %4, i32 0, i32 2
  store i8 %24, ptr %25, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"||_result15")
  br i1 false, label %"||_true13", label %"||_lhs_false11"

"||_lhs_false11":                                 ; preds = %"||_merge"
  %26 = load i64, ptr %"$foo", align 8
  %27 = inttoptr i64 %26 to ptr
  %28 = call ptr @llvm.preserve.static.offset(ptr %27)
  %29 = getelementptr i8, ptr %28, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.m16")
  %probe_read17 = call i64 inttoptr (i64 4 to ptr)(ptr %"struct Foo.m16", i32 4, ptr %29)
  %30 = load i32, ptr %"struct Foo.m16", align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.m16")
  %rhs_true_cond18 = icmp ne i32 %30, 0
  br i1 %rhs_true_cond18, label %"||_true13", label %"||_false12"

"||_false12":                                     ; preds = %"||_lhs_false11"
  store i8 0, ptr %"||_result15", align 1
  br label %"||_merge14"

"||_true13":                                      ; preds = %"||_lhs_false11", %"||_merge"
  store i8 1, ptr %"||_result15", align 1
  br label %"||_merge14"

"||_merge14":                                     ; preds = %"||_true13", %"||_false12"
  %31 = load i8, ptr %"||_result15", align 1
  %32 = getelementptr %printf_args_t, ptr %4, i32 0, i32 3
  store i8 %31, ptr %32, align 1
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %2, i64 40, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %"||_merge14"
  %get_cpu_id19 = call i64 inttoptr (i64 8 to ptr)() #4
  %33 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded20 = and i64 %get_cpu_id19, %33
  %34 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded20, i64 0
  %35 = load i64, ptr %34, align 8
  %36 = add i64 %35, 1
  store i64 %36, ptr %34, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %"||_merge14"
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

!llvm.dbg.cu = !{!38}
!llvm.module.flags = !{!40, !41}

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
!32 = distinct !DIGlobalVariable(name: "__bt__fmt_str_buf", linkageName: "global", scope: !2, file: !2, type: !33, isLocal: false, isDefinition: true)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !34, size: 320, elements: !27)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !35, size: 320, elements: !27)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 320, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 40, lowerBound: 0)
!38 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !39)
!39 = !{!0, !7, !22, !29, !31}
!40 = !{i32 2, !"Debug Info Version", i32 3}
!41 = !{i32 7, !"uwtable", i32 0}
!42 = distinct !DISubprogram(name: "begin_1", linkageName: "begin_1", scope: !2, file: !2, type: !43, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !38, retainedNodes: !46)
!43 = !DISubroutineType(types: !44)
!44 = !{!26, !45}
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!46 = !{!47}
!47 = !DILocalVariable(name: "ctx", arg: 1, scope: !42, file: !2, type: !45)
