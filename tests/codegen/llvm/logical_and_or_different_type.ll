; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%printf_t = type { i64, i64, i64, i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@event_loss_counter = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !42
@fmt_str_buf = dso_local externally_initialized global [1 x [1 x [40 x i8]]] zeroinitializer, section ".data.fmt_str_buf", !dbg !44

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @p1_0(ptr %0) #0 section "probes" !dbg !55 {
entry:
  %key = alloca i32, align 4
  %"struct Foo.m16" = alloca i32, align 4
  %"||_result15" = alloca i64, align 8
  %"struct Foo.m8" = alloca i32, align 4
  %"||_result" = alloca i64, align 8
  %"struct Foo.m6" = alloca i32, align 4
  %"&&_result5" = alloca i64, align 8
  %"struct Foo.m" = alloca i32, align 4
  %"&&_result" = alloca i64, align 8
  %"$foo" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$foo")
  store i64 0, ptr %"$foo", align 8
  store i64 0, ptr %"$foo", align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [1 x [40 x i8]]], ptr @fmt_str_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %2, i8 0, i64 40, i1 false)
  %3 = getelementptr %printf_t, ptr %2, i32 0, i32 0
  store i64 0, ptr %3, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"&&_result")
  %4 = load i64, ptr %"$foo", align 8
  %5 = inttoptr i64 %4 to ptr
  %6 = call ptr @llvm.preserve.static.offset(ptr %5)
  %7 = getelementptr i8, ptr %6, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.m")
  %probe_read = call i64 inttoptr (i64 4 to ptr)(ptr %"struct Foo.m", i32 4, ptr %7)
  %8 = load i32, ptr %"struct Foo.m", align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.m")
  %lhs_true_cond = icmp ne i32 %8, 0
  br i1 %lhs_true_cond, label %"&&_lhs_true", label %"&&_false"

"&&_lhs_true":                                    ; preds = %entry
  br i1 false, label %"&&_true", label %"&&_false"

"&&_true":                                        ; preds = %"&&_lhs_true"
  store i64 1, ptr %"&&_result", align 8
  br label %"&&_merge"

"&&_false":                                       ; preds = %"&&_lhs_true", %entry
  store i64 0, ptr %"&&_result", align 8
  br label %"&&_merge"

"&&_merge":                                       ; preds = %"&&_false", %"&&_true"
  %9 = load i64, ptr %"&&_result", align 8
  %10 = getelementptr %printf_t, ptr %2, i32 0, i32 1
  store i64 %9, ptr %10, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"&&_result5")
  br i1 true, label %"&&_lhs_true1", label %"&&_false3"

"&&_lhs_true1":                                   ; preds = %"&&_merge"
  %11 = load i64, ptr %"$foo", align 8
  %12 = inttoptr i64 %11 to ptr
  %13 = call ptr @llvm.preserve.static.offset(ptr %12)
  %14 = getelementptr i8, ptr %13, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.m6")
  %probe_read7 = call i64 inttoptr (i64 4 to ptr)(ptr %"struct Foo.m6", i32 4, ptr %14)
  %15 = load i32, ptr %"struct Foo.m6", align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.m6")
  %rhs_true_cond = icmp ne i32 %15, 0
  br i1 %rhs_true_cond, label %"&&_true2", label %"&&_false3"

"&&_true2":                                       ; preds = %"&&_lhs_true1"
  store i64 1, ptr %"&&_result5", align 8
  br label %"&&_merge4"

"&&_false3":                                      ; preds = %"&&_lhs_true1", %"&&_merge"
  store i64 0, ptr %"&&_result5", align 8
  br label %"&&_merge4"

"&&_merge4":                                      ; preds = %"&&_false3", %"&&_true2"
  %16 = load i64, ptr %"&&_result5", align 8
  %17 = getelementptr %printf_t, ptr %2, i32 0, i32 2
  store i64 %16, ptr %17, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"||_result")
  %18 = load i64, ptr %"$foo", align 8
  %19 = inttoptr i64 %18 to ptr
  %20 = call ptr @llvm.preserve.static.offset(ptr %19)
  %21 = getelementptr i8, ptr %20, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.m8")
  %probe_read9 = call i64 inttoptr (i64 4 to ptr)(ptr %"struct Foo.m8", i32 4, ptr %21)
  %22 = load i32, ptr %"struct Foo.m8", align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.m8")
  %lhs_true_cond10 = icmp ne i32 %22, 0
  br i1 %lhs_true_cond10, label %"||_true", label %"||_lhs_false"

"||_lhs_false":                                   ; preds = %"&&_merge4"
  br i1 false, label %"||_true", label %"||_false"

"||_false":                                       ; preds = %"||_lhs_false"
  store i64 0, ptr %"||_result", align 8
  br label %"||_merge"

"||_true":                                        ; preds = %"||_lhs_false", %"&&_merge4"
  store i64 1, ptr %"||_result", align 8
  br label %"||_merge"

"||_merge":                                       ; preds = %"||_true", %"||_false"
  %23 = load i64, ptr %"||_result", align 8
  %24 = getelementptr %printf_t, ptr %2, i32 0, i32 3
  store i64 %23, ptr %24, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"||_result15")
  br i1 false, label %"||_true13", label %"||_lhs_false11"

"||_lhs_false11":                                 ; preds = %"||_merge"
  %25 = load i64, ptr %"$foo", align 8
  %26 = inttoptr i64 %25 to ptr
  %27 = call ptr @llvm.preserve.static.offset(ptr %26)
  %28 = getelementptr i8, ptr %27, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.m16")
  %probe_read17 = call i64 inttoptr (i64 4 to ptr)(ptr %"struct Foo.m16", i32 4, ptr %28)
  %29 = load i32, ptr %"struct Foo.m16", align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.m16")
  %rhs_true_cond18 = icmp ne i32 %29, 0
  br i1 %rhs_true_cond18, label %"||_true13", label %"||_false12"

"||_false12":                                     ; preds = %"||_lhs_false11"
  store i64 0, ptr %"||_result15", align 8
  br label %"||_merge14"

"||_true13":                                      ; preds = %"||_lhs_false11", %"||_merge"
  store i64 1, ptr %"||_result15", align 8
  br label %"||_merge14"

"||_merge14":                                     ; preds = %"||_true13", %"||_false12"
  %30 = load i64, ptr %"||_result15", align 8
  %31 = getelementptr %printf_t, ptr %2, i32 0, i32 4
  store i64 %30, ptr %31, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %2, i64 40, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %"||_merge14"
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %"||_merge14"
  ret i64 0

lookup_success:                                   ; preds = %event_loss_counter
  %32 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge
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

!llvm.dbg.cu = !{!51}
!llvm.module.flags = !{!53, !54}

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
!23 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !25)
!25 = !{!26, !31, !36, !39}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 64, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 2, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !32, size: 64, offset: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 1, lowerBound: 0)
!36 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !37, size: 64, offset: 128)
!37 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !38, size: 64)
!38 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !40, size: 64, offset: 192)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!42 = !DIGlobalVariableExpression(var: !43, expr: !DIExpression())
!43 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !41, isLocal: false, isDefinition: true)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "fmt_str_buf", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !47, size: 320, elements: !34)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !48, size: 320, elements: !34)
!48 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 320, elements: !49)
!49 = !{!50}
!50 = !DISubrange(count: 40, lowerBound: 0)
!51 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !52)
!52 = !{!0, !7, !22, !42, !44}
!53 = !{i32 2, !"Debug Info Version", i32 3}
!54 = !{i32 7, !"uwtable", i32 0}
!55 = distinct !DISubprogram(name: "p1_0", linkageName: "p1_0", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !51, retainedNodes: !59)
!56 = !DISubroutineType(types: !57)
!57 = !{!41, !58}
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!59 = !{!60}
!60 = !DILocalVariable(name: "ctx", arg: 1, scope: !55, file: !2, type: !58)
