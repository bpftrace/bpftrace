; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }
%printf_t = type { i64, i64, i64, i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@event_loss_counter = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(i8* %0) section "s_BEGIN_1" !dbg !40 {
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
  %printf_args = alloca %printf_t, align 8
  %"$foo" = alloca i64, align 8
  %1 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$foo", align 8
  store i64 0, i64* %"$foo", align 8
  %2 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %3, i8 0, i64 40, i1 false)
  %4 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %4, align 8
  %5 = bitcast i64* %"&&_result" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = load i64, i64* %"$foo", align 8
  %7 = add i64 %6, 0
  %8 = bitcast i32* %"struct Foo.m" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i32*, i32, i64)*)(i32* %"struct Foo.m", i32 4, i64 %7)
  %9 = load i32, i32* %"struct Foo.m", align 4
  %10 = bitcast i32* %"struct Foo.m" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %lhs_true_cond = icmp ne i32 %9, 0
  br i1 %lhs_true_cond, label %"&&_lhs_true", label %"&&_false"

"&&_lhs_true":                                    ; preds = %entry
  br i1 false, label %"&&_true", label %"&&_false"

"&&_true":                                        ; preds = %"&&_lhs_true"
  store i64 1, i64* %"&&_result", align 8
  br label %"&&_merge"

"&&_false":                                       ; preds = %"&&_lhs_true", %entry
  store i64 0, i64* %"&&_result", align 8
  br label %"&&_merge"

"&&_merge":                                       ; preds = %"&&_false", %"&&_true"
  %11 = load i64, i64* %"&&_result", align 8
  %12 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  store i64 %11, i64* %12, align 8
  %13 = bitcast i64* %"&&_result5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  br i1 true, label %"&&_lhs_true1", label %"&&_false3"

"&&_lhs_true1":                                   ; preds = %"&&_merge"
  %14 = load i64, i64* %"$foo", align 8
  %15 = add i64 %14, 0
  %16 = bitcast i32* %"struct Foo.m6" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  %probe_read7 = call i64 inttoptr (i64 4 to i64 (i32*, i32, i64)*)(i32* %"struct Foo.m6", i32 4, i64 %15)
  %17 = load i32, i32* %"struct Foo.m6", align 4
  %18 = bitcast i32* %"struct Foo.m6" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  %rhs_true_cond = icmp ne i32 %17, 0
  br i1 %rhs_true_cond, label %"&&_true2", label %"&&_false3"

"&&_true2":                                       ; preds = %"&&_lhs_true1"
  store i64 1, i64* %"&&_result5", align 8
  br label %"&&_merge4"

"&&_false3":                                      ; preds = %"&&_lhs_true1", %"&&_merge"
  store i64 0, i64* %"&&_result5", align 8
  br label %"&&_merge4"

"&&_merge4":                                      ; preds = %"&&_false3", %"&&_true2"
  %19 = load i64, i64* %"&&_result5", align 8
  %20 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 2
  store i64 %19, i64* %20, align 8
  %21 = bitcast i64* %"||_result" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  %22 = load i64, i64* %"$foo", align 8
  %23 = add i64 %22, 0
  %24 = bitcast i32* %"struct Foo.m8" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %24)
  %probe_read9 = call i64 inttoptr (i64 4 to i64 (i32*, i32, i64)*)(i32* %"struct Foo.m8", i32 4, i64 %23)
  %25 = load i32, i32* %"struct Foo.m8", align 4
  %26 = bitcast i32* %"struct Foo.m8" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %26)
  %lhs_true_cond10 = icmp ne i32 %25, 0
  br i1 %lhs_true_cond10, label %"||_true", label %"||_lhs_false"

"||_lhs_false":                                   ; preds = %"&&_merge4"
  br i1 false, label %"||_true", label %"||_false"

"||_false":                                       ; preds = %"||_lhs_false"
  store i64 0, i64* %"||_result", align 8
  br label %"||_merge"

"||_true":                                        ; preds = %"||_lhs_false", %"&&_merge4"
  store i64 1, i64* %"||_result", align 8
  br label %"||_merge"

"||_merge":                                       ; preds = %"||_true", %"||_false"
  %27 = load i64, i64* %"||_result", align 8
  %28 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 3
  store i64 %27, i64* %28, align 8
  %29 = bitcast i64* %"||_result15" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %29)
  br i1 false, label %"||_true13", label %"||_lhs_false11"

"||_lhs_false11":                                 ; preds = %"||_merge"
  %30 = load i64, i64* %"$foo", align 8
  %31 = add i64 %30, 0
  %32 = bitcast i32* %"struct Foo.m16" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %32)
  %probe_read17 = call i64 inttoptr (i64 4 to i64 (i32*, i32, i64)*)(i32* %"struct Foo.m16", i32 4, i64 %31)
  %33 = load i32, i32* %"struct Foo.m16", align 4
  %34 = bitcast i32* %"struct Foo.m16" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %34)
  %rhs_true_cond18 = icmp ne i32 %33, 0
  br i1 %rhs_true_cond18, label %"||_true13", label %"||_false12"

"||_false12":                                     ; preds = %"||_lhs_false11"
  store i64 0, i64* %"||_result15", align 8
  br label %"||_merge14"

"||_true13":                                      ; preds = %"||_lhs_false11", %"||_merge"
  store i64 1, i64* %"||_result15", align 8
  br label %"||_merge14"

"||_merge14":                                     ; preds = %"||_true13", %"||_false12"
  %35 = load i64, i64* %"||_result15", align 8
  %36 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 4
  store i64 %35, i64* %36, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t"*, %printf_t*, i64, i64)*)(%"struct map_t"* @ringbuf, %printf_t* %printf_args, i64 40, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %"||_merge14"
  %37 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %37)
  store i32 0, i32* %key, align 4
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t.0"*, i32*)*)(%"struct map_t.0"* @event_loss_counter, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %"||_merge14"
  %38 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %38)
  ret i64 0

lookup_success:                                   ; preds = %event_loss_counter
  %39 = bitcast i8* %lookup_elem to i64*
  %40 = atomicrmw add i64* %39, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %41 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %41)
  br label %counter_merge
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!36}
!llvm.module.flags = !{!39}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !4)
!4 = !{!5, !11}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 27, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 262144, lowerBound: 0)
!16 = !DIGlobalVariableExpression(var: !17, expr: !DIExpression())
!17 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !19)
!19 = !{!20, !25, !30, !33}
!20 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !21, size: 64)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !23)
!23 = !{!24}
!24 = !DISubrange(count: 2, lowerBound: 0)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !26, size: 64, offset: 64)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 1, lowerBound: 0)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !31, size: 64, offset: 128)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !34, size: 64, offset: 192)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!36 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !37, globals: !38)
!37 = !{}
!38 = !{!0, !16}
!39 = !{i32 2, !"Debug Info Version", i32 3}
!40 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !41, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !36, retainedNodes: !45)
!41 = !DISubroutineType(types: !42)
!42 = !{!35, !43}
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !44, size: 64)
!44 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!45 = !{!46}
!46 = !DILocalVariable(name: "ctx", arg: 1, scope: !40, file: !2, type: !43)
