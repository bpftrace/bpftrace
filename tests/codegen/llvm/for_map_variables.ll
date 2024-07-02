; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }
%"struct map_t.1" = type { i8*, i8* }
%"struct map_t.2" = type { i8*, i8*, i8*, i8* }
%ctx_t = type { i64*, i64* }
%print_string_4_t = type <{ i64, i64, [4 x i8] }>
%"unsigned int64_int64__tuple_t" = type { i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_len = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_map = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !22
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !36

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(i8* %0) section "s_BEGIN_1" !dbg !53 {
entry:
  %"@len_val" = alloca i64, align 8
  %"@len_key" = alloca i64, align 8
  %ctx = alloca %ctx_t, align 8
  %"$var3" = alloca [4 x i8], align 1
  %1 = bitcast [4 x i8]* %"$var3" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [4 x i8]* %"$var3" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 4, i1 false)
  %str1 = alloca [4 x i8], align 1
  %"$var2" = alloca [4 x i8], align 1
  %3 = bitcast [4 x i8]* %"$var2" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = bitcast [4 x i8]* %"$var2" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %4, i8 0, i64 4, i1 false)
  %str = alloca [4 x i8], align 1
  %"$var1" = alloca i64, align 8
  %5 = bitcast i64* %"$var1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 0, i64* %"$var1", align 8
  %"@map_val" = alloca i64, align 8
  %"@map_key" = alloca i64, align 8
  %6 = bitcast i64* %"@map_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  store i64 16, i64* %"@map_key", align 8
  %7 = bitcast i64* %"@map_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 32, i64* %"@map_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t.0"*, i64*, i64*, i64)*)(%"struct map_t.0"* @AT_map, i64* %"@map_key", i64* %"@map_val", i64 0)
  %8 = bitcast i64* %"@map_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast i64* %"@map_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  store i64 123, i64* %"$var1", align 8
  %10 = bitcast [4 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store [4 x i8] c"abc\00", [4 x i8]* %str, align 1
  %11 = bitcast [4 x i8]* %"$var2" to i8*
  %12 = bitcast [4 x i8]* %str to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %11, i8* align 1 %12, i64 4, i1 false)
  %13 = bitcast [4 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  %14 = bitcast [4 x i8]* %str1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store [4 x i8] c"def\00", [4 x i8]* %str1, align 1
  %15 = bitcast [4 x i8]* %"$var3" to i8*
  %16 = bitcast [4 x i8]* %str1 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %15, i8* align 1 %16, i64 4, i1 false)
  %17 = bitcast [4 x i8]* %str1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  %18 = bitcast %ctx_t* %ctx to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  %"ctx.$var1" = getelementptr %ctx_t, %ctx_t* %ctx, i64 0, i32 0
  store i64* %"$var1", i64** %"ctx.$var1", align 8
  %"ctx.$var3" = getelementptr %ctx_t, %ctx_t* %ctx, i64 0, i32 1
  %19 = bitcast i64** %"ctx.$var3" to [4 x i8]**
  store [4 x i8]* %"$var3", [4 x i8]** %19, align 8
  %20 = bitcast %ctx_t* %ctx to i8*
  %for_each_map_elem = call i64 inttoptr (i64 164 to i64 (%"struct map_t.0"*, i64 (i8*, i8*, i8*, %ctx_t*)*, i8*, i64)*)(%"struct map_t.0"* @AT_map, i64 (i8*, i8*, i8*, %ctx_t*)* @map_for_each_cb, i8* %20, i64 0)
  %21 = load i64, i64* %"$var1", align 8
  %22 = bitcast i64* %"@len_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %22)
  store i64 0, i64* %"@len_key", align 8
  %23 = bitcast i64* %"@len_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  store i64 %21, i64* %"@len_val", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_len, i64* %"@len_key", i64* %"@len_val", i64 0)
  %24 = bitcast i64* %"@len_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  %25 = bitcast i64* %"@len_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %25)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) #1

define internal i64 @map_for_each_cb(i8* %0, i8* %1, i8* %2, %ctx_t* %3) section ".text" !dbg !60 {
  %key1 = alloca i32, align 4
  %print_string_4_t = alloca %print_string_4_t, align 8
  %"$kv" = alloca %"unsigned int64_int64__tuple_t", align 8
  %key = load i64, i8* %1, align 8
  %val = load i64, i8* %2, align 8
  %5 = bitcast %"unsigned int64_int64__tuple_t"* %"$kv" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast %"unsigned int64_int64__tuple_t"* %"$kv" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %6, i8 0, i64 16, i1 false)
  %7 = getelementptr %"unsigned int64_int64__tuple_t", %"unsigned int64_int64__tuple_t"* %"$kv", i32 0, i32 0
  store i64 %key, i64* %7, align 8
  %8 = getelementptr %"unsigned int64_int64__tuple_t", %"unsigned int64_int64__tuple_t"* %"$kv", i32 0, i32 1
  store i64 %val, i64* %8, align 8
  %"ctx.$var1" = getelementptr %ctx_t, %ctx_t* %3, i64 0, i32 0
  %"$var1" = load i64*, i64** %"ctx.$var1", align 8
  %"ctx.$var3" = getelementptr %ctx_t, %ctx_t* %3, i64 0, i32 1
  %"$var3" = load [4 x i8]*, i64** %"ctx.$var3", align 8
  %9 = load i64, i64* %"$var1", align 8
  %10 = add i64 %9, 1
  store i64 %10, i64* %"$var1", align 8
  %11 = bitcast %print_string_4_t* %print_string_4_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  %12 = getelementptr %print_string_4_t, %print_string_4_t* %print_string_4_t, i64 0, i32 0
  store i64 30007, i64* %12, align 8
  %13 = getelementptr %print_string_4_t, %print_string_4_t* %print_string_4_t, i64 0, i32 1
  store i64 0, i64* %13, align 8
  %14 = getelementptr %print_string_4_t, %print_string_4_t* %print_string_4_t, i32 0, i32 2
  %15 = bitcast [4 x i8]* %14 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %15, i8 0, i64 4, i1 false)
  %16 = bitcast [4 x i8]* %14 to i8*
  %17 = bitcast [4 x i8]* %"$var3" to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %16, i8* align 1 %17, i64 4, i1 false)
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t.1"*, %print_string_4_t*, i64, i64)*)(%"struct map_t.1"* @ringbuf, %print_string_4_t* %print_string_4_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %4
  %18 = bitcast i32* %key1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i32 0, i32* %key1, align 4
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t.2"*, i32*)*)(%"struct map_t.2"* @event_loss_counter, i32* %key1)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %4
  %19 = bitcast %print_string_4_t* %print_string_4_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  ret i64 0

lookup_success:                                   ; preds = %event_loss_counter
  %20 = bitcast i8* %lookup_elem to i64*
  %21 = atomicrmw add i64* %20, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %22 = bitcast i32* %key1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  br label %counter_merge
}

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!49}
!llvm.module.flags = !{!52}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_len", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 131072, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 4096, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!20 = !DIGlobalVariableExpression(var: !21, expr: !DIExpression())
!21 = distinct !DIGlobalVariable(name: "AT_map", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !25)
!25 = !{!26, !31}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 27, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !32, size: 64, offset: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 262144, lowerBound: 0)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !39)
!39 = !{!40, !45, !46, !19}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 2, lowerBound: 0)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!46 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !47, size: 64, offset: 128)
!47 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !48, size: 64)
!48 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!49 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !50, globals: !51)
!50 = !{}
!51 = !{!0, !20, !22, !36}
!52 = !{i32 2, !"Debug Info Version", i32 3}
!53 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !54, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !49, retainedNodes: !58)
!54 = !DISubroutineType(types: !55)
!55 = !{!18, !56}
!56 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !57, size: 64)
!57 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!58 = !{!59}
!59 = !DILocalVariable(name: "ctx", arg: 1, scope: !53, file: !2, type: !56)
!60 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !54, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !49, retainedNodes: !61)
!61 = !{!62}
!62 = !DILocalVariable(name: "ctx", arg: 1, scope: !60, file: !2, type: !56)
