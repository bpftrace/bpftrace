; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%ctx_t = type { ptr, ptr }
%print_string_4_t = type <{ i64, i64, [4 x i8] }>
%"unsigned int64_int64__tuple_t" = type { i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_len = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_map = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !33
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !47

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !52 {
entry:
  %"@len_val" = alloca i64, align 8
  %"@len_key" = alloca i64, align 8
  %ctx = alloca %ctx_t, align 8
  %"$var3" = alloca [4 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var3")
  call void @llvm.memset.p0.i64(ptr align 1 %"$var3", i8 0, i64 4, i1 false)
  %str1 = alloca [4 x i8], align 1
  %"$var2" = alloca [4 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var2")
  call void @llvm.memset.p0.i64(ptr align 1 %"$var2", i8 0, i64 4, i1 false)
  %str = alloca [4 x i8], align 1
  %"$var1" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var1")
  store i64 0, ptr %"$var1", align 8
  %"@map_val" = alloca i64, align 8
  %"@map_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@map_key")
  store i64 16, ptr %"@map_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@map_val")
  store i64 32, ptr %"@map_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_map, ptr %"@map_key", ptr %"@map_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@map_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@map_key")
  store i64 123, ptr %"$var1", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %str)
  store [4 x i8] c"abc\00", ptr %str, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %"$var2", ptr align 1 %str, i64 4, i1 false)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %str)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %str1)
  store [4 x i8] c"def\00", ptr %str1, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %"$var3", ptr align 1 %str1, i64 4, i1 false)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %str1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ctx)
  %"ctx.$var1" = getelementptr %ctx_t, ptr %ctx, i64 0, i32 0
  store ptr %"$var1", ptr %"ctx.$var1", align 8
  %"ctx.$var3" = getelementptr %ctx_t, ptr %ctx, i64 0, i32 1
  store ptr %"$var3", ptr %"ctx.$var3", align 8
  %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr @AT_map, ptr @map_for_each_cb, ptr %ctx, i64 0)
  %1 = load i64, ptr %"$var1", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@len_key")
  store i64 0, ptr %"@len_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@len_val")
  store i64 %1, ptr %"@len_val", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_len, ptr %"@len_key", ptr %"@len_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@len_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@len_key")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) section ".text" !dbg !59 {
  %key1 = alloca i32, align 4
  %print_string_4_t = alloca %print_string_4_t, align 8
  %"$kv" = alloca %"unsigned int64_int64__tuple_t", align 8
  %key = load i64, ptr %1, align 8
  %val = load i64, ptr %2, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$kv")
  call void @llvm.memset.p0.i64(ptr align 1 %"$kv", i8 0, i64 16, i1 false)
  %5 = getelementptr %"unsigned int64_int64__tuple_t", ptr %"$kv", i32 0, i32 0
  store i64 %key, ptr %5, align 8
  %6 = getelementptr %"unsigned int64_int64__tuple_t", ptr %"$kv", i32 0, i32 1
  store i64 %val, ptr %6, align 8
  %"ctx.$var1" = getelementptr %ctx_t, ptr %3, i64 0, i32 0
  %"$var1" = load ptr, ptr %"ctx.$var1", align 8
  %"ctx.$var3" = getelementptr %ctx_t, ptr %3, i64 0, i32 1
  %"$var3" = load ptr, ptr %"ctx.$var3", align 8
  %7 = load i64, ptr %"$var1", align 8
  %8 = add i64 %7, 1
  store i64 %8, ptr %"$var1", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %print_string_4_t)
  %9 = getelementptr %print_string_4_t, ptr %print_string_4_t, i64 0, i32 0
  store i64 30007, ptr %9, align 8
  %10 = getelementptr %print_string_4_t, ptr %print_string_4_t, i64 0, i32 1
  store i64 0, ptr %10, align 8
  %11 = getelementptr %print_string_4_t, ptr %print_string_4_t, i32 0, i32 2
  call void @llvm.memset.p0.i64(ptr align 1 %11, i8 0, i64 4, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %11, ptr align 1 %"$var3", i64 4, i1 false)
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %print_string_4_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key1)
  store i32 0, ptr %key1, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key1)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %print_string_4_t)
  ret i64 0

lookup_success:                                   ; preds = %event_loss_counter
  %12 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key1)
  br label %counter_merge
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!49}
!llvm.module.flags = !{!51}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_len", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 2, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 1, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !20, size: 64, offset: 192)
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!21 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "AT_map", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !25)
!25 = !{!26, !27, !32, !19}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !28, size: 64, offset: 64)
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!29 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 131072, elements: !30)
!30 = !{!31}
!31 = !DISubrange(count: 4096, lowerBound: 0)
!32 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !20, size: 64, offset: 128)
!33 = !DIGlobalVariableExpression(var: !34, expr: !DIExpression())
!34 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !35, isLocal: false, isDefinition: true)
!35 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !36)
!36 = !{!37, !42}
!37 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !38, size: 64)
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !39, size: 64)
!39 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !40)
!40 = !{!41}
!41 = !DISubrange(count: 27, lowerBound: 0)
!42 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !43, size: 64, offset: 64)
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !44, size: 64)
!44 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !45)
!45 = !{!46}
!46 = !DISubrange(count: 262144, lowerBound: 0)
!47 = !DIGlobalVariableExpression(var: !48, expr: !DIExpression())
!48 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!49 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !50)
!50 = !{!0, !22, !33, !47}
!51 = !{i32 2, !"Debug Info Version", i32 3}
!52 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !53, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !49, retainedNodes: !57)
!53 = !DISubroutineType(types: !54)
!54 = !{!21, !55}
!55 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !56, size: 64)
!56 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!57 = !{!58}
!58 = !DILocalVariable(name: "ctx", arg: 1, scope: !52, file: !2, type: !55)
!59 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !53, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !49, retainedNodes: !60)
!60 = !{!61}
!61 = !DILocalVariable(name: "ctx", arg: 1, scope: !59, file: !2, type: !55)
