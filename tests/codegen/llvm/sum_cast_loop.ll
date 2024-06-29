; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%print_tuple_16_t = type <{ i64, i64, [16 x i8] }>
%"unsigned int64_sum__tuple_t" = type { i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !55 {
entry:
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 1, i64* %"@x_key", align 8
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key")
  %2 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %3 = load i64, i64* %cast, align 8
  %4 = add i64 %3, 2
  store i64 %4, i64* %cast, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  %5 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 2, i64* %initial_value, align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key", i64* %initial_value, i64 1)
  %6 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %7 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  %8 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %for_each_map_elem = call i64 inttoptr (i64 164 to i64 (%"struct map_t"*, i64 (i8*, i8*, i8*, i8*)*, i8*, i64)*)(%"struct map_t"* @AT_x, i64 (i8*, i8*, i8*, i8*)* @map_for_each_cb, i8* null, i64 0)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

define internal i64 @map_for_each_cb(i8* %0, i8* %1, i8* %2, i8* %3) section ".text" !dbg !62 {
  %key1 = alloca i32, align 4
  %print_tuple_16_t = alloca %print_tuple_16_t, align 8
  %tuple = alloca %"unsigned int64_sum__tuple_t", align 8
  %"$kv" = alloca %"unsigned int64_sum__tuple_t", align 8
  %is_ret_set = alloca i64, align 8
  %ret = alloca i64, align 8
  %i = alloca i32, align 4
  %lookup_key = alloca i64, align 8
  %key = load i64, i8* %1, align 8
  %5 = bitcast i64* %lookup_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 %key, i64* %lookup_key, align 8
  %6 = bitcast i32* %i to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %7 = bitcast i64* %ret to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %8 = bitcast i64* %is_ret_set to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  store i32 0, i32* %i, align 4
  store i64 0, i64* %ret, align 8
  store i64 0, i64* %is_ret_set, align 8
  br label %while_cond

while_cond:                                       ; preds = %lookup_success, %4
  %9 = load i32, i32* %i, align 4
  %num_cpu.cmp = icmp ult i32 %9, 20
  br i1 %num_cpu.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %10 = load i32, i32* %i, align 4
  %lookup_percpu_elem = call i8* inttoptr (i64 195 to i8* (%"struct map_t"*, i64*, i32)*)(%"struct map_t"* @AT_x, i64* %lookup_key, i32 %10)
  %map_lookup_cond = icmp ne i8* %lookup_percpu_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

while_end:                                        ; preds = %error_failure, %error_success, %while_cond
  %11 = bitcast i32* %i to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast i64* %is_ret_set to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  %13 = load i64, i64* %ret, align 8
  %14 = bitcast i64* %ret to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  %15 = bitcast %"unsigned int64_sum__tuple_t"* %"$kv" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  %16 = bitcast %"unsigned int64_sum__tuple_t"* %"$kv" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %16, i8 0, i64 16, i1 false)
  %17 = getelementptr %"unsigned int64_sum__tuple_t", %"unsigned int64_sum__tuple_t"* %"$kv", i32 0, i32 0
  store i64 %key, i64* %17, align 8
  %18 = getelementptr %"unsigned int64_sum__tuple_t", %"unsigned int64_sum__tuple_t"* %"$kv", i32 0, i32 1
  store i64 %13, i64* %18, align 8
  %19 = getelementptr %"unsigned int64_sum__tuple_t", %"unsigned int64_sum__tuple_t"* %"$kv", i32 0, i32 0
  %20 = load i64, i64* %19, align 8
  %21 = getelementptr %"unsigned int64_sum__tuple_t", %"unsigned int64_sum__tuple_t"* %"$kv", i32 0, i32 1
  %22 = load i64, i64* %21, align 8
  %23 = bitcast %"unsigned int64_sum__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  %24 = bitcast %"unsigned int64_sum__tuple_t"* %tuple to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %24, i8 0, i64 16, i1 false)
  %25 = getelementptr %"unsigned int64_sum__tuple_t", %"unsigned int64_sum__tuple_t"* %tuple, i32 0, i32 0
  store i64 %20, i64* %25, align 8
  %26 = getelementptr %"unsigned int64_sum__tuple_t", %"unsigned int64_sum__tuple_t"* %tuple, i32 0, i32 1
  store i64 %22, i64* %26, align 8
  %27 = bitcast %print_tuple_16_t* %print_tuple_16_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %27)
  %28 = getelementptr %print_tuple_16_t, %print_tuple_16_t* %print_tuple_16_t, i64 0, i32 0
  store i64 30007, i64* %28, align 8
  %29 = getelementptr %print_tuple_16_t, %print_tuple_16_t* %print_tuple_16_t, i64 0, i32 1
  store i64 0, i64* %29, align 8
  %30 = getelementptr %print_tuple_16_t, %print_tuple_16_t* %print_tuple_16_t, i32 0, i32 2
  %31 = bitcast [16 x i8]* %30 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %31, i8 0, i64 16, i1 false)
  %32 = bitcast [16 x i8]* %30 to i8*
  %33 = bitcast %"unsigned int64_sum__tuple_t"* %tuple to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %32, i8* align 1 %33, i64 16, i1 false)
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, %print_tuple_16_t*, i64, i64)*)(%"struct map_t.0"* @ringbuf, %print_tuple_16_t* %print_tuple_16_t, i64 32, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

lookup_success:                                   ; preds = %while_body
  %cast = bitcast i8* %lookup_percpu_elem to i64*
  %34 = load i64, i64* %ret, align 8
  %35 = load i64, i64* %cast, align 8
  %36 = add i64 %35, %34
  store i64 %36, i64* %ret, align 8
  %37 = load i32, i32* %i, align 4
  %38 = add i32 %37, 1
  store i32 %38, i32* %i, align 4
  br label %while_cond

lookup_failure:                                   ; preds = %while_body
  %39 = load i32, i32* %i, align 4
  %error_lookup_cond = icmp eq i32 %39, 0
  br i1 %error_lookup_cond, label %error_success, label %error_failure

error_success:                                    ; preds = %lookup_failure
  br label %while_end

error_failure:                                    ; preds = %lookup_failure
  %40 = load i32, i32* %i, align 4
  br label %while_end

event_loss_counter:                               ; preds = %while_end
  %41 = bitcast i32* %key1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %41)
  store i32 0, i32* %key1, align 4
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key1)
  %map_lookup_cond4 = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond4, label %lookup_success2, label %lookup_failure3

counter_merge:                                    ; preds = %lookup_merge, %while_end
  %42 = bitcast %print_tuple_16_t* %print_tuple_16_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %42)
  %43 = bitcast %"unsigned int64_sum__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %43)
  ret i64 0

lookup_success2:                                  ; preds = %event_loss_counter
  %44 = bitcast i8* %lookup_elem to i64*
  %45 = atomicrmw add i64* %44, i64 1 seq_cst
  br label %lookup_merge

lookup_failure3:                                  ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure3, %lookup_success2
  %46 = bitcast i32* %key1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %46)
  br label %counter_merge
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!51}
!llvm.module.flags = !{!54}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 160, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 5, lowerBound: 0)
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
!21 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !22, isLocal: false, isDefinition: true)
!22 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !23)
!23 = !{!24, !29}
!24 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !25, size: 64)
!25 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !26, size: 64)
!26 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !27)
!27 = !{!28}
!28 = !DISubrange(count: 27, lowerBound: 0)
!29 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !30, size: 64, offset: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 262144, lowerBound: 0)
!34 = !DIGlobalVariableExpression(var: !35, expr: !DIExpression())
!35 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!36 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !37)
!37 = !{!38, !43, !48, !19}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !39, size: 64)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 2, lowerBound: 0)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !44, size: 64, offset: 64)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 1, lowerBound: 0)
!48 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !49, size: 64, offset: 128)
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!50 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!51 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !52, globals: !53)
!52 = !{}
!53 = !{!0, !20, !34}
!54 = !{i32 2, !"Debug Info Version", i32 3}
!55 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !51, retainedNodes: !60)
!56 = !DISubroutineType(types: !57)
!57 = !{!18, !58}
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!59 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!60 = !{!61}
!61 = !DILocalVariable(name: "ctx", arg: 1, scope: !55, file: !2, type: !58)
!62 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !51, retainedNodes: !63)
!63 = !{!64}
!64 = !DILocalVariable(name: "ctx", arg: 1, scope: !62, file: !2, type: !58)
