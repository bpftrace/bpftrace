; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%min_max_val = type { i64, i64 }
%print_tuple_16_t = type <{ i64, i64, [16 x i8] }>
%"unsigned int64_max__tuple_t" = type { i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !26
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !40

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !61 {
entry:
  %mm_struct = alloca %min_max_val, align 8
  %"@x_key" = alloca i64, align 8
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 1, i64* %"@x_key", align 8
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key")
  %lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to %min_max_val*
  %2 = getelementptr %min_max_val, %min_max_val* %cast, i64 0, i32 0
  %3 = load i64, i64* %2, align 8
  %4 = getelementptr %min_max_val, %min_max_val* %cast, i64 0, i32 1
  %5 = load i64, i64* %4, align 8
  %is_set_cond = icmp eq i64 %5, 1
  br i1 %is_set_cond, label %is_set, label %min_max

lookup_failure:                                   ; preds = %entry
  %6 = bitcast %min_max_val* %mm_struct to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %7 = getelementptr %min_max_val, %min_max_val* %mm_struct, i64 0, i32 0
  store i64 2, i64* %7, align 8
  %8 = getelementptr %min_max_val, %min_max_val* %mm_struct, i64 0, i32 1
  store i64 1, i64* %8, align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, %min_max_val*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key", %min_max_val* %mm_struct, i64 0)
  %9 = bitcast %min_max_val* %mm_struct to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %min_max, %is_set
  %10 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %for_each_map_elem = call i64 inttoptr (i64 164 to i64 (%"struct map_t"*, i64 (i8*, i8*, i8*, i8*)*, i8*, i64)*)(%"struct map_t"* @AT_x, i64 (i8*, i8*, i8*, i8*)* @map_for_each_cb, i8* null, i64 0)
  ret i64 0

is_set:                                           ; preds = %lookup_success
  %11 = icmp sge i64 2, %3
  br i1 %11, label %min_max, label %lookup_merge

min_max:                                          ; preds = %is_set, %lookup_success
  %12 = getelementptr %min_max_val, %min_max_val* %cast, i64 0, i32 0
  store i64 2, i64* %12, align 8
  %13 = getelementptr %min_max_val, %min_max_val* %cast, i64 0, i32 1
  store i64 1, i64* %13, align 8
  br label %lookup_merge
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

define internal i64 @map_for_each_cb(i8* %0, i8* %1, i8* %2, i8* %3) section ".text" !dbg !68 {
  %key1 = alloca i32, align 4
  %print_tuple_16_t = alloca %print_tuple_16_t, align 8
  %tuple = alloca %"unsigned int64_max__tuple_t", align 8
  %"$kv" = alloca %"unsigned int64_max__tuple_t", align 8
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

while_cond:                                       ; preds = %min_max_merge, %4
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
  %15 = bitcast %"unsigned int64_max__tuple_t"* %"$kv" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  %16 = bitcast %"unsigned int64_max__tuple_t"* %"$kv" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %16, i8 0, i64 16, i1 false)
  %17 = getelementptr %"unsigned int64_max__tuple_t", %"unsigned int64_max__tuple_t"* %"$kv", i32 0, i32 0
  store i64 %key, i64* %17, align 8
  %18 = getelementptr %"unsigned int64_max__tuple_t", %"unsigned int64_max__tuple_t"* %"$kv", i32 0, i32 1
  store i64 %13, i64* %18, align 8
  %19 = getelementptr %"unsigned int64_max__tuple_t", %"unsigned int64_max__tuple_t"* %"$kv", i32 0, i32 0
  %20 = load i64, i64* %19, align 8
  %21 = getelementptr %"unsigned int64_max__tuple_t", %"unsigned int64_max__tuple_t"* %"$kv", i32 0, i32 1
  %22 = load i64, i64* %21, align 8
  %23 = bitcast %"unsigned int64_max__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  %24 = bitcast %"unsigned int64_max__tuple_t"* %tuple to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %24, i8 0, i64 16, i1 false)
  %25 = getelementptr %"unsigned int64_max__tuple_t", %"unsigned int64_max__tuple_t"* %tuple, i32 0, i32 0
  store i64 %20, i64* %25, align 8
  %26 = getelementptr %"unsigned int64_max__tuple_t", %"unsigned int64_max__tuple_t"* %tuple, i32 0, i32 1
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
  %33 = bitcast %"unsigned int64_max__tuple_t"* %tuple to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %32, i8* align 1 %33, i64 16, i1 false)
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, %print_tuple_16_t*, i64, i64)*)(%"struct map_t.0"* @ringbuf, %print_tuple_16_t* %print_tuple_16_t, i64 32, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

lookup_success:                                   ; preds = %while_body
  %cast = bitcast i8* %lookup_percpu_elem to %min_max_val*
  %34 = getelementptr %min_max_val, %min_max_val* %cast, i64 0, i32 0
  %35 = load i64, i64* %34, align 8
  %36 = getelementptr %min_max_val, %min_max_val* %cast, i64 0, i32 1
  %37 = load i64, i64* %36, align 8
  %val_set_cond = icmp eq i64 %37, 1
  %38 = load i64, i64* %is_ret_set, align 8
  %ret_set_cond = icmp eq i64 %38, 1
  %39 = load i64, i64* %ret, align 8
  %max_cond = icmp sgt i64 %35, %39
  br i1 %val_set_cond, label %val_set_success, label %min_max_merge

lookup_failure:                                   ; preds = %while_body
  %40 = load i32, i32* %i, align 4
  %error_lookup_cond = icmp eq i32 %40, 0
  br i1 %error_lookup_cond, label %error_success, label %error_failure

val_set_success:                                  ; preds = %lookup_success
  br i1 %ret_set_cond, label %ret_set_success, label %min_max_success

min_max_success:                                  ; preds = %ret_set_success, %val_set_success
  store i64 %35, i64* %ret, align 8
  store i64 1, i64* %is_ret_set, align 8
  br label %min_max_merge

ret_set_success:                                  ; preds = %val_set_success
  br i1 %max_cond, label %min_max_success, label %min_max_merge

min_max_merge:                                    ; preds = %min_max_success, %ret_set_success, %lookup_success
  %41 = load i32, i32* %i, align 4
  %42 = add i32 %41, 1
  store i32 %42, i32* %i, align 4
  br label %while_cond

error_success:                                    ; preds = %lookup_failure
  br label %while_end

error_failure:                                    ; preds = %lookup_failure
  %43 = load i32, i32* %i, align 4
  br label %while_end

event_loss_counter:                               ; preds = %while_end
  %44 = bitcast i32* %key1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %44)
  store i32 0, i32* %key1, align 4
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key1)
  %map_lookup_cond4 = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond4, label %lookup_success2, label %lookup_failure3

counter_merge:                                    ; preds = %lookup_merge, %while_end
  %45 = bitcast %print_tuple_16_t* %print_tuple_16_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %45)
  %46 = bitcast %"unsigned int64_max__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %46)
  ret i64 0

lookup_success2:                                  ; preds = %event_loss_counter
  %47 = bitcast i8* %lookup_elem to i64*
  %48 = atomicrmw add i64* %47, i64 1 seq_cst
  br label %lookup_merge

lookup_failure3:                                  ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure3, %lookup_success2
  %49 = bitcast i32* %key1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %49)
  br label %counter_merge
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!57}
!llvm.module.flags = !{!60}

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
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !20, size: 64, offset: 192)
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!21 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !22)
!22 = !{!23, !24}
!23 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !18, size: 64)
!24 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !25, size: 64, offset: 64)
!25 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!26 = !DIGlobalVariableExpression(var: !27, expr: !DIExpression())
!27 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !28, isLocal: false, isDefinition: true)
!28 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !29)
!29 = !{!30, !35}
!30 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !31, size: 64)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !33)
!33 = !{!34}
!34 = !DISubrange(count: 27, lowerBound: 0)
!35 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !36, size: 64, offset: 64)
!36 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !37, size: 64)
!37 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !38)
!38 = !{!39}
!39 = !DISubrange(count: 262144, lowerBound: 0)
!40 = !DIGlobalVariableExpression(var: !41, expr: !DIExpression())
!41 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !42, isLocal: false, isDefinition: true)
!42 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !43)
!43 = !{!44, !49, !54, !56}
!44 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !45, size: 64)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !47)
!47 = !{!48}
!48 = !DISubrange(count: 2, lowerBound: 0)
!49 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !50, size: 64, offset: 64)
!50 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !51, size: 64)
!51 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !52)
!52 = !{!53}
!53 = !DISubrange(count: 1, lowerBound: 0)
!54 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !55, size: 64, offset: 128)
!55 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !25, size: 64)
!56 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!57 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !58, globals: !59)
!58 = !{}
!59 = !{!0, !26, !40}
!60 = !{i32 2, !"Debug Info Version", i32 3}
!61 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !62, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !57, retainedNodes: !66)
!62 = !DISubroutineType(types: !63)
!63 = !{!18, !64}
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !65, size: 64)
!65 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!66 = !{!67}
!67 = !DILocalVariable(name: "ctx", arg: 1, scope: !61, file: !2, type: !64)
!68 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !62, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !57, retainedNodes: !69)
!69 = !{!70}
!70 = !DILocalVariable(name: "ctx", arg: 1, scope: !68, file: !2, type: !64)
