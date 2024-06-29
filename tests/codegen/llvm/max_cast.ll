; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%print_integer_8_t = type <{ i64, i64, [8 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !55 {
entry:
  %key = alloca i32, align 4
  %print_integer_8_t = alloca %print_integer_8_t, align 8
  %i = alloca i32, align 4
  %ret_2 = alloca i64, align 8
  %ret_1 = alloca i64, align 8
  %"@x_key7" = alloca i64, align 8
  %"@x_key6" = alloca i64, align 8
  %"@x_key5" = alloca i64, align 8
  %initial_value3 = alloca i64, align 8
  %initial_value = alloca i64, align 8
  %"@x_key1" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 1, i64* %"@x_key", align 8
  %2 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"@x_key1", align 8
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key1")
  %lookup_elem2 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key")
  %mm_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %mm_lookup_cond, label %mm_lookup_success, label %lookup_failure

mm_lookup_success:                                ; preds = %entry
  %is_set_lookup_cond = icmp ne i8* %lookup_elem2, null
  br i1 %is_set_lookup_cond, label %is_set_lookup_success, label %lookup_failure

is_set_lookup_success:                            ; preds = %mm_lookup_success
  %is_set_cast = bitcast i8* %lookup_elem2 to i64*
  %mm_cast = bitcast i8* %lookup_elem to i64*
  %3 = load i64, i64* %is_set_cast, align 8
  %is_set_cond = icmp eq i64 %3, 1
  br i1 %is_set_cond, label %is_set, label %min_max

lookup_failure:                                   ; preds = %mm_lookup_success, %entry
  %4 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i64 2, i64* %initial_value, align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key1", i64* %initial_value, i64 1)
  %5 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = bitcast i64* %initial_value3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  store i64 1, i64* %initial_value3, align 8
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key", i64* %initial_value3, i64 1)
  %7 = bitcast i64* %initial_value3 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %min_max, %is_set
  %8 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %"@x_key5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 0, i64* %"@x_key5", align 8
  %11 = bitcast i64* %"@x_key6" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i64 0, i64* %"@x_key6", align 8
  %12 = bitcast i64* %"@x_key7" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  store i64 1, i64* %"@x_key7", align 8
  %13 = bitcast i64* %ret_1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  %14 = bitcast i64* %ret_2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  %15 = bitcast i32* %i to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  store i32 0, i32* %i, align 4
  store i64 0, i64* %ret_1, align 8
  store i64 0, i64* %ret_2, align 8
  br label %while_cond

is_set:                                           ; preds = %is_set_lookup_success
  %16 = load i64, i64* %mm_cast, align 8
  %17 = icmp sge i64 2, %16
  br i1 %17, label %min_max, label %lookup_merge

min_max:                                          ; preds = %is_set, %is_set_lookup_success
  store i64 2, i64* %mm_cast, align 8
  store i64 1, i64* %is_set_cast, align 8
  br label %lookup_merge

if_body:                                          ; preds = %while_end
  %18 = bitcast %print_integer_8_t* %print_integer_8_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  %19 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 0
  store i64 30007, i64* %19, align 8
  %20 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 1
  store i64 0, i64* %20, align 8
  %21 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i32 0, i32 2
  %22 = bitcast [8 x i8]* %21 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %22, i8 0, i64 8, i1 false)
  %23 = bitcast [8 x i8]* %21 to i64*
  store i64 6, i64* %23, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, %print_integer_8_t*, i64, i64)*)(%"struct map_t.0"* @ringbuf, %print_integer_8_t* %print_integer_8_t, i64 24, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

if_end:                                           ; preds = %counter_merge, %while_end
  ret i64 0

while_cond:                                       ; preds = %min_max_merge, %lookup_merge
  %24 = load i32, i32* %i, align 4
  %num_cpu.cmp = icmp ult i32 %24, 20
  br i1 %num_cpu.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %25 = load i32, i32* %i, align 4
  %lookup_percpu_elem = call i8* inttoptr (i64 195 to i8* (%"struct map_t"*, i64*, i32)*)(%"struct map_t"* @AT_x, i64* %"@x_key6", i32 %25)
  %26 = load i32, i32* %i, align 4
  %lookup_percpu_elem8 = call i8* inttoptr (i64 195 to i8* (%"struct map_t"*, i64*, i32)*)(%"struct map_t"* @AT_x, i64* %"@x_key7", i32 %26)
  %null_check_1 = icmp ne i8* %lookup_percpu_elem, null
  %null_check_2 = icmp ne i8* %lookup_percpu_elem8, null
  br i1 %null_check_1, label %lookup_success_1, label %lookup_failure9

while_end:                                        ; preds = %error_failure, %error_success, %while_cond
  %27 = bitcast i32* %i to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %27)
  %28 = load i64, i64* %ret_1, align 8
  %29 = bitcast i64* %ret_1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %29)
  %30 = bitcast i64* %ret_2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %30)
  %31 = bitcast i64* %"@x_key5" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = icmp sgt i64 %28, 5
  %33 = zext i1 %32 to i64
  %true_cond = icmp ne i64 %33, 0
  br i1 %true_cond, label %if_body, label %if_end

lookup_success_1:                                 ; preds = %while_body
  br i1 %null_check_2, label %lookup_success_2, label %lookup_failure9

lookup_success_2:                                 ; preds = %lookup_success_1
  %cast_1 = bitcast i8* %lookup_percpu_elem to i64*
  %cast_2 = bitcast i8* %lookup_percpu_elem8 to i64*
  %34 = load i64, i64* %cast_2, align 8
  %val_set_cond = icmp eq i64 %34, 1
  %35 = load i64, i64* %ret_2, align 8
  %ret_set_cond = icmp eq i64 %35, 1
  %36 = load i64, i64* %ret_1, align 8
  %37 = load i64, i64* %cast_1, align 8
  %max_cond = icmp sgt i64 %37, %36
  br i1 %val_set_cond, label %val_set_success, label %min_max_merge

lookup_failure9:                                  ; preds = %lookup_success_1, %while_body
  %38 = load i32, i32* %i, align 4
  %error_lookup_cond = icmp eq i32 %38, 0
  br i1 %error_lookup_cond, label %error_success, label %error_failure

val_set_success:                                  ; preds = %lookup_success_2
  br i1 %ret_set_cond, label %ret_set_success, label %min_max_success

min_max_success:                                  ; preds = %ret_set_success, %val_set_success
  %39 = load i64, i64* %cast_1, align 8
  store i64 %39, i64* %ret_1, align 8
  store i64 1, i64* %ret_2, align 8
  br label %min_max_merge

ret_set_success:                                  ; preds = %val_set_success
  br i1 %max_cond, label %min_max_success, label %min_max_merge

min_max_merge:                                    ; preds = %min_max_success, %ret_set_success, %lookup_success_2
  %40 = load i32, i32* %i, align 4
  %41 = add i32 %40, 1
  store i32 %41, i32* %i, align 4
  br label %while_cond

error_success:                                    ; preds = %lookup_failure9
  br label %while_end

error_failure:                                    ; preds = %lookup_failure9
  %42 = load i32, i32* %i, align 4
  br label %while_end

event_loss_counter:                               ; preds = %if_body
  %43 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %43)
  store i32 0, i32* %key, align 4
  %lookup_elem10 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem10, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure11

counter_merge:                                    ; preds = %lookup_merge12, %if_body
  %44 = bitcast %print_integer_8_t* %print_integer_8_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %44)
  br label %if_end

lookup_success:                                   ; preds = %event_loss_counter
  %45 = bitcast i8* %lookup_elem10 to i64*
  %46 = atomicrmw add i64* %45, i64 1 seq_cst
  br label %lookup_merge12

lookup_failure11:                                 ; preds = %event_loss_counter
  br label %lookup_merge12

lookup_merge12:                                   ; preds = %lookup_failure11, %lookup_success
  %47 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %47)
  br label %counter_merge
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

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
