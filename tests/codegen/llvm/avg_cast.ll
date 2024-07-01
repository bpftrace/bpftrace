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
  %"@x_key13" = alloca i64, align 8
  %"@x_key12" = alloca i64, align 8
  %"@x_key11" = alloca i64, align 8
  %initial_value9 = alloca i64, align 8
  %lookup_elem_val6 = alloca i64, align 8
  %"@x_key1" = alloca i64, align 8
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@x_key", align 8
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key")
  %2 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %3 = load i64, i64* %cast, align 8
  %4 = add i64 %3, 1
  store i64 %4, i64* %cast, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  %5 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 1, i64* %initial_value, align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key", i64* %initial_value, i64 1)
  %6 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %7 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  %8 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i64 1, i64* %"@x_key1", align 8
  %lookup_elem2 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key1")
  %10 = bitcast i64* %lookup_elem_val6 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  %map_lookup_cond7 = icmp ne i8* %lookup_elem2, null
  br i1 %map_lookup_cond7, label %lookup_success3, label %lookup_failure4

lookup_success3:                                  ; preds = %lookup_merge
  %cast8 = bitcast i8* %lookup_elem2 to i64*
  %11 = load i64, i64* %cast8, align 8
  %12 = add i64 %11, 2
  store i64 %12, i64* %cast8, align 8
  br label %lookup_merge5

lookup_failure4:                                  ; preds = %lookup_merge
  %13 = bitcast i64* %initial_value9 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i64 2, i64* %initial_value9, align 8
  %update_elem10 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key1", i64* %initial_value9, i64 1)
  %14 = bitcast i64* %initial_value9 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  br label %lookup_merge5

lookup_merge5:                                    ; preds = %lookup_failure4, %lookup_success3
  %15 = bitcast i64* %lookup_elem_val6 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast i64* %"@x_key11" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  store i64 0, i64* %"@x_key11", align 8
  %18 = bitcast i64* %"@x_key12" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i64 0, i64* %"@x_key12", align 8
  %19 = bitcast i64* %"@x_key13" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  store i64 1, i64* %"@x_key13", align 8
  %20 = bitcast i64* %ret_1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %20)
  %21 = bitcast i64* %ret_2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  %22 = bitcast i32* %i to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %22)
  store i32 0, i32* %i, align 4
  store i64 0, i64* %ret_1, align 8
  store i64 0, i64* %ret_2, align 8
  br label %while_cond

if_body:                                          ; preds = %while_end
  %23 = bitcast %print_integer_8_t* %print_integer_8_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  %24 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 0
  store i64 30007, i64* %24, align 8
  %25 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 1
  store i64 0, i64* %25, align 8
  %26 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i32 0, i32 2
  %27 = bitcast [8 x i8]* %26 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %27, i8 0, i64 8, i1 false)
  %28 = bitcast [8 x i8]* %26 to i64*
  store i64 6, i64* %28, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, %print_integer_8_t*, i64, i64)*)(%"struct map_t.0"* @ringbuf, %print_integer_8_t* %print_integer_8_t, i64 24, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

if_end:                                           ; preds = %counter_merge, %while_end
  ret i64 0

while_cond:                                       ; preds = %lookup_success_2, %lookup_merge5
  %29 = load i32, i32* %i, align 4
  %num_cpu.cmp = icmp ult i32 %29, 20
  br i1 %num_cpu.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %30 = load i32, i32* %i, align 4
  %lookup_percpu_elem = call i8* inttoptr (i64 195 to i8* (%"struct map_t"*, i64*, i32)*)(%"struct map_t"* @AT_x, i64* %"@x_key12", i32 %30)
  %31 = load i32, i32* %i, align 4
  %lookup_percpu_elem14 = call i8* inttoptr (i64 195 to i8* (%"struct map_t"*, i64*, i32)*)(%"struct map_t"* @AT_x, i64* %"@x_key13", i32 %31)
  %null_check_1 = icmp ne i8* %lookup_percpu_elem, null
  %null_check_2 = icmp ne i8* %lookup_percpu_elem14, null
  br i1 %null_check_1, label %lookup_success_1, label %lookup_failure15

while_end:                                        ; preds = %error_failure, %error_success, %while_cond
  %32 = bitcast i32* %i to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %32)
  %33 = load i64, i64* %ret_1, align 8
  %34 = load i64, i64* %ret_2, align 8
  %35 = udiv i64 %34, %33
  %36 = bitcast i64* %ret_1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %36)
  %37 = bitcast i64* %ret_2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %37)
  %38 = bitcast i64* %"@x_key11" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %38)
  %39 = icmp eq i64 %35, 2
  %40 = zext i1 %39 to i64
  %true_cond = icmp ne i64 %40, 0
  br i1 %true_cond, label %if_body, label %if_end

lookup_success_1:                                 ; preds = %while_body
  br i1 %null_check_2, label %lookup_success_2, label %lookup_failure15

lookup_success_2:                                 ; preds = %lookup_success_1
  %cast_1 = bitcast i8* %lookup_percpu_elem to i64*
  %cast_2 = bitcast i8* %lookup_percpu_elem14 to i64*
  %41 = load i64, i64* %ret_1, align 8
  %42 = load i64, i64* %cast_1, align 8
  %43 = add i64 %42, %41
  store i64 %43, i64* %ret_1, align 8
  %44 = load i64, i64* %ret_2, align 8
  %45 = load i64, i64* %cast_2, align 8
  %46 = add i64 %45, %44
  store i64 %46, i64* %ret_2, align 8
  %47 = load i32, i32* %i, align 4
  %48 = add i32 %47, 1
  store i32 %48, i32* %i, align 4
  br label %while_cond

lookup_failure15:                                 ; preds = %lookup_success_1, %while_body
  %49 = load i32, i32* %i, align 4
  %error_lookup_cond = icmp eq i32 %49, 0
  br i1 %error_lookup_cond, label %error_success, label %error_failure

error_success:                                    ; preds = %lookup_failure15
  br label %while_end

error_failure:                                    ; preds = %lookup_failure15
  %50 = load i32, i32* %i, align 4
  br label %while_end

event_loss_counter:                               ; preds = %if_body
  %51 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %51)
  store i32 0, i32* %key, align 4
  %lookup_elem16 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key)
  %map_lookup_cond20 = icmp ne i8* %lookup_elem16, null
  br i1 %map_lookup_cond20, label %lookup_success17, label %lookup_failure18

counter_merge:                                    ; preds = %lookup_merge19, %if_body
  %52 = bitcast %print_integer_8_t* %print_integer_8_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %52)
  br label %if_end

lookup_success17:                                 ; preds = %event_loss_counter
  %53 = bitcast i8* %lookup_elem16 to i64*
  %54 = atomicrmw add i64* %53, i64 1 seq_cst
  br label %lookup_merge19

lookup_failure18:                                 ; preds = %event_loss_counter
  br label %lookup_merge19

lookup_merge19:                                   ; preds = %lookup_failure18, %lookup_success17
  %55 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %55)
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
