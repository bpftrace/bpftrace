; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%print_integer_8_t = type <{ i64, i64, [8 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34
@num_cpus = dso_local externally_initialized constant i64 1, section ".rodata", !dbg !51

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !56 {
entry:
  %key = alloca i32, align 4
  %print_integer_8_t = alloca %print_integer_8_t, align 8
  %is_ret_set18 = alloca i64, align 8
  %ret17 = alloca i64, align 8
  %i16 = alloca i32, align 4
  %"@x_key15" = alloca i64, align 8
  %is_ret_set = alloca i64, align 8
  %ret = alloca i64, align 8
  %i = alloca i32, align 4
  %"@x_key11" = alloca i64, align 8
  %"@x_key10" = alloca i64, align 8
  %initial_value8 = alloca i64, align 8
  %lookup_elem_val6 = alloca i64, align 8
  %"@x_key1" = alloca i64, align 8
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %1 = load i64, ptr %lookup_elem, align 8
  %2 = add i64 %1, 1
  store i64 %2, ptr %lookup_elem, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %initial_value)
  store i64 1, ptr %initial_value, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %initial_value, i64 1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %initial_value)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key1")
  store i64 1, ptr %"@x_key1", align 8
  %lookup_elem2 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key1")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val6)
  %map_lookup_cond7 = icmp ne ptr %lookup_elem2, null
  br i1 %map_lookup_cond7, label %lookup_success3, label %lookup_failure4

lookup_success3:                                  ; preds = %lookup_merge
  %3 = load i64, ptr %lookup_elem2, align 8
  %4 = add i64 %3, 2
  store i64 %4, ptr %lookup_elem2, align 8
  br label %lookup_merge5

lookup_failure4:                                  ; preds = %lookup_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %initial_value8)
  store i64 2, ptr %initial_value8, align 8
  %update_elem9 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key1", ptr %initial_value8, i64 1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %initial_value8)
  br label %lookup_merge5

lookup_merge5:                                    ; preds = %lookup_failure4, %lookup_success3
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val6)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key1")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key10")
  store i64 0, ptr %"@x_key10", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key11")
  store i64 0, ptr %"@x_key11", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ret)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %is_ret_set)
  store i32 0, ptr %i, align 4
  store i64 0, ptr %ret, align 8
  store i64 0, ptr %is_ret_set, align 8
  br label %while_cond

if_body:                                          ; preds = %while_end21
  call void @llvm.lifetime.start.p0(i64 -1, ptr %print_integer_8_t)
  %5 = getelementptr %print_integer_8_t, ptr %print_integer_8_t, i64 0, i32 0
  store i64 30007, ptr %5, align 8
  %6 = getelementptr %print_integer_8_t, ptr %print_integer_8_t, i64 0, i32 1
  store i64 0, ptr %6, align 8
  %7 = getelementptr %print_integer_8_t, ptr %print_integer_8_t, i32 0, i32 2
  call void @llvm.memset.p0.i64(ptr align 1 %7, i8 0, i64 8, i1 false)
  store i64 6, ptr %7, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %print_integer_8_t, i64 24, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

if_end:                                           ; preds = %counter_merge, %while_end21
  ret i64 0

while_cond:                                       ; preds = %lookup_success12, %lookup_merge5
  %8 = load i32, ptr @num_cpus, align 4
  %9 = load i32, ptr %i, align 4
  %num_cpu.cmp = icmp ult i32 %9, %8
  br i1 %num_cpu.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %10 = load i32, ptr %i, align 4
  %lookup_percpu_elem = call ptr inttoptr (i64 195 to ptr)(ptr @AT_x, ptr %"@x_key11", i32 %10)
  %map_lookup_cond14 = icmp ne ptr %lookup_percpu_elem, null
  br i1 %map_lookup_cond14, label %lookup_success12, label %lookup_failure13

while_end:                                        ; preds = %error_failure, %error_success, %while_cond
  call void @llvm.lifetime.end.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %is_ret_set)
  %11 = load i64, ptr %ret, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %ret)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key11")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key15")
  store i64 1, ptr %"@x_key15", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %i16)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ret17)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %is_ret_set18)
  store i32 0, ptr %i16, align 4
  store i64 0, ptr %ret17, align 8
  store i64 0, ptr %is_ret_set18, align 8
  br label %while_cond19

lookup_success12:                                 ; preds = %while_body
  %12 = load i64, ptr %ret, align 8
  %13 = load i64, ptr %lookup_percpu_elem, align 8
  %14 = add i64 %13, %12
  store i64 %14, ptr %ret, align 8
  %15 = load i32, ptr %i, align 4
  %16 = add i32 %15, 1
  store i32 %16, ptr %i, align 4
  br label %while_cond

lookup_failure13:                                 ; preds = %while_body
  %17 = load i32, ptr %i, align 4
  %error_lookup_cond = icmp eq i32 %17, 0
  br i1 %error_lookup_cond, label %error_success, label %error_failure

error_success:                                    ; preds = %lookup_failure13
  br label %while_end

error_failure:                                    ; preds = %lookup_failure13
  %18 = load i32, ptr %i, align 4
  br label %while_end

while_cond19:                                     ; preds = %lookup_success24, %while_end
  %19 = load i32, ptr @num_cpus, align 4
  %20 = load i32, ptr %i16, align 4
  %num_cpu.cmp22 = icmp ult i32 %20, %19
  br i1 %num_cpu.cmp22, label %while_body20, label %while_end21

while_body20:                                     ; preds = %while_cond19
  %21 = load i32, ptr %i16, align 4
  %lookup_percpu_elem23 = call ptr inttoptr (i64 195 to ptr)(ptr @AT_x, ptr %"@x_key15", i32 %21)
  %map_lookup_cond26 = icmp ne ptr %lookup_percpu_elem23, null
  br i1 %map_lookup_cond26, label %lookup_success24, label %lookup_failure25

while_end21:                                      ; preds = %error_failure28, %error_success27, %while_cond19
  call void @llvm.lifetime.end.p0(i64 -1, ptr %i16)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %is_ret_set18)
  %22 = load i64, ptr %ret17, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %ret17)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key15")
  %23 = udiv i64 %22, %11
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key10")
  %24 = icmp eq i64 %23, 2
  %25 = zext i1 %24 to i64
  %true_cond = icmp ne i64 %25, 0
  br i1 %true_cond, label %if_body, label %if_end

lookup_success24:                                 ; preds = %while_body20
  %26 = load i64, ptr %ret17, align 8
  %27 = load i64, ptr %lookup_percpu_elem23, align 8
  %28 = add i64 %27, %26
  store i64 %28, ptr %ret17, align 8
  %29 = load i32, ptr %i16, align 4
  %30 = add i32 %29, 1
  store i32 %30, ptr %i16, align 4
  br label %while_cond19

lookup_failure25:                                 ; preds = %while_body20
  %31 = load i32, ptr %i16, align 4
  %error_lookup_cond29 = icmp eq i32 %31, 0
  br i1 %error_lookup_cond29, label %error_success27, label %error_failure28

error_success27:                                  ; preds = %lookup_failure25
  br label %while_end21

error_failure28:                                  ; preds = %lookup_failure25
  %32 = load i32, ptr %i16, align 4
  br label %while_end21

event_loss_counter:                               ; preds = %if_body
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem30 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond34 = icmp ne ptr %lookup_elem30, null
  br i1 %map_lookup_cond34, label %lookup_success31, label %lookup_failure32

counter_merge:                                    ; preds = %lookup_merge33, %if_body
  call void @llvm.lifetime.end.p0(i64 -1, ptr %print_integer_8_t)
  br label %if_end

lookup_success31:                                 ; preds = %event_loss_counter
  %33 = atomicrmw add ptr %lookup_elem30, i64 1 seq_cst, align 8
  br label %lookup_merge33

lookup_failure32:                                 ; preds = %event_loss_counter
  br label %lookup_merge33

lookup_merge33:                                   ; preds = %lookup_failure32, %lookup_success31
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!53}
!llvm.module.flags = !{!55}

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
!51 = !DIGlobalVariableExpression(var: !52, expr: !DIExpression())
!52 = distinct !DIGlobalVariable(name: "num_cpus", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!53 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !54)
!54 = !{!0, !20, !34, !51}
!55 = !{i32 2, !"Debug Info Version", i32 3}
!56 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !57, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !53, retainedNodes: !61)
!57 = !DISubroutineType(types: !58)
!58 = !{!18, !59}
!59 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !60, size: 64)
!60 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!61 = !{!62}
!62 = !DILocalVariable(name: "ctx", arg: 1, scope: !56, file: !2, type: !59)
