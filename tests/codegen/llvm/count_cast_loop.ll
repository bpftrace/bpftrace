; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%int64_count__tuple_t = type { i64, i64 }
%print_tuple_16_t = type <{ i64, i64, [16 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34
@tuple_buf = dso_local externally_initialized global [1 x [2 x [16 x i8]]] zeroinitializer, section ".data.tuple_buf", !dbg !51
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !59
@fmt_str_buf = dso_local externally_initialized global [1 x [1 x [32 x i8]]] zeroinitializer, section ".data.fmt_str_buf", !dbg !61
@num_cpus = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !68

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !73 {
entry:
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 1, ptr %"@x_key", align 8
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
  %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr @AT_x, ptr @map_for_each_cb, ptr null, i64 0)
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) section ".text" !dbg !79 {
  %key7 = alloca i32, align 4
  %val_2 = alloca i64, align 8
  %val_1 = alloca i64, align 8
  %i = alloca i32, align 4
  %lookup_key = alloca i64, align 8
  %key = load i64, ptr %1, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_key)
  store i64 %key, ptr %lookup_key, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %val_1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %val_2)
  store i32 0, ptr %i, align 4
  store i64 0, ptr %val_1, align 8
  store i64 0, ptr %val_2, align 8
  br label %while_cond

while_cond:                                       ; preds = %lookup_success, %4
  %5 = load i32, ptr @num_cpus, align 4
  %6 = load i32, ptr %i, align 4
  %num_cpu.cmp = icmp ult i32 %6, %5
  br i1 %num_cpu.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %7 = load i32, ptr %i, align 4
  %lookup_percpu_elem = call ptr inttoptr (i64 195 to ptr)(ptr @AT_x, ptr %lookup_key, i32 %7)
  %map_lookup_cond = icmp ne ptr %lookup_percpu_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

while_end:                                        ; preds = %error_failure, %error_success, %while_cond
  call void @llvm.lifetime.end.p0(i64 -1, ptr %i)
  %8 = load i64, ptr %val_1, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %val_1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %val_2)
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %9 = load i64, ptr @max_cpu_id, align 8
  %cpuid.min.cmp = icmp ule i64 %get_cpu_id, %9
  %cpuid.min.select = select i1 %cpuid.min.cmp, i64 %get_cpu_id, i64 %9
  %10 = getelementptr [1 x [2 x [16 x i8]]], ptr @tuple_buf, i64 0, i64 %cpuid.min.select, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %10, i8 0, i64 16, i1 false)
  %11 = getelementptr %int64_count__tuple_t, ptr %10, i32 0, i32 0
  store i64 %key, ptr %11, align 8
  %12 = getelementptr %int64_count__tuple_t, ptr %10, i32 0, i32 1
  store i64 %8, ptr %12, align 8
  %13 = getelementptr %int64_count__tuple_t, ptr %10, i32 0, i32 0
  %14 = load i64, ptr %13, align 8
  %15 = getelementptr %int64_count__tuple_t, ptr %10, i32 0, i32 1
  %16 = load i64, ptr %15, align 8
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)()
  %17 = load i64, ptr @max_cpu_id, align 8
  %cpuid.min.cmp2 = icmp ule i64 %get_cpu_id1, %17
  %cpuid.min.select3 = select i1 %cpuid.min.cmp2, i64 %get_cpu_id1, i64 %17
  %18 = getelementptr [1 x [2 x [16 x i8]]], ptr @tuple_buf, i64 0, i64 %cpuid.min.select3, i64 1, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %18, i8 0, i64 16, i1 false)
  %19 = getelementptr %int64_count__tuple_t, ptr %18, i32 0, i32 0
  store i64 %14, ptr %19, align 8
  %20 = getelementptr %int64_count__tuple_t, ptr %18, i32 0, i32 1
  store i64 %16, ptr %20, align 8
  %get_cpu_id4 = call i64 inttoptr (i64 8 to ptr)()
  %21 = load i64, ptr @max_cpu_id, align 8
  %cpuid.min.cmp5 = icmp ule i64 %get_cpu_id4, %21
  %cpuid.min.select6 = select i1 %cpuid.min.cmp5, i64 %get_cpu_id4, i64 %21
  %22 = getelementptr [1 x [1 x [32 x i8]]], ptr @fmt_str_buf, i64 0, i64 %cpuid.min.select6, i64 0, i64 0
  %23 = getelementptr %print_tuple_16_t, ptr %22, i64 0, i32 0
  store i64 30007, ptr %23, align 8
  %24 = getelementptr %print_tuple_16_t, ptr %22, i64 0, i32 1
  store i64 0, ptr %24, align 8
  %25 = getelementptr %print_tuple_16_t, ptr %22, i32 0, i32 2
  call void @llvm.memset.p0.i64(ptr align 1 %25, i8 0, i64 16, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %25, ptr align 1 %18, i64 16, i1 false)
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %22, i64 32, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

lookup_success:                                   ; preds = %while_body
  %26 = load i64, ptr %val_1, align 8
  %27 = load i64, ptr %lookup_percpu_elem, align 8
  %28 = add i64 %27, %26
  store i64 %28, ptr %val_1, align 8
  %29 = load i32, ptr %i, align 4
  %30 = add i32 %29, 1
  store i32 %30, ptr %i, align 4
  br label %while_cond

lookup_failure:                                   ; preds = %while_body
  %31 = load i32, ptr %i, align 4
  %error_lookup_cond = icmp eq i32 %31, 0
  br i1 %error_lookup_cond, label %error_success, label %error_failure

error_success:                                    ; preds = %lookup_failure
  br label %while_end

error_failure:                                    ; preds = %lookup_failure
  %32 = load i32, ptr %i, align 4
  br label %while_end

event_loss_counter:                               ; preds = %while_end
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key7)
  store i32 0, ptr %key7, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key7)
  %map_lookup_cond10 = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond10, label %lookup_success8, label %lookup_failure9

counter_merge:                                    ; preds = %lookup_merge, %while_end
  ret i64 0

lookup_success8:                                  ; preds = %event_loss_counter
  %33 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure9:                                  ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure9, %lookup_success8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key7)
  br label %counter_merge
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!70}
!llvm.module.flags = !{!72}

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
!52 = distinct !DIGlobalVariable(name: "tuple_buf", linkageName: "global", scope: !2, file: !2, type: !53, isLocal: false, isDefinition: true)
!53 = !DICompositeType(tag: DW_TAG_array_type, baseType: !54, size: 256, elements: !46)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !55, size: 256, elements: !41)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !56, size: 128, elements: !57)
!56 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!57 = !{!58}
!58 = !DISubrange(count: 16, lowerBound: 0)
!59 = !DIGlobalVariableExpression(var: !60, expr: !DIExpression())
!60 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!61 = !DIGlobalVariableExpression(var: !62, expr: !DIExpression())
!62 = distinct !DIGlobalVariable(name: "fmt_str_buf", linkageName: "global", scope: !2, file: !2, type: !63, isLocal: false, isDefinition: true)
!63 = !DICompositeType(tag: DW_TAG_array_type, baseType: !64, size: 256, elements: !46)
!64 = !DICompositeType(tag: DW_TAG_array_type, baseType: !65, size: 256, elements: !46)
!65 = !DICompositeType(tag: DW_TAG_array_type, baseType: !56, size: 256, elements: !66)
!66 = !{!67}
!67 = !DISubrange(count: 32, lowerBound: 0)
!68 = !DIGlobalVariableExpression(var: !69, expr: !DIExpression())
!69 = distinct !DIGlobalVariable(name: "num_cpus", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!70 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !71)
!71 = !{!0, !20, !34, !51, !59, !61, !68}
!72 = !{i32 2, !"Debug Info Version", i32 3}
!73 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !74, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !70, retainedNodes: !77)
!74 = !DISubroutineType(types: !75)
!75 = !{!18, !76}
!76 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !56, size: 64)
!77 = !{!78}
!78 = !DILocalVariable(name: "ctx", arg: 1, scope: !73, file: !2, type: !76)
!79 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !74, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !70, retainedNodes: !80)
!80 = !{!81}
!81 = !DILocalVariable(name: "ctx", arg: 1, scope: !79, file: !2, type: !76)
