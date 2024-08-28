; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"struct map_t.3" = type { ptr, ptr, ptr, ptr }
%print_integer_8_t = type <{ i64, i64, [8 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34
@stack = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !51
@fmt_string_args = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !64
@num_cpus = dso_local externally_initialized constant i64 1, section ".rodata", !dbg !73

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !78 {
entry:
  %key = alloca i32, align 4
  %lookup_fmtstr_key = alloca i32, align 4
  %val_2 = alloca i64, align 8
  %val_1 = alloca i64, align 8
  %i = alloca i32, align 4
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
  %2 = add i64 %1, 2
  store i64 %2, ptr %lookup_elem, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %initial_value)
  store i64 2, ptr %initial_value, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %initial_value, i64 1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %initial_value)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key1")
  store i64 0, ptr %"@x_key1", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %val_1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %val_2)
  store i32 0, ptr %i, align 4
  store i64 0, ptr %val_1, align 8
  store i64 0, ptr %val_2, align 8
  br label %while_cond

if_body:                                          ; preds = %while_end
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_fmtstr_key)
  store i32 0, ptr %lookup_fmtstr_key, align 4
  %lookup_fmtstr_map = call ptr inttoptr (i64 1 to ptr)(ptr @fmt_string_args, ptr %lookup_fmtstr_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_fmtstr_key)
  %lookup_fmtstr_cond = icmp ne ptr %lookup_fmtstr_map, null
  br i1 %lookup_fmtstr_cond, label %lookup_fmtstr_merge, label %lookup_fmtstr_failure

if_end:                                           ; preds = %counter_merge, %while_end
  ret i64 0

while_cond:                                       ; preds = %lookup_success2, %lookup_merge
  %3 = load i32, ptr @num_cpus, align 4
  %4 = load i32, ptr %i, align 4
  %num_cpu.cmp = icmp ult i32 %4, %3
  br i1 %num_cpu.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %5 = load i32, ptr %i, align 4
  %lookup_percpu_elem = call ptr inttoptr (i64 195 to ptr)(ptr @AT_x, ptr %"@x_key1", i32 %5)
  %map_lookup_cond4 = icmp ne ptr %lookup_percpu_elem, null
  br i1 %map_lookup_cond4, label %lookup_success2, label %lookup_failure3

while_end:                                        ; preds = %error_failure, %error_success, %while_cond
  call void @llvm.lifetime.end.p0(i64 -1, ptr %i)
  %6 = load i64, ptr %val_1, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %val_1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %val_2)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key1")
  %7 = icmp sgt i64 %6, 5
  %8 = zext i1 %7 to i64
  %true_cond = icmp ne i64 %8, 0
  br i1 %true_cond, label %if_body, label %if_end

lookup_success2:                                  ; preds = %while_body
  %9 = load i64, ptr %val_1, align 8
  %10 = load i64, ptr %lookup_percpu_elem, align 8
  %11 = add i64 %10, %9
  store i64 %11, ptr %val_1, align 8
  %12 = load i32, ptr %i, align 4
  %13 = add i32 %12, 1
  store i32 %13, ptr %i, align 4
  br label %while_cond

lookup_failure3:                                  ; preds = %while_body
  %14 = load i32, ptr %i, align 4
  %error_lookup_cond = icmp eq i32 %14, 0
  br i1 %error_lookup_cond, label %error_success, label %error_failure

error_success:                                    ; preds = %lookup_failure3
  br label %while_end

error_failure:                                    ; preds = %lookup_failure3
  %15 = load i32, ptr %i, align 4
  br label %while_end

lookup_fmtstr_failure:                            ; preds = %if_body
  ret i64 0

lookup_fmtstr_merge:                              ; preds = %if_body
  %16 = getelementptr %print_integer_8_t, ptr %lookup_fmtstr_map, i64 0, i32 0
  store i64 30007, ptr %16, align 8
  %17 = getelementptr %print_integer_8_t, ptr %lookup_fmtstr_map, i64 0, i32 1
  store i64 0, ptr %17, align 8
  %18 = getelementptr %print_integer_8_t, ptr %lookup_fmtstr_map, i32 0, i32 2
  call void @llvm.memset.p0.i64(ptr align 1 %18, i8 0, i64 8, i1 false)
  store i64 6, ptr %18, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_fmtstr_map, i64 24, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %lookup_fmtstr_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem5 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond9 = icmp ne ptr %lookup_elem5, null
  br i1 %map_lookup_cond9, label %lookup_success6, label %lookup_failure7

counter_merge:                                    ; preds = %lookup_merge8, %lookup_fmtstr_merge
  br label %if_end

lookup_success6:                                  ; preds = %event_loss_counter
  %19 = atomicrmw add ptr %lookup_elem5, i64 1 seq_cst, align 8
  br label %lookup_merge8

lookup_failure7:                                  ; preds = %event_loss_counter
  br label %lookup_merge8

lookup_merge8:                                    ; preds = %lookup_failure7, %lookup_success6
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

!llvm.dbg.cu = !{!75}
!llvm.module.flags = !{!77}

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
!52 = distinct !DIGlobalVariable(name: "stack", linkageName: "global", scope: !2, file: !2, type: !53, isLocal: false, isDefinition: true)
!53 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !54)
!54 = !{!55, !43, !48, !60}
!55 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !56, size: 64)
!56 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !57, size: 64)
!57 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !58)
!58 = !{!59}
!59 = !DISubrange(count: 6, lowerBound: 0)
!60 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !61, size: 64, offset: 192)
!61 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !62, size: 64)
!62 = !DICompositeType(tag: DW_TAG_array_type, baseType: !63, size: 32768, elements: !14)
!63 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!64 = !DIGlobalVariableExpression(var: !65, expr: !DIExpression())
!65 = distinct !DIGlobalVariable(name: "fmt_string_args", linkageName: "global", scope: !2, file: !2, type: !66, isLocal: false, isDefinition: true)
!66 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !67)
!67 = !{!55, !43, !48, !68}
!68 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !69, size: 64, offset: 192)
!69 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !70, size: 64)
!70 = !DICompositeType(tag: DW_TAG_array_type, baseType: !63, size: 192, elements: !71)
!71 = !{!72}
!72 = !DISubrange(count: 24, lowerBound: 0)
!73 = !DIGlobalVariableExpression(var: !74, expr: !DIExpression())
!74 = distinct !DIGlobalVariable(name: "num_cpus", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!75 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !76)
!76 = !{!0, !20, !34, !51, !64, !73}
!77 = !{i32 2, !"Debug Info Version", i32 3}
!78 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !79, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !75, retainedNodes: !82)
!79 = !DISubroutineType(types: !80)
!80 = !{!18, !81}
!81 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !63, size: 64)
!82 = !{!83}
!83 = !DILocalVariable(name: "ctx", arg: 1, scope: !78, file: !2, type: !81)
