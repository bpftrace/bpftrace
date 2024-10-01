; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%avg_stas_val = type { i64, i64 }
%print_integer_8_t = type <{ i64, i64, [8 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !26
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !40
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !57
@fmt_str_buf = dso_local externally_initialized global [1 x [1 x [24 x i8]]] zeroinitializer, section ".data.fmt_str_buf", !dbg !59
@num_cpus = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !67

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !72 {
entry:
  %key = alloca i32, align 4
  %ret = alloca i64, align 8
  %val_2 = alloca i64, align 8
  %val_1 = alloca i64, align 8
  %i = alloca i32, align 4
  %"@x_key1" = alloca i64, align 8
  %avg_struct = alloca %avg_stas_val, align 8
  %"@x_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key")
  %lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %1 = getelementptr %avg_stas_val, ptr %lookup_elem, i64 0, i32 0
  %2 = load i64, ptr %1, align 8
  %3 = getelementptr %avg_stas_val, ptr %lookup_elem, i64 0, i32 1
  %4 = load i64, ptr %3, align 8
  %5 = getelementptr %avg_stas_val, ptr %lookup_elem, i64 0, i32 0
  %6 = add i64 %2, 2
  store i64 %6, ptr %5, align 8
  %7 = getelementptr %avg_stas_val, ptr %lookup_elem, i64 0, i32 1
  %8 = add i64 1, %4
  store i64 %8, ptr %7, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %avg_struct)
  %9 = getelementptr %avg_stas_val, ptr %avg_struct, i64 0, i32 0
  store i64 2, ptr %9, align 8
  %10 = getelementptr %avg_stas_val, ptr %avg_struct, i64 0, i32 1
  store i64 1, ptr %10, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %avg_struct, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %avg_struct)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
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

if_body:                                          ; preds = %is_negative_merge_block
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %11 = load i64, ptr @max_cpu_id, align 8
  %cpuid.min.cmp = icmp ule i64 %get_cpu_id, %11
  %cpuid.min.select = select i1 %cpuid.min.cmp, i64 %get_cpu_id, i64 %11
  %12 = getelementptr [1 x [1 x [24 x i8]]], ptr @fmt_str_buf, i64 0, i64 %cpuid.min.select, i64 0, i64 0
  %13 = getelementptr %print_integer_8_t, ptr %12, i64 0, i32 0
  store i64 30007, ptr %13, align 8
  %14 = getelementptr %print_integer_8_t, ptr %12, i64 0, i32 1
  store i64 0, ptr %14, align 8
  %15 = getelementptr %print_integer_8_t, ptr %12, i32 0, i32 2
  call void @llvm.memset.p0.i64(ptr align 1 %15, i8 0, i64 8, i1 false)
  store i64 6, ptr %15, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %12, i64 24, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

if_end:                                           ; preds = %counter_merge, %is_negative_merge_block
  ret i64 0

while_cond:                                       ; preds = %lookup_success2, %lookup_merge
  %16 = load i32, ptr @num_cpus, align 4
  %17 = load i32, ptr %i, align 4
  %num_cpu.cmp = icmp ult i32 %17, %16
  br i1 %num_cpu.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %18 = load i32, ptr %i, align 4
  %lookup_percpu_elem = call ptr inttoptr (i64 195 to ptr)(ptr @AT_x, ptr %"@x_key1", i32 %18)
  %map_lookup_cond = icmp ne ptr %lookup_percpu_elem, null
  br i1 %map_lookup_cond, label %lookup_success2, label %lookup_failure3

while_end:                                        ; preds = %error_failure, %error_success, %while_cond
  call void @llvm.lifetime.end.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ret)
  %19 = load i64, ptr %val_1, align 8
  %is_negative_cond = icmp slt i64 %19, 0
  br i1 %is_negative_cond, label %is_negative, label %is_positive

lookup_success2:                                  ; preds = %while_body
  %20 = getelementptr %avg_stas_val, ptr %lookup_percpu_elem, i64 0, i32 0
  %21 = load i64, ptr %20, align 8
  %22 = getelementptr %avg_stas_val, ptr %lookup_percpu_elem, i64 0, i32 1
  %23 = load i64, ptr %22, align 8
  %24 = load i64, ptr %val_1, align 8
  %25 = add i64 %21, %24
  store i64 %25, ptr %val_1, align 8
  %26 = load i64, ptr %val_2, align 8
  %27 = add i64 %23, %26
  store i64 %27, ptr %val_2, align 8
  %28 = load i32, ptr %i, align 4
  %29 = add i32 %28, 1
  store i32 %29, ptr %i, align 4
  br label %while_cond

lookup_failure3:                                  ; preds = %while_body
  %30 = load i32, ptr %i, align 4
  %error_lookup_cond = icmp eq i32 %30, 0
  br i1 %error_lookup_cond, label %error_success, label %error_failure

error_success:                                    ; preds = %lookup_failure3
  br label %while_end

error_failure:                                    ; preds = %lookup_failure3
  %31 = load i32, ptr %i, align 4
  br label %while_end

is_negative:                                      ; preds = %while_end
  %32 = load i64, ptr %val_1, align 8
  %33 = xor i64 %32, -1
  %34 = add i64 %33, 1
  %35 = load i64, ptr %val_2, align 8
  %36 = udiv i64 %34, %35
  %37 = sub i64 0, %36
  store i64 %37, ptr %ret, align 8
  br label %is_negative_merge_block

is_positive:                                      ; preds = %while_end
  %38 = load i64, ptr %val_2, align 8
  %39 = load i64, ptr %val_1, align 8
  %40 = udiv i64 %39, %38
  store i64 %40, ptr %ret, align 8
  br label %is_negative_merge_block

is_negative_merge_block:                          ; preds = %is_positive, %is_negative
  %41 = load i64, ptr %ret, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %ret)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %val_1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %val_2)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key1")
  %42 = icmp eq i64 %41, 2
  %43 = zext i1 %42 to i64
  %true_cond = icmp ne i64 %43, 0
  br i1 %true_cond, label %if_body, label %if_end

event_loss_counter:                               ; preds = %if_body
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem4 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond8 = icmp ne ptr %lookup_elem4, null
  br i1 %map_lookup_cond8, label %lookup_success5, label %lookup_failure6

counter_merge:                                    ; preds = %lookup_merge7, %if_body
  br label %if_end

lookup_success5:                                  ; preds = %event_loss_counter
  %44 = atomicrmw add ptr %lookup_elem4, i64 1 seq_cst, align 8
  br label %lookup_merge7

lookup_failure6:                                  ; preds = %event_loss_counter
  br label %lookup_merge7

lookup_merge7:                                    ; preds = %lookup_failure6, %lookup_success5
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

!llvm.dbg.cu = !{!69}
!llvm.module.flags = !{!71}

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
!57 = !DIGlobalVariableExpression(var: !58, expr: !DIExpression())
!58 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!59 = !DIGlobalVariableExpression(var: !60, expr: !DIExpression())
!60 = distinct !DIGlobalVariable(name: "fmt_str_buf", linkageName: "global", scope: !2, file: !2, type: !61, isLocal: false, isDefinition: true)
!61 = !DICompositeType(tag: DW_TAG_array_type, baseType: !62, size: 192, elements: !52)
!62 = !DICompositeType(tag: DW_TAG_array_type, baseType: !63, size: 192, elements: !52)
!63 = !DICompositeType(tag: DW_TAG_array_type, baseType: !64, size: 192, elements: !65)
!64 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!65 = !{!66}
!66 = !DISubrange(count: 24, lowerBound: 0)
!67 = !DIGlobalVariableExpression(var: !68, expr: !DIExpression())
!68 = distinct !DIGlobalVariable(name: "num_cpus", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!69 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !70)
!70 = !{!0, !26, !40, !57, !59, !67}
!71 = !{i32 2, !"Debug Info Version", i32 3}
!72 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !73, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !69, retainedNodes: !76)
!73 = !DISubroutineType(types: !74)
!74 = !{!18, !75}
!75 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !64, size: 64)
!76 = !{!77}
!77 = !DILocalVariable(name: "ctx", arg: 1, scope: !72, file: !2, type: !75)
