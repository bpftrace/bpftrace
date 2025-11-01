; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.616" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.617" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.618" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.619" = type { ptr, ptr }
%kstack_key = type { i64, i64 }
%ustack_key = type { i64, i64, i32, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_y = dso_local global %"struct map_internal_repr_t.616" zeroinitializer, section ".maps", !dbg !22
@stack_bpftrace_127 = dso_local global %"struct map_internal_repr_t.617" zeroinitializer, section ".maps", !dbg !24
@stack_scratch = dso_local global %"struct map_internal_repr_t.618" zeroinitializer, section ".maps", !dbg !48
@ringbuf = dso_local global %"struct map_internal_repr_t.619" zeroinitializer, section ".maps", !dbg !60
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !74
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !78

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !84 {
entry:
  %"@y_val" = alloca i64, align 8
  %"@y_key" = alloca i64, align 8
  %lookup_stack_scratch_key5 = alloca i32, align 4
  %stack_key2 = alloca %kstack_key, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %lookup_stack_scratch_key = alloca i32, align 4
  %stack_key = alloca %ustack_key, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key)
  call void @llvm.memset.p0.i64(ptr align 1 %stack_key, i8 0, i64 24, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key)
  store i32 0, ptr %lookup_stack_scratch_key, align 4
  %lookup_stack_scratch_map = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key)
  %lookup_stack_scratch_cond = icmp ne ptr %lookup_stack_scratch_map, null
  br i1 %lookup_stack_scratch_cond, label %lookup_stack_scratch_merge, label %lookup_stack_scratch_failure

stack_scratch_failure:                            ; preds = %lookup_stack_scratch_failure
  br label %merge_block

merge_block:                                      ; preds = %stack_scratch_failure, %get_stack_success, %get_stack_fail
  %1 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 2
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)() #4
  %2 = lshr i64 %get_pid_tgid, 32
  %pid = trunc i64 %2 to i32
  store i32 %pid, ptr %1, align 4
  %3 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 3
  store i32 0, ptr %3, align 4
  %4 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 1
  %5 = load i64, ptr %4, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_val")
  store i64 %5, ptr %"@x_val", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key2)
  call void @llvm.memset.p0.i64(ptr align 1 %stack_key2, i8 0, i64 16, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key5)
  store i32 0, ptr %lookup_stack_scratch_key5, align 4
  %lookup_stack_scratch_map6 = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key5)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key5)
  %lookup_stack_scratch_cond9 = icmp ne ptr %lookup_stack_scratch_map6, null
  br i1 %lookup_stack_scratch_cond9, label %lookup_stack_scratch_merge8, label %lookup_stack_scratch_failure7

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map, i32 1016, ptr null)
  %get_stack = call i64 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map, i32 1016, i64 256)
  %6 = icmp sge i64 %get_stack, 0
  br i1 %6, label %get_stack_success, label %get_stack_fail

get_stack_success:                                ; preds = %lookup_stack_scratch_merge
  %7 = udiv i64 %get_stack, 8
  %8 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 1
  store i64 %7, ptr %8, align 8
  %9 = trunc i64 %7 to i8
  %murmur_hash_2 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map, i8 %9, i64 1)
  %10 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 0
  store i64 %murmur_hash_2, ptr %10, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key, ptr %lookup_stack_scratch_map, i64 0)
  br label %merge_block

get_stack_fail:                                   ; preds = %lookup_stack_scratch_merge
  br label %merge_block

stack_scratch_failure3:                           ; preds = %lookup_stack_scratch_failure7
  br label %merge_block4

merge_block4:                                     ; preds = %stack_scratch_failure3, %get_stack_success11, %get_stack_fail12
  %11 = getelementptr %kstack_key, ptr %stack_key2, i64 0, i32 1
  %12 = load i64, ptr %11, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_val")
  store i64 %12, ptr %"@y_val", align 8
  %update_elem16 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %"@y_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  ret i64 0

lookup_stack_scratch_failure7:                    ; preds = %merge_block
  br label %stack_scratch_failure3

lookup_stack_scratch_merge8:                      ; preds = %merge_block
  %probe_read_kernel10 = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map6, i32 1016, ptr null)
  %get_stack13 = call i64 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map6, i32 1016, i64 0)
  %13 = icmp sge i64 %get_stack13, 0
  br i1 %13, label %get_stack_success11, label %get_stack_fail12

get_stack_success11:                              ; preds = %lookup_stack_scratch_merge8
  %14 = udiv i64 %get_stack13, 8
  %15 = getelementptr %kstack_key, ptr %stack_key2, i64 0, i32 1
  store i64 %14, ptr %15, align 8
  %16 = trunc i64 %14 to i8
  %murmur_hash_214 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map6, i8 %16, i64 1)
  %17 = getelementptr %kstack_key, ptr %stack_key2, i64 0, i32 0
  store i64 %murmur_hash_214, ptr %17, align 8
  %update_elem15 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key2, ptr %lookup_stack_scratch_map6, i64 0)
  br label %merge_block4

get_stack_fail12:                                 ; preds = %lookup_stack_scratch_merge8
  br label %merge_block4
}

; Function Attrs: alwaysinline nounwind
define internal i64 @murmur_hash_2(ptr %0, i8 %1, i64 %2) #1 section "helpers" {
entry:
  %k = alloca i64, align 8
  %i = alloca i8, align 1
  %id = alloca i64, align 8
  %seed_addr = alloca i64, align 8
  %nr_stack_frames_addr = alloca i8, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %nr_stack_frames_addr)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %seed_addr)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %id)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %k)
  store i8 %1, ptr %nr_stack_frames_addr, align 1
  store i64 %2, ptr %seed_addr, align 8
  %3 = load i8, ptr %nr_stack_frames_addr, align 1
  %4 = zext i8 %3 to i64
  %5 = mul i64 %4, -4132994306676758123
  %6 = load i64, ptr %seed_addr, align 8
  %7 = xor i64 %6, %5
  store i64 %7, ptr %id, align 8
  store i8 0, ptr %i, align 1
  br label %while_cond

while_cond:                                       ; preds = %while_body, %entry
  %8 = load i8, ptr %nr_stack_frames_addr, align 1
  %9 = load i8, ptr %i, align 1
  %length.cmp = icmp ult i8 %9, %8
  br i1 %length.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %10 = load i8, ptr %i, align 1
  %11 = getelementptr i64, ptr %0, i8 %10
  %12 = load i64, ptr %11, align 8
  store i64 %12, ptr %k, align 8
  %13 = load i64, ptr %k, align 8
  %14 = mul i64 %13, -4132994306676758123
  store i64 %14, ptr %k, align 8
  %15 = load i64, ptr %k, align 8
  %16 = lshr i64 %15, 47
  %17 = load i64, ptr %k, align 8
  %18 = xor i64 %17, %16
  store i64 %18, ptr %k, align 8
  %19 = load i64, ptr %k, align 8
  %20 = mul i64 %19, -4132994306676758123
  store i64 %20, ptr %k, align 8
  %21 = load i64, ptr %k, align 8
  %22 = load i64, ptr %id, align 8
  %23 = xor i64 %22, %21
  store i64 %23, ptr %id, align 8
  %24 = load i64, ptr %id, align 8
  %25 = mul i64 %24, -4132994306676758123
  store i64 %25, ptr %id, align 8
  %26 = load i8, ptr %i, align 1
  %27 = add i8 %26, 1
  store i8 %27, ptr %i, align 1
  br label %while_cond

while_end:                                        ; preds = %while_cond
  call void @llvm.lifetime.end.p0(i64 -1, ptr %nr_stack_frames_addr)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %seed_addr)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %k)
  %28 = load i64, ptr %id, align 8
  %zero_cond = icmp eq i64 %28, 0
  br i1 %zero_cond, label %if_zero, label %if_end

if_zero:                                          ; preds = %while_end
  store i64 1, ptr %id, align 8
  br label %if_end

if_end:                                           ; preds = %if_zero, %while_end
  %29 = load i64, ptr %id, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %id)
  ret i64 %29
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { alwaysinline nounwind }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #4 = { memory(none) }

!llvm.dbg.cu = !{!80}
!llvm.module.flags = !{!82, !83}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !10)
!10 = !{!11, !17, !18, !21}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 1, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !19, size: 64, offset: 128)
!19 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !20, size: 64)
!20 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !19, size: 64, offset: 192)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!24 = !DIGlobalVariableExpression(var: !25, expr: !DIExpression())
!25 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!26 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !27)
!27 = !{!28, !33, !38, !43}
!28 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !29, size: 64)
!29 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !30, size: 64)
!30 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 288, elements: !31)
!31 = !{!32}
!32 = !DISubrange(count: 9, lowerBound: 0)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !34, size: 64, offset: 64)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 4194304, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 131072, lowerBound: 0)
!38 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !39, size: 64, offset: 128)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 128, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 16, lowerBound: 0)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !44, size: 64, offset: 192)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 8128, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 127, lowerBound: 0)
!48 = !DIGlobalVariableExpression(var: !49, expr: !DIExpression())
!49 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !50, isLocal: false, isDefinition: true)
!50 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !51)
!51 = !{!52, !17, !57, !43}
!52 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !53, size: 64)
!53 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !54, size: 64)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 192, elements: !55)
!55 = !{!56}
!56 = !DISubrange(count: 6, lowerBound: 0)
!57 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !58, size: 64, offset: 128)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!59 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!60 = !DIGlobalVariableExpression(var: !61, expr: !DIExpression())
!61 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !62, isLocal: false, isDefinition: true)
!62 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !63)
!63 = !{!64, !69}
!64 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !65, size: 64)
!65 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !66, size: 64)
!66 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !67)
!67 = !{!68}
!68 = !DISubrange(count: 27, lowerBound: 0)
!69 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !70, size: 64, offset: 64)
!70 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !71, size: 64)
!71 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !72)
!72 = !{!73}
!73 = !DISubrange(count: 262144, lowerBound: 0)
!74 = !DIGlobalVariableExpression(var: !75, expr: !DIExpression())
!75 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !76, isLocal: false, isDefinition: true)
!76 = !DICompositeType(tag: DW_TAG_array_type, baseType: !77, size: 64, elements: !15)
!77 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 64, elements: !15)
!78 = !DIGlobalVariableExpression(var: !79, expr: !DIExpression())
!79 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!80 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !81)
!81 = !{!0, !7, !22, !24, !48, !60, !74, !78}
!82 = !{i32 2, !"Debug Info Version", i32 3}
!83 = !{i32 7, !"uwtable", i32 0}
!84 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !85, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !80, retainedNodes: !88)
!85 = !DISubroutineType(types: !86)
!86 = !{!20, !87}
!87 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!88 = !{!89}
!89 = !DILocalVariable(name: "ctx", arg: 1, scope: !84, file: !2, type: !87)
