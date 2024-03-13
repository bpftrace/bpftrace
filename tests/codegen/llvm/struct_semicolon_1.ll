; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }
%"struct map_t.1" = type { i8*, i8* }
%"struct map_t.2" = type { i8*, i8*, i8*, i8* }
%stack_t = type { i64, i32, i32 }
%printf_t = type { i64, [16 x i8] }

@stack_bpftrace_127 = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@stack_scratch = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !24
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !37
@ringbuf_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !51

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !65 {
entry:
  %key = alloca i32, align 4
  %stack_args = alloca %stack_t, align 8
  %fmt_str = alloca [49 x i8], align 1
  %seed = alloca i64, align 8
  %lookup_stack_scratch_key = alloca i32, align 4
  %stackid = alloca i64, align 8
  %printf_args = alloca %printf_t, align 8
  %1 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 24, i1 false)
  %3 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %3, align 8
  %4 = bitcast i64* %stackid to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  %5 = bitcast i32* %lookup_stack_scratch_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i32 0, i32* %lookup_stack_scratch_key, align 4
  %lookup_stack_scratch_map = call [127 x i64]* inttoptr (i64 1 to [127 x i64]* (%"struct map_t.0"*, i32*)*)(%"struct map_t.0"* @stack_scratch, i32* %lookup_stack_scratch_key)
  %6 = bitcast i32* %lookup_stack_scratch_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  %lookup_stack_scratch_cond = icmp ne i8* %7, null
  br i1 %lookup_stack_scratch_cond, label %lookup_stack_scratch_merge, label %lookup_stack_scratch_failure

stack_scratch_failure:                            ; preds = %lookup_stack_scratch_failure
  store i64 0, i64* %stackid, align 8
  br label %merge_block

merge_block:                                      ; preds = %stack_scratch_failure, %get_stack_success, %get_stack_fail
  %8 = bitcast %stack_t* %stack_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %9 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 0
  %10 = load i64, i64* %stackid, align 8
  store i64 %10, i64* %9, align 8
  %11 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 1
  %get_pid_tgid1 = call i64 inttoptr (i64 14 to i64 ()*)()
  %12 = trunc i64 %get_pid_tgid1 to i32
  store i32 %12, i32* %11, align 4
  %13 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 2
  store i32 0, i32* %13, align 4
  %14 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  %15 = bitcast [16 x i8]* %14 to i8*
  %16 = bitcast %stack_t* %stack_args to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %15, i8* align 1 %16, i64 16, i1 false)
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t.1"*, %printf_t*, i64, i64)*)(%"struct map_t.1"* @ringbuf, %printf_t* %printf_args, i64 24, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %17 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %17, i8 0, i64 1016, i1 false)
  %18 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  %get_stack = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %18, i32 1016, i64 256)
  %19 = icmp sge i32 %get_stack, 8
  br i1 %19, label %get_stack_success, label %get_stack_fail

get_stack_success:                                ; preds = %lookup_stack_scratch_merge
  %20 = udiv i32 %get_stack, 8
  %21 = bitcast i64* %seed to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  store i64 %get_pid_tgid, i64* %seed, align 8
  %22 = trunc i32 %20 to i8
  %23 = load i64, i64* %seed, align 8
  %murmur_hash_2 = call i64 @murmur_hash_2(i8* %18, i8 %22, i64 %23)
  %24 = bitcast [49 x i8]* %fmt_str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %24)
  %25 = bitcast [49 x i8]* %fmt_str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %25, i8 0, i64 49, i1 false)
  store [49 x i8] c"[BPFTRACE_DEBUG_OUTPUT] Stack id %llu. Len: %llu\00", [49 x i8]* %fmt_str, align 1
  %26 = bitcast [49 x i8]* %fmt_str to i8*
  %trace_printk = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* %26, i32 49, i64 %murmur_hash_2, i32 %20)
  store i64 %murmur_hash_2, i64* %stackid, align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, [127 x i64]*, i64)*)(%"struct map_t"* @stack_bpftrace_127, i64* %stackid, [127 x i64]* %lookup_stack_scratch_map, i64 0)
  br label %merge_block

get_stack_fail:                                   ; preds = %lookup_stack_scratch_merge
  store i64 0, i64* %stackid, align 8
  br label %merge_block

event_loss_counter:                               ; preds = %merge_block
  %27 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %27)
  store i32 0, i32* %key, align 4
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t.2"*, i32*)*)(%"struct map_t.2"* @ringbuf_loss_counter, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %merge_block
  %28 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %28)
  ret i64 0

lookup_success:                                   ; preds = %event_loss_counter
  %29 = bitcast i8* %lookup_elem to i64*
  %30 = atomicrmw add i64* %29, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %31 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  br label %counter_merge
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: alwaysinline
define internal i64 @murmur_hash_2(i8* %0, i8 %1, i64 %2) #3 section "helpers" {
  %k = alloca i64, align 8
  %i = alloca i8, align 1
  %id = alloca i64, align 8
  %seed_addr = alloca i64, align 8
  %len_addr = alloca i8, align 1
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %len_addr)
  %4 = bitcast i64* %seed_addr to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  %5 = bitcast i64* %id to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %i)
  %6 = bitcast i64* %k to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %7 = bitcast i8* %0 to i64*
  store i8 %1, i8* %len_addr, align 1
  store i64 %2, i64* %seed_addr, align 8
  %8 = load i8, i8* %len_addr, align 1
  %9 = zext i8 %8 to i64
  %10 = mul i64 %9, -4132994306676758123
  %11 = load i64, i64* %seed_addr, align 8
  %12 = xor i64 %11, %10
  store i64 %12, i64* %id, align 8
  store i8 0, i8* %i, align 1
  br label %while_cond

while_cond:                                       ; preds = %while_body, %3
  %13 = load i8, i8* %len_addr, align 1
  %14 = load i8, i8* %i, align 1
  %length.cmp = icmp ult i8 %14, %13
  br i1 %length.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %15 = load i8, i8* %i, align 1
  %16 = getelementptr i64, i64* %7, i8 %15
  %17 = load i64, i64* %16, align 8
  store i64 %17, i64* %k, align 8
  %18 = load i64, i64* %k, align 8
  %19 = mul i64 %18, -4132994306676758123
  store i64 %19, i64* %k, align 8
  %20 = load i64, i64* %k, align 8
  %21 = lshr i64 %20, 47
  %22 = load i64, i64* %k, align 8
  %23 = xor i64 %22, %21
  store i64 %23, i64* %k, align 8
  %24 = load i64, i64* %k, align 8
  %25 = mul i64 %24, -4132994306676758123
  store i64 %25, i64* %k, align 8
  %26 = load i64, i64* %k, align 8
  %27 = load i64, i64* %id, align 8
  %28 = xor i64 %27, %26
  store i64 %28, i64* %id, align 8
  %29 = load i64, i64* %id, align 8
  %30 = mul i64 %29, -4132994306676758123
  store i64 %30, i64* %id, align 8
  %31 = load i8, i8* %i, align 1
  %32 = add i8 %31, 1
  store i8 %32, i8* %i, align 1
  br label %while_cond

while_end:                                        ; preds = %while_cond
  %33 = load i64, i64* %id, align 8
  ret i64 %33
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }
attributes #3 = { alwaysinline }

!llvm.dbg.cu = !{!61}
!llvm.module.flags = !{!64}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 4194304, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 131072, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !20, size: 64, offset: 192)
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!21 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 8128, elements: !22)
!22 = !{!23}
!23 = !DISubrange(count: 127, lowerBound: 0)
!24 = !DIGlobalVariableExpression(var: !25, expr: !DIExpression())
!25 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!26 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !27)
!27 = !{!28, !33, !34, !19}
!28 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !29, size: 64)
!29 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !30, size: 64)
!30 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !31)
!31 = !{!32}
!32 = !DISubrange(count: 6, lowerBound: 0)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!34 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !35, size: 64, offset: 128)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!37 = !DIGlobalVariableExpression(var: !38, expr: !DIExpression())
!38 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !39, isLocal: false, isDefinition: true)
!39 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !40)
!40 = !{!41, !46}
!41 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !42, size: 64)
!42 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!43 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !44)
!44 = !{!45}
!45 = !DISubrange(count: 27, lowerBound: 0)
!46 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !47, size: 64, offset: 64)
!47 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !48, size: 64)
!48 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !49)
!49 = !{!50}
!50 = !DISubrange(count: 262144, lowerBound: 0)
!51 = !DIGlobalVariableExpression(var: !52, expr: !DIExpression())
!52 = distinct !DIGlobalVariable(name: "ringbuf_loss_counter", linkageName: "global", scope: !2, file: !2, type: !53, isLocal: false, isDefinition: true)
!53 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !54)
!54 = !{!55, !33, !34, !60}
!55 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !56, size: 64)
!56 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !57, size: 64)
!57 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !58)
!58 = !{!59}
!59 = !DISubrange(count: 2, lowerBound: 0)
!60 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!61 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !62, globals: !63)
!62 = !{}
!63 = !{!0, !24, !37, !51}
!64 = !{i32 2, !"Debug Info Version", i32 3}
!65 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !2, file: !2, type: !66, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !61, retainedNodes: !70)
!66 = !DISubroutineType(types: !67)
!67 = !{!18, !68}
!68 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !69, size: 64)
!69 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!70 = !{!71, !72}
!71 = !DILocalVariable(name: "var0", scope: !65, file: !2, type: !18)
!72 = !DILocalVariable(name: "var1", arg: 1, scope: !65, file: !2, type: !68)
