; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%"struct map_t.2" = type { i8*, i8* }
%"struct map_t.3" = type { i8*, i8*, i8*, i8* }
%stack_t = type { i64, i32, i32 }

@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@stack_bpftrace_127 = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@stack_scratch = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !39
@ringbuf = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !52
@ringbuf_loss_counter = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !66

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !80 {
entry:
  %"@x_key" = alloca i64, align 8
  %stack_args = alloca %stack_t, align 8
  %fmt_str = alloca [49 x i8], align 1
  %seed = alloca i64, align 8
  %lookup_stack_scratch_key = alloca i32, align 4
  %stackid = alloca i64, align 8
  %1 = bitcast i64* %stackid to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast i32* %lookup_stack_scratch_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i32 0, i32* %lookup_stack_scratch_key, align 4
  %lookup_stack_scratch_map = call [127 x i64]* inttoptr (i64 1 to [127 x i64]* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @stack_scratch, i32* %lookup_stack_scratch_key)
  %3 = bitcast i32* %lookup_stack_scratch_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  %lookup_stack_scratch_cond = icmp ne i8* %4, null
  br i1 %lookup_stack_scratch_cond, label %lookup_stack_scratch_merge, label %lookup_stack_scratch_failure

stack_scratch_failure:                            ; preds = %lookup_stack_scratch_failure
  store i64 0, i64* %stackid, align 8
  br label %merge_block

merge_block:                                      ; preds = %stack_scratch_failure, %get_stack_success, %get_stack_fail
  %5 = bitcast %stack_t* %stack_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 0
  %7 = load i64, i64* %stackid, align 8
  store i64 %7, i64* %6, align 8
  %8 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 1
  %get_pid_tgid1 = call i64 inttoptr (i64 14 to i64 ()*)()
  %9 = trunc i64 %get_pid_tgid1 to i32
  store i32 %9, i32* %8, align 4
  %10 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 2
  store i32 0, i32* %10, align 4
  %11 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i64 0, i64* %"@x_key", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, %stack_t*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key", %stack_t* %stack_args, i64 0)
  %12 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %13 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %13, i8 0, i64 1016, i1 false)
  %14 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  %get_stack = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %14, i32 1016, i64 256)
  %15 = icmp sge i32 %get_stack, 8
  br i1 %15, label %get_stack_success, label %get_stack_fail

get_stack_success:                                ; preds = %lookup_stack_scratch_merge
  %16 = udiv i32 %get_stack, 8
  %17 = bitcast i64* %seed to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  store i64 %get_pid_tgid, i64* %seed, align 8
  %18 = trunc i32 %16 to i8
  %19 = load i64, i64* %seed, align 8
  %murmur_hash_2 = call i64 @murmur_hash_2(i8* %14, i8 %18, i64 %19)
  %20 = bitcast [49 x i8]* %fmt_str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %20)
  %21 = bitcast [49 x i8]* %fmt_str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %21, i8 0, i64 49, i1 false)
  store [49 x i8] c"[BPFTRACE_DEBUG_OUTPUT] Stack id %llu. Len: %llu\00", [49 x i8]* %fmt_str, align 1
  %22 = bitcast [49 x i8]* %fmt_str to i8*
  %trace_printk = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* %22, i32 49, i64 %murmur_hash_2, i32 %16)
  store i64 %murmur_hash_2, i64* %stackid, align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t.0"*, i64*, [127 x i64]*, i64)*)(%"struct map_t.0"* @stack_bpftrace_127, i64* %stackid, [127 x i64]* %lookup_stack_scratch_map, i64 0)
  br label %merge_block

get_stack_fail:                                   ; preds = %lookup_stack_scratch_merge
  store i64 0, i64* %stackid, align 8
  br label %merge_block
}

; Function Attrs: alwaysinline
define internal i64 @murmur_hash_2(i8* %0, i8 %1, i64 %2) #1 section "helpers" {
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
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { alwaysinline }
attributes #2 = { argmemonly nofree nosync nounwind willreturn }
attributes #3 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!76}
!llvm.module.flags = !{!79}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 131072, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 4096, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !20, size: 64, offset: 192)
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!21 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 128, elements: !23)
!22 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!23 = !{!24}
!24 = !DISubrange(count: 16, lowerBound: 0)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !28)
!28 = !{!5, !29, !16, !34}
!29 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !30, size: 64, offset: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 4194304, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 131072, lowerBound: 0)
!34 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !35, size: 64, offset: 192)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 8128, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 127, lowerBound: 0)
!39 = !DIGlobalVariableExpression(var: !40, expr: !DIExpression())
!40 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !41, isLocal: false, isDefinition: true)
!41 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !42)
!42 = !{!43, !48, !49, !34}
!43 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !44, size: 64)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 6, lowerBound: 0)
!48 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!49 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !50, size: 64, offset: 128)
!50 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !51, size: 64)
!51 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!52 = !DIGlobalVariableExpression(var: !53, expr: !DIExpression())
!53 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !54, isLocal: false, isDefinition: true)
!54 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !55)
!55 = !{!56, !61}
!56 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !57, size: 64)
!57 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !58, size: 64)
!58 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !59)
!59 = !{!60}
!60 = !DISubrange(count: 27, lowerBound: 0)
!61 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !62, size: 64, offset: 64)
!62 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !63, size: 64)
!63 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !64)
!64 = !{!65}
!65 = !DISubrange(count: 262144, lowerBound: 0)
!66 = !DIGlobalVariableExpression(var: !67, expr: !DIExpression())
!67 = distinct !DIGlobalVariable(name: "ringbuf_loss_counter", linkageName: "global", scope: !2, file: !2, type: !68, isLocal: false, isDefinition: true)
!68 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !69)
!69 = !{!70, !48, !49, !75}
!70 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !71, size: 64)
!71 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !72, size: 64)
!72 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !73)
!73 = !{!74}
!74 = !DISubrange(count: 2, lowerBound: 0)
!75 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!76 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !77, globals: !78)
!77 = !{}
!78 = !{!0, !25, !39, !52, !66}
!79 = !{i32 2, !"Debug Info Version", i32 3}
!80 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !2, file: !2, type: !81, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !76, retainedNodes: !84)
!81 = !DISubroutineType(types: !82)
!82 = !{!18, !83}
!83 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!84 = !{!85, !86}
!85 = !DILocalVariable(name: "var0", scope: !80, file: !2, type: !18)
!86 = !DILocalVariable(name: "var1", arg: 1, scope: !80, file: !2, type: !83)
