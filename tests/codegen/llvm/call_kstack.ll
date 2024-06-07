; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%"struct map_t.2" = type { i8*, i8*, i8*, i8* }
%"struct map_t.3" = type { i8*, i8*, i8*, i8* }
%"struct map_t.4" = type { i8*, i8*, i8*, i8* }
%"struct map_t.5" = type { i8*, i8*, i8*, i8* }
%"struct map_t.6" = type { i8*, i8* }
%"struct map_t.7" = type { i8*, i8*, i8*, i8* }
%stack_key = type { i64, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@AT_z = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !27
@stack_perf_127 = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !29
@stack_bpftrace_6 = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !49
@stack_bpftrace_127 = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !58
@stack_scratch = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !60
@ringbuf = dso_local global %"struct map_t.6" zeroinitializer, section ".maps", !dbg !71
@event_loss_counter = dso_local global %"struct map_t.7" zeroinitializer, section ".maps", !dbg !85

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !99 {
entry:
  %"@z_key" = alloca i64, align 8
  %lookup_stack_scratch_key19 = alloca i32, align 4
  %stack_key16 = alloca %stack_key, align 8
  %"@y_key" = alloca i64, align 8
  %lookup_stack_scratch_key5 = alloca i32, align 4
  %stack_key2 = alloca %stack_key, align 8
  %"@x_key" = alloca i64, align 8
  %lookup_stack_scratch_key = alloca i32, align 4
  %stack_key = alloca %stack_key, align 8
  %1 = bitcast %stack_key* %stack_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = getelementptr %stack_key, %stack_key* %stack_key, i64 0, i32 0
  store i64 0, i64* %2, align 8
  %3 = getelementptr %stack_key, %stack_key* %stack_key, i64 0, i32 1
  store i32 0, i32* %3, align 4
  %4 = bitcast i32* %lookup_stack_scratch_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i32 0, i32* %lookup_stack_scratch_key, align 4
  %lookup_stack_scratch_map = call [127 x i64]* inttoptr (i64 1 to [127 x i64]* (%"struct map_t.5"*, i32*)*)(%"struct map_t.5"* @stack_scratch, i32* %lookup_stack_scratch_key)
  %5 = bitcast i32* %lookup_stack_scratch_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  %lookup_stack_scratch_cond = icmp ne i8* %6, null
  br i1 %lookup_stack_scratch_cond, label %lookup_stack_scratch_merge, label %lookup_stack_scratch_failure

stack_scratch_failure:                            ; preds = %lookup_stack_scratch_failure
  br label %merge_block

merge_block:                                      ; preds = %stack_scratch_failure, %get_stack_success, %get_stack_fail
  %7 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 0, i64* %"@x_key", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, %stack_key*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key", %stack_key* %stack_key, i64 0)
  %8 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast %stack_key* %stack_key2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %10 = getelementptr %stack_key, %stack_key* %stack_key2, i64 0, i32 0
  store i64 0, i64* %10, align 8
  %11 = getelementptr %stack_key, %stack_key* %stack_key2, i64 0, i32 1
  store i32 0, i32* %11, align 4
  %12 = bitcast i32* %lookup_stack_scratch_key5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  store i32 0, i32* %lookup_stack_scratch_key5, align 4
  %lookup_stack_scratch_map6 = call [6 x i64]* inttoptr (i64 1 to [6 x i64]* (%"struct map_t.5"*, i32*)*)(%"struct map_t.5"* @stack_scratch, i32* %lookup_stack_scratch_key5)
  %13 = bitcast i32* %lookup_stack_scratch_key5 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  %14 = bitcast [6 x i64]* %lookup_stack_scratch_map6 to i8*
  %lookup_stack_scratch_cond9 = icmp ne i8* %14, null
  br i1 %lookup_stack_scratch_cond9, label %lookup_stack_scratch_merge8, label %lookup_stack_scratch_failure7

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([127 x i64]*, i32, i8*)*)([127 x i64]* %lookup_stack_scratch_map, i32 1016, i8* null)
  %15 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  %get_stack = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %15, i32 1016, i64 0)
  %16 = icmp sge i32 %get_stack, 0
  br i1 %16, label %get_stack_success, label %get_stack_fail

get_stack_success:                                ; preds = %lookup_stack_scratch_merge
  %17 = udiv i32 %get_stack, 8
  %18 = getelementptr %stack_key, %stack_key* %stack_key, i64 0, i32 1
  store i32 %17, i32* %18, align 4
  %19 = trunc i32 %17 to i8
  %murmur_hash_2 = call i64 @murmur_hash_2(i8* %15, i8 %19, i64 1)
  %20 = getelementptr %stack_key, %stack_key* %stack_key, i64 0, i32 0
  store i64 %murmur_hash_2, i64* %20, align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t.4"*, %stack_key*, [127 x i64]*, i64)*)(%"struct map_t.4"* @stack_bpftrace_127, %stack_key* %stack_key, [127 x i64]* %lookup_stack_scratch_map, i64 0)
  br label %merge_block

get_stack_fail:                                   ; preds = %lookup_stack_scratch_merge
  br label %merge_block

stack_scratch_failure3:                           ; preds = %lookup_stack_scratch_failure7
  br label %merge_block4

merge_block4:                                     ; preds = %stack_scratch_failure3, %get_stack_success10, %get_stack_fail11
  %21 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  store i64 0, i64* %"@y_key", align 8
  %update_elem15 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.0"*, i64*, %stack_key*, i64)*)(%"struct map_t.0"* @AT_y, i64* %"@y_key", %stack_key* %stack_key2, i64 0)
  %22 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  %23 = bitcast %stack_key* %stack_key16 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  %24 = getelementptr %stack_key, %stack_key* %stack_key16, i64 0, i32 0
  store i64 0, i64* %24, align 8
  %25 = getelementptr %stack_key, %stack_key* %stack_key16, i64 0, i32 1
  store i32 0, i32* %25, align 4
  %26 = bitcast i32* %lookup_stack_scratch_key19 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %26)
  store i32 0, i32* %lookup_stack_scratch_key19, align 4
  %lookup_stack_scratch_map20 = call [127 x i64]* inttoptr (i64 1 to [127 x i64]* (%"struct map_t.5"*, i32*)*)(%"struct map_t.5"* @stack_scratch, i32* %lookup_stack_scratch_key19)
  %27 = bitcast i32* %lookup_stack_scratch_key19 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %27)
  %28 = bitcast [127 x i64]* %lookup_stack_scratch_map20 to i8*
  %lookup_stack_scratch_cond23 = icmp ne i8* %28, null
  br i1 %lookup_stack_scratch_cond23, label %lookup_stack_scratch_merge22, label %lookup_stack_scratch_failure21

lookup_stack_scratch_failure7:                    ; preds = %merge_block
  br label %stack_scratch_failure3

lookup_stack_scratch_merge8:                      ; preds = %merge_block
  %29 = bitcast [6 x i64]* %lookup_stack_scratch_map6 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %29, i8 0, i64 48, i1 false)
  %30 = bitcast [6 x i64]* %lookup_stack_scratch_map6 to i8*
  %get_stack12 = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %30, i32 48, i64 0)
  %31 = icmp sge i32 %get_stack12, 0
  br i1 %31, label %get_stack_success10, label %get_stack_fail11

get_stack_success10:                              ; preds = %lookup_stack_scratch_merge8
  %32 = udiv i32 %get_stack12, 8
  %33 = getelementptr %stack_key, %stack_key* %stack_key2, i64 0, i32 1
  store i32 %32, i32* %33, align 4
  %34 = trunc i32 %32 to i8
  %murmur_hash_213 = call i64 @murmur_hash_2(i8* %30, i8 %34, i64 1)
  %35 = getelementptr %stack_key, %stack_key* %stack_key2, i64 0, i32 0
  store i64 %murmur_hash_213, i64* %35, align 8
  %update_elem14 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.3"*, %stack_key*, [6 x i64]*, i64)*)(%"struct map_t.3"* @stack_bpftrace_6, %stack_key* %stack_key2, [6 x i64]* %lookup_stack_scratch_map6, i64 0)
  br label %merge_block4

get_stack_fail11:                                 ; preds = %lookup_stack_scratch_merge8
  br label %merge_block4

stack_scratch_failure17:                          ; preds = %lookup_stack_scratch_failure21
  br label %merge_block18

merge_block18:                                    ; preds = %stack_scratch_failure17, %get_stack_success25, %get_stack_fail26
  %36 = bitcast i64* %"@z_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %36)
  store i64 0, i64* %"@z_key", align 8
  %update_elem30 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.1"*, i64*, %stack_key*, i64)*)(%"struct map_t.1"* @AT_z, i64* %"@z_key", %stack_key* %stack_key16, i64 0)
  %37 = bitcast i64* %"@z_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %37)
  ret i64 0

lookup_stack_scratch_failure21:                   ; preds = %merge_block4
  br label %stack_scratch_failure17

lookup_stack_scratch_merge22:                     ; preds = %merge_block4
  %probe_read_kernel24 = call i64 inttoptr (i64 113 to i64 ([127 x i64]*, i32, i8*)*)([127 x i64]* %lookup_stack_scratch_map20, i32 1016, i8* null)
  %38 = bitcast [127 x i64]* %lookup_stack_scratch_map20 to i8*
  %get_stack27 = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %38, i32 1016, i64 0)
  %39 = icmp sge i32 %get_stack27, 0
  br i1 %39, label %get_stack_success25, label %get_stack_fail26

get_stack_success25:                              ; preds = %lookup_stack_scratch_merge22
  %40 = udiv i32 %get_stack27, 8
  %41 = getelementptr %stack_key, %stack_key* %stack_key16, i64 0, i32 1
  store i32 %40, i32* %41, align 4
  %42 = trunc i32 %40 to i8
  %murmur_hash_228 = call i64 @murmur_hash_2(i8* %38, i8 %42, i64 1)
  %43 = getelementptr %stack_key, %stack_key* %stack_key16, i64 0, i32 0
  store i64 %murmur_hash_228, i64* %43, align 8
  %update_elem29 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.2"*, %stack_key*, [127 x i64]*, i64)*)(%"struct map_t.2"* @stack_perf_127, %stack_key* %stack_key16, [127 x i64]* %lookup_stack_scratch_map20, i64 0)
  br label %merge_block18

get_stack_fail26:                                 ; preds = %lookup_stack_scratch_merge22
  br label %merge_block18
}

; Function Attrs: alwaysinline
define internal i64 @murmur_hash_2(i8* %0, i8 %1, i64 %2) #1 section "helpers" {
entry:
  %k = alloca i64, align 8
  %i = alloca i8, align 1
  %id = alloca i64, align 8
  %seed_addr = alloca i64, align 8
  %nr_stack_frames_addr = alloca i8, align 1
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %nr_stack_frames_addr)
  %3 = bitcast i64* %seed_addr to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %id to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %i)
  %5 = bitcast i64* %k to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast i8* %0 to i64*
  store i8 %1, i8* %nr_stack_frames_addr, align 1
  store i64 %2, i64* %seed_addr, align 8
  %7 = load i8, i8* %nr_stack_frames_addr, align 1
  %8 = zext i8 %7 to i64
  %9 = mul i64 %8, -4132994306676758123
  %10 = load i64, i64* %seed_addr, align 8
  %11 = xor i64 %10, %9
  store i64 %11, i64* %id, align 8
  store i8 0, i8* %i, align 1
  br label %while_cond

while_cond:                                       ; preds = %while_body, %entry
  %12 = load i8, i8* %nr_stack_frames_addr, align 1
  %13 = load i8, i8* %i, align 1
  %length.cmp = icmp ult i8 %13, %12
  br i1 %length.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %14 = load i8, i8* %i, align 1
  %15 = getelementptr i64, i64* %6, i8 %14
  %16 = load i64, i64* %15, align 8
  store i64 %16, i64* %k, align 8
  %17 = load i64, i64* %k, align 8
  %18 = mul i64 %17, -4132994306676758123
  store i64 %18, i64* %k, align 8
  %19 = load i64, i64* %k, align 8
  %20 = lshr i64 %19, 47
  %21 = load i64, i64* %k, align 8
  %22 = xor i64 %21, %20
  store i64 %22, i64* %k, align 8
  %23 = load i64, i64* %k, align 8
  %24 = mul i64 %23, -4132994306676758123
  store i64 %24, i64* %k, align 8
  %25 = load i64, i64* %k, align 8
  %26 = load i64, i64* %id, align 8
  %27 = xor i64 %26, %25
  store i64 %27, i64* %id, align 8
  %28 = load i64, i64* %id, align 8
  %29 = mul i64 %28, -4132994306676758123
  store i64 %29, i64* %id, align 8
  %30 = load i8, i8* %i, align 1
  %31 = add i8 %30, 1
  store i8 %31, i8* %i, align 1
  br label %while_cond

while_end:                                        ; preds = %while_cond
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %nr_stack_frames_addr)
  %32 = bitcast i64* %seed_addr to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %32)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %i)
  %33 = bitcast i64* %k to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %33)
  %34 = load i64, i64* %id, align 8
  %zero_cond = icmp eq i64 %34, 0
  br i1 %zero_cond, label %if_zero, label %if_end

if_zero:                                          ; preds = %while_end
  store i64 1, i64* %id, align 8
  br label %if_end

if_end:                                           ; preds = %if_zero, %while_end
  %35 = load i64, i64* %id, align 8
  %36 = bitcast i64* %id to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %36)
  ret i64 %35
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

!llvm.dbg.cu = !{!95}
!llvm.module.flags = !{!98}

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
!21 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 96, elements: !23)
!22 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!23 = !{!24}
!24 = !DISubrange(count: 12, lowerBound: 0)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!27 = !DIGlobalVariableExpression(var: !28, expr: !DIExpression())
!28 = distinct !DIGlobalVariable(name: "AT_z", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "stack_perf_127", linkageName: "global", scope: !2, file: !2, type: !31, isLocal: false, isDefinition: true)
!31 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !32)
!32 = !{!33, !38, !43, !44}
!33 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !34, size: 64)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 288, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 9, lowerBound: 0)
!38 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !39, size: 64, offset: 64)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 4194304, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 131072, lowerBound: 0)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !20, size: 64, offset: 128)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !45, size: 64, offset: 192)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 8128, elements: !47)
!47 = !{!48}
!48 = !DISubrange(count: 127, lowerBound: 0)
!49 = !DIGlobalVariableExpression(var: !50, expr: !DIExpression())
!50 = distinct !DIGlobalVariable(name: "stack_bpftrace_6", linkageName: "global", scope: !2, file: !2, type: !51, isLocal: false, isDefinition: true)
!51 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !52)
!52 = !{!33, !38, !43, !53}
!53 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !54, size: 64, offset: 192)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 384, elements: !56)
!56 = !{!57}
!57 = !DISubrange(count: 6, lowerBound: 0)
!58 = !DIGlobalVariableExpression(var: !59, expr: !DIExpression())
!59 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !31, isLocal: false, isDefinition: true)
!60 = !DIGlobalVariableExpression(var: !61, expr: !DIExpression())
!61 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !62, isLocal: false, isDefinition: true)
!62 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !63)
!63 = !{!64, !67, !68, !44}
!64 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !65, size: 64)
!65 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !66, size: 64)
!66 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !56)
!67 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!68 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !69, size: 64, offset: 128)
!69 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !70, size: 64)
!70 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!71 = !DIGlobalVariableExpression(var: !72, expr: !DIExpression())
!72 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !73, isLocal: false, isDefinition: true)
!73 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !74)
!74 = !{!75, !80}
!75 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !76, size: 64)
!76 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !77, size: 64)
!77 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !78)
!78 = !{!79}
!79 = !DISubrange(count: 27, lowerBound: 0)
!80 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !81, size: 64, offset: 64)
!81 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !82, size: 64)
!82 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !83)
!83 = !{!84}
!84 = !DISubrange(count: 262144, lowerBound: 0)
!85 = !DIGlobalVariableExpression(var: !86, expr: !DIExpression())
!86 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !87, isLocal: false, isDefinition: true)
!87 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !88)
!88 = !{!89, !67, !68, !94}
!89 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !90, size: 64)
!90 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !91, size: 64)
!91 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !92)
!92 = !{!93}
!93 = !DISubrange(count: 2, lowerBound: 0)
!94 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!95 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !96, globals: !97)
!96 = !{}
!97 = !{!0, !25, !27, !29, !49, !58, !60, !71, !85}
!98 = !{i32 2, !"Debug Info Version", i32 3}
!99 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !100, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !95, retainedNodes: !103)
!100 = !DISubroutineType(types: !101)
!101 = !{!18, !102}
!102 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!103 = !{!104}
!104 = !DILocalVariable(name: "ctx", arg: 1, scope: !99, file: !2, type: !102)
