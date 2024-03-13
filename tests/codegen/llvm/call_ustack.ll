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
%stack_t = type { i64, i32, i32 }

@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@AT_z = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !27
@stack_perf_127 = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !29
@stack_bpftrace_6 = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !48
@stack_bpftrace_127 = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !57
@stack_scratch = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !59
@ringbuf = dso_local global %"struct map_t.6" zeroinitializer, section ".maps", !dbg !70
@ringbuf_loss_counter = dso_local global %"struct map_t.7" zeroinitializer, section ".maps", !dbg !84

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !98 {
entry:
  %"@z_key" = alloca i64, align 8
  %stack_args31 = alloca %stack_t, align 8
  %lookup_stack_scratch_key21 = alloca i32, align 4
  %stackid18 = alloca i64, align 8
  %"@y_key" = alloca i64, align 8
  %stack_args15 = alloca %stack_t, align 8
  %lookup_stack_scratch_key5 = alloca i32, align 4
  %stackid2 = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %stack_args = alloca %stack_t, align 8
  %lookup_stack_scratch_key = alloca i32, align 4
  %stackid = alloca i64, align 8
  %1 = bitcast i64* %stackid to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast i32* %lookup_stack_scratch_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i32 0, i32* %lookup_stack_scratch_key, align 4
  %lookup_stack_scratch_map = call [127 x i64]* inttoptr (i64 1 to [127 x i64]* (%"struct map_t.5"*, i32*)*)(%"struct map_t.5"* @stack_scratch, i32* %lookup_stack_scratch_key)
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
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %9 = trunc i64 %get_pid_tgid to i32
  store i32 %9, i32* %8, align 4
  %10 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 2
  store i32 0, i32* %10, align 4
  %11 = bitcast i64* %stackid to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  store i64 0, i64* %"@x_key", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, %stack_t*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key", %stack_t* %stack_args, i64 0)
  %13 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  %14 = bitcast i64* %stackid2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  %15 = bitcast i32* %lookup_stack_scratch_key5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  store i32 0, i32* %lookup_stack_scratch_key5, align 4
  %lookup_stack_scratch_map6 = call [6 x i64]* inttoptr (i64 1 to [6 x i64]* (%"struct map_t.5"*, i32*)*)(%"struct map_t.5"* @stack_scratch, i32* %lookup_stack_scratch_key5)
  %16 = bitcast i32* %lookup_stack_scratch_key5 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast [6 x i64]* %lookup_stack_scratch_map6 to i8*
  %lookup_stack_scratch_cond9 = icmp ne i8* %17, null
  br i1 %lookup_stack_scratch_cond9, label %lookup_stack_scratch_merge8, label %lookup_stack_scratch_failure7

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %18 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %18, i8 0, i64 1016, i1 false)
  %19 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  %get_stack = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %19, i32 1016, i64 256)
  %20 = icmp sge i32 %get_stack, 0
  br i1 %20, label %get_stack_success, label %get_stack_fail

get_stack_success:                                ; preds = %lookup_stack_scratch_merge
  %21 = udiv i32 %get_stack, 8
  %22 = trunc i32 %21 to i8
  %murmur_hash_2 = call i64 @murmur_hash_2(i8* %19, i8 %22, i64 1)
  store i64 %murmur_hash_2, i64* %stackid, align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t.4"*, i64*, [127 x i64]*, i64)*)(%"struct map_t.4"* @stack_bpftrace_127, i64* %stackid, [127 x i64]* %lookup_stack_scratch_map, i64 0)
  br label %merge_block

get_stack_fail:                                   ; preds = %lookup_stack_scratch_merge
  store i64 0, i64* %stackid, align 8
  br label %merge_block

stack_scratch_failure3:                           ; preds = %lookup_stack_scratch_failure7
  store i64 0, i64* %stackid2, align 8
  br label %merge_block4

merge_block4:                                     ; preds = %stack_scratch_failure3, %get_stack_success10, %get_stack_fail11
  %23 = bitcast %stack_t* %stack_args15 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  %24 = getelementptr %stack_t, %stack_t* %stack_args15, i64 0, i32 0
  %25 = load i64, i64* %stackid2, align 8
  store i64 %25, i64* %24, align 8
  %26 = getelementptr %stack_t, %stack_t* %stack_args15, i64 0, i32 1
  %get_pid_tgid16 = call i64 inttoptr (i64 14 to i64 ()*)()
  %27 = trunc i64 %get_pid_tgid16 to i32
  store i32 %27, i32* %26, align 4
  %28 = getelementptr %stack_t, %stack_t* %stack_args15, i64 0, i32 2
  store i32 0, i32* %28, align 4
  %29 = bitcast i64* %stackid2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %29)
  %30 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %30)
  store i64 0, i64* %"@y_key", align 8
  %update_elem17 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.0"*, i64*, %stack_t*, i64)*)(%"struct map_t.0"* @AT_y, i64* %"@y_key", %stack_t* %stack_args15, i64 0)
  %31 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = bitcast i64* %stackid18 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %32)
  %33 = bitcast i32* %lookup_stack_scratch_key21 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %33)
  store i32 0, i32* %lookup_stack_scratch_key21, align 4
  %lookup_stack_scratch_map22 = call [127 x i64]* inttoptr (i64 1 to [127 x i64]* (%"struct map_t.5"*, i32*)*)(%"struct map_t.5"* @stack_scratch, i32* %lookup_stack_scratch_key21)
  %34 = bitcast i32* %lookup_stack_scratch_key21 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %34)
  %35 = bitcast [127 x i64]* %lookup_stack_scratch_map22 to i8*
  %lookup_stack_scratch_cond25 = icmp ne i8* %35, null
  br i1 %lookup_stack_scratch_cond25, label %lookup_stack_scratch_merge24, label %lookup_stack_scratch_failure23

lookup_stack_scratch_failure7:                    ; preds = %merge_block
  br label %stack_scratch_failure3

lookup_stack_scratch_merge8:                      ; preds = %merge_block
  %36 = bitcast [6 x i64]* %lookup_stack_scratch_map6 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %36, i8 0, i64 48, i1 false)
  %37 = bitcast [6 x i64]* %lookup_stack_scratch_map6 to i8*
  %get_stack12 = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %37, i32 48, i64 256)
  %38 = icmp sge i32 %get_stack12, 0
  br i1 %38, label %get_stack_success10, label %get_stack_fail11

get_stack_success10:                              ; preds = %lookup_stack_scratch_merge8
  %39 = udiv i32 %get_stack12, 8
  %40 = trunc i32 %39 to i8
  %murmur_hash_213 = call i64 @murmur_hash_2(i8* %37, i8 %40, i64 1)
  store i64 %murmur_hash_213, i64* %stackid2, align 8
  %update_elem14 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.3"*, i64*, [6 x i64]*, i64)*)(%"struct map_t.3"* @stack_bpftrace_6, i64* %stackid2, [6 x i64]* %lookup_stack_scratch_map6, i64 0)
  br label %merge_block4

get_stack_fail11:                                 ; preds = %lookup_stack_scratch_merge8
  store i64 0, i64* %stackid2, align 8
  br label %merge_block4

stack_scratch_failure19:                          ; preds = %lookup_stack_scratch_failure23
  store i64 0, i64* %stackid18, align 8
  br label %merge_block20

merge_block20:                                    ; preds = %stack_scratch_failure19, %get_stack_success26, %get_stack_fail27
  %41 = bitcast %stack_t* %stack_args31 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %41)
  %42 = getelementptr %stack_t, %stack_t* %stack_args31, i64 0, i32 0
  %43 = load i64, i64* %stackid18, align 8
  store i64 %43, i64* %42, align 8
  %44 = getelementptr %stack_t, %stack_t* %stack_args31, i64 0, i32 1
  %get_pid_tgid32 = call i64 inttoptr (i64 14 to i64 ()*)()
  %45 = trunc i64 %get_pid_tgid32 to i32
  store i32 %45, i32* %44, align 4
  %46 = getelementptr %stack_t, %stack_t* %stack_args31, i64 0, i32 2
  store i32 0, i32* %46, align 4
  %47 = bitcast i64* %stackid18 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %47)
  %48 = bitcast i64* %"@z_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %48)
  store i64 0, i64* %"@z_key", align 8
  %update_elem33 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.1"*, i64*, %stack_t*, i64)*)(%"struct map_t.1"* @AT_z, i64* %"@z_key", %stack_t* %stack_args31, i64 0)
  %49 = bitcast i64* %"@z_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %49)
  ret i64 0

lookup_stack_scratch_failure23:                   ; preds = %merge_block4
  br label %stack_scratch_failure19

lookup_stack_scratch_merge24:                     ; preds = %merge_block4
  %50 = bitcast [127 x i64]* %lookup_stack_scratch_map22 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %50, i8 0, i64 1016, i1 false)
  %51 = bitcast [127 x i64]* %lookup_stack_scratch_map22 to i8*
  %get_stack28 = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %51, i32 1016, i64 256)
  %52 = icmp sge i32 %get_stack28, 0
  br i1 %52, label %get_stack_success26, label %get_stack_fail27

get_stack_success26:                              ; preds = %lookup_stack_scratch_merge24
  %53 = udiv i32 %get_stack28, 8
  %54 = trunc i32 %53 to i8
  %murmur_hash_229 = call i64 @murmur_hash_2(i8* %51, i8 %54, i64 1)
  store i64 %murmur_hash_229, i64* %stackid18, align 8
  %update_elem30 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.2"*, i64*, [127 x i64]*, i64)*)(%"struct map_t.2"* @stack_perf_127, i64* %stackid18, [127 x i64]* %lookup_stack_scratch_map22, i64 0)
  br label %merge_block20

get_stack_fail27:                                 ; preds = %lookup_stack_scratch_merge24
  store i64 0, i64* %stackid18, align 8
  br label %merge_block20
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

!llvm.dbg.cu = !{!94}
!llvm.module.flags = !{!97}

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
!26 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!27 = !DIGlobalVariableExpression(var: !28, expr: !DIExpression())
!28 = distinct !DIGlobalVariable(name: "AT_z", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "stack_perf_127", linkageName: "global", scope: !2, file: !2, type: !31, isLocal: false, isDefinition: true)
!31 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !32)
!32 = !{!33, !38, !16, !43}
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
!43 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !44, size: 64, offset: 192)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 8128, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 127, lowerBound: 0)
!48 = !DIGlobalVariableExpression(var: !49, expr: !DIExpression())
!49 = distinct !DIGlobalVariable(name: "stack_bpftrace_6", linkageName: "global", scope: !2, file: !2, type: !50, isLocal: false, isDefinition: true)
!50 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !51)
!51 = !{!33, !38, !16, !52}
!52 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !53, size: 64, offset: 192)
!53 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !54, size: 64)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 384, elements: !55)
!55 = !{!56}
!56 = !DISubrange(count: 6, lowerBound: 0)
!57 = !DIGlobalVariableExpression(var: !58, expr: !DIExpression())
!58 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !31, isLocal: false, isDefinition: true)
!59 = !DIGlobalVariableExpression(var: !60, expr: !DIExpression())
!60 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !61, isLocal: false, isDefinition: true)
!61 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !62)
!62 = !{!63, !66, !67, !43}
!63 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !64, size: 64)
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !65, size: 64)
!65 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !55)
!66 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!67 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !68, size: 64, offset: 128)
!68 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !69, size: 64)
!69 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!70 = !DIGlobalVariableExpression(var: !71, expr: !DIExpression())
!71 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !72, isLocal: false, isDefinition: true)
!72 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !73)
!73 = !{!74, !79}
!74 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !75, size: 64)
!75 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !76, size: 64)
!76 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !77)
!77 = !{!78}
!78 = !DISubrange(count: 27, lowerBound: 0)
!79 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !80, size: 64, offset: 64)
!80 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !81, size: 64)
!81 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !82)
!82 = !{!83}
!83 = !DISubrange(count: 262144, lowerBound: 0)
!84 = !DIGlobalVariableExpression(var: !85, expr: !DIExpression())
!85 = distinct !DIGlobalVariable(name: "ringbuf_loss_counter", linkageName: "global", scope: !2, file: !2, type: !86, isLocal: false, isDefinition: true)
!86 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !87)
!87 = !{!88, !66, !67, !93}
!88 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !89, size: 64)
!89 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !90, size: 64)
!90 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !91)
!91 = !{!92}
!92 = !DISubrange(count: 2, lowerBound: 0)
!93 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!94 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !95, globals: !96)
!95 = !{}
!96 = !{!0, !25, !27, !29, !48, !57, !59, !70, !84}
!97 = !{i32 2, !"Debug Info Version", i32 3}
!98 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !2, file: !2, type: !99, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !94, retainedNodes: !102)
!99 = !DISubroutineType(types: !100)
!100 = !{!18, !101}
!101 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!102 = !{!103, !104}
!103 = !DILocalVariable(name: "var0", scope: !98, file: !2, type: !18)
!104 = !DILocalVariable(name: "var1", arg: 1, scope: !98, file: !2, type: !101)
