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

@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@AT_z = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !22
@stack_perf_127 = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !24
@stack_bpftrace_6 = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !38
@stack_bpftrace_127 = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !47
@stack_scratch = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !49
@ringbuf = dso_local global %"struct map_t.6" zeroinitializer, section ".maps", !dbg !60
@ringbuf_loss_counter = dso_local global %"struct map_t.7" zeroinitializer, section ".maps", !dbg !74

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !87 {
entry:
  %"@z_val" = alloca i64, align 8
  %"@z_key" = alloca i64, align 8
  %fmt_str32 = alloca [49 x i8], align 1
  %seed30 = alloca i64, align 8
  %lookup_stack_scratch_key22 = alloca i32, align 4
  %stackid19 = alloca i64, align 8
  %"@y_val" = alloca i64, align 8
  %"@y_key" = alloca i64, align 8
  %fmt_str15 = alloca [49 x i8], align 1
  %seed13 = alloca i64, align 8
  %lookup_stack_scratch_key5 = alloca i32, align 4
  %stackid2 = alloca i64, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %fmt_str = alloca [49 x i8], align 1
  %seed = alloca i64, align 8
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
  %5 = load i64, i64* %stackid, align 8
  %6 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  store i64 0, i64* %"@x_key", align 8
  %7 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 %5, i64* %"@x_val", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key", i64* %"@x_val", i64 0)
  %8 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %stackid2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  %11 = bitcast i32* %lookup_stack_scratch_key5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i32 0, i32* %lookup_stack_scratch_key5, align 4
  %lookup_stack_scratch_map6 = call [6 x i64]* inttoptr (i64 1 to [6 x i64]* (%"struct map_t.5"*, i32*)*)(%"struct map_t.5"* @stack_scratch, i32* %lookup_stack_scratch_key5)
  %12 = bitcast i32* %lookup_stack_scratch_key5 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  %13 = bitcast [6 x i64]* %lookup_stack_scratch_map6 to i8*
  %lookup_stack_scratch_cond9 = icmp ne i8* %13, null
  br i1 %lookup_stack_scratch_cond9, label %lookup_stack_scratch_merge8, label %lookup_stack_scratch_failure7

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %14 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %14, i8 0, i64 1016, i1 false)
  %15 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  %get_stack = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %15, i32 1016, i64 0)
  %16 = icmp sge i32 %get_stack, 8
  br i1 %16, label %get_stack_success, label %get_stack_fail

get_stack_success:                                ; preds = %lookup_stack_scratch_merge
  %17 = udiv i32 %get_stack, 8
  %18 = bitcast i64* %seed to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i64 1, i64* %seed, align 8
  %19 = trunc i32 %17 to i8
  %20 = load i64, i64* %seed, align 8
  %murmur_hash_2 = call i64 @murmur_hash_2(i8* %15, i8 %19, i64 %20)
  %21 = bitcast [49 x i8]* %fmt_str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  %22 = bitcast [49 x i8]* %fmt_str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %22, i8 0, i64 49, i1 false)
  store [49 x i8] c"[BPFTRACE_DEBUG_OUTPUT] Stack id %llu. Len: %llu\00", [49 x i8]* %fmt_str, align 1
  %23 = bitcast [49 x i8]* %fmt_str to i8*
  %trace_printk = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* %23, i32 49, i64 %murmur_hash_2, i32 %17)
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
  %24 = load i64, i64* %stackid2, align 8
  %25 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %25)
  store i64 0, i64* %"@y_key", align 8
  %26 = bitcast i64* %"@y_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %26)
  store i64 %24, i64* %"@y_val", align 8
  %update_elem18 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.0"*, i64*, i64*, i64)*)(%"struct map_t.0"* @AT_y, i64* %"@y_key", i64* %"@y_val", i64 0)
  %27 = bitcast i64* %"@y_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %27)
  %28 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %28)
  %29 = bitcast i64* %stackid19 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %29)
  %30 = bitcast i32* %lookup_stack_scratch_key22 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %30)
  store i32 0, i32* %lookup_stack_scratch_key22, align 4
  %lookup_stack_scratch_map23 = call [127 x i64]* inttoptr (i64 1 to [127 x i64]* (%"struct map_t.5"*, i32*)*)(%"struct map_t.5"* @stack_scratch, i32* %lookup_stack_scratch_key22)
  %31 = bitcast i32* %lookup_stack_scratch_key22 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = bitcast [127 x i64]* %lookup_stack_scratch_map23 to i8*
  %lookup_stack_scratch_cond26 = icmp ne i8* %32, null
  br i1 %lookup_stack_scratch_cond26, label %lookup_stack_scratch_merge25, label %lookup_stack_scratch_failure24

lookup_stack_scratch_failure7:                    ; preds = %merge_block
  br label %stack_scratch_failure3

lookup_stack_scratch_merge8:                      ; preds = %merge_block
  %33 = bitcast [6 x i64]* %lookup_stack_scratch_map6 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %33, i8 0, i64 48, i1 false)
  %34 = bitcast [6 x i64]* %lookup_stack_scratch_map6 to i8*
  %get_stack12 = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %34, i32 48, i64 0)
  %35 = icmp sge i32 %get_stack12, 8
  br i1 %35, label %get_stack_success10, label %get_stack_fail11

get_stack_success10:                              ; preds = %lookup_stack_scratch_merge8
  %36 = udiv i32 %get_stack12, 8
  %37 = bitcast i64* %seed13 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %37)
  store i64 1, i64* %seed13, align 8
  %38 = trunc i32 %36 to i8
  %39 = load i64, i64* %seed13, align 8
  %murmur_hash_214 = call i64 @murmur_hash_2(i8* %34, i8 %38, i64 %39)
  %40 = bitcast [49 x i8]* %fmt_str15 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %40)
  %41 = bitcast [49 x i8]* %fmt_str15 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %41, i8 0, i64 49, i1 false)
  store [49 x i8] c"[BPFTRACE_DEBUG_OUTPUT] Stack id %llu. Len: %llu\00", [49 x i8]* %fmt_str15, align 1
  %42 = bitcast [49 x i8]* %fmt_str15 to i8*
  %trace_printk16 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* %42, i32 49, i64 %murmur_hash_214, i32 %36)
  store i64 %murmur_hash_214, i64* %stackid2, align 8
  %update_elem17 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.3"*, i64*, [6 x i64]*, i64)*)(%"struct map_t.3"* @stack_bpftrace_6, i64* %stackid2, [6 x i64]* %lookup_stack_scratch_map6, i64 0)
  br label %merge_block4

get_stack_fail11:                                 ; preds = %lookup_stack_scratch_merge8
  store i64 0, i64* %stackid2, align 8
  br label %merge_block4

stack_scratch_failure20:                          ; preds = %lookup_stack_scratch_failure24
  store i64 0, i64* %stackid19, align 8
  br label %merge_block21

merge_block21:                                    ; preds = %stack_scratch_failure20, %get_stack_success27, %get_stack_fail28
  %43 = load i64, i64* %stackid19, align 8
  %44 = bitcast i64* %"@z_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %44)
  store i64 0, i64* %"@z_key", align 8
  %45 = bitcast i64* %"@z_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %45)
  store i64 %43, i64* %"@z_val", align 8
  %update_elem35 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.1"*, i64*, i64*, i64)*)(%"struct map_t.1"* @AT_z, i64* %"@z_key", i64* %"@z_val", i64 0)
  %46 = bitcast i64* %"@z_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %46)
  %47 = bitcast i64* %"@z_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %47)
  ret i64 0

lookup_stack_scratch_failure24:                   ; preds = %merge_block4
  br label %stack_scratch_failure20

lookup_stack_scratch_merge25:                     ; preds = %merge_block4
  %48 = bitcast [127 x i64]* %lookup_stack_scratch_map23 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %48, i8 0, i64 1016, i1 false)
  %49 = bitcast [127 x i64]* %lookup_stack_scratch_map23 to i8*
  %get_stack29 = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %49, i32 1016, i64 0)
  %50 = icmp sge i32 %get_stack29, 8
  br i1 %50, label %get_stack_success27, label %get_stack_fail28

get_stack_success27:                              ; preds = %lookup_stack_scratch_merge25
  %51 = udiv i32 %get_stack29, 8
  %52 = bitcast i64* %seed30 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %52)
  store i64 1, i64* %seed30, align 8
  %53 = trunc i32 %51 to i8
  %54 = load i64, i64* %seed30, align 8
  %murmur_hash_231 = call i64 @murmur_hash_2(i8* %49, i8 %53, i64 %54)
  %55 = bitcast [49 x i8]* %fmt_str32 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %55)
  %56 = bitcast [49 x i8]* %fmt_str32 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %56, i8 0, i64 49, i1 false)
  store [49 x i8] c"[BPFTRACE_DEBUG_OUTPUT] Stack id %llu. Len: %llu\00", [49 x i8]* %fmt_str32, align 1
  %57 = bitcast [49 x i8]* %fmt_str32 to i8*
  %trace_printk33 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* %57, i32 49, i64 %murmur_hash_231, i32 %51)
  store i64 %murmur_hash_231, i64* %stackid19, align 8
  %update_elem34 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.2"*, i64*, [127 x i64]*, i64)*)(%"struct map_t.2"* @stack_perf_127, i64* %stackid19, [127 x i64]* %lookup_stack_scratch_map23, i64 0)
  br label %merge_block21

get_stack_fail28:                                 ; preds = %lookup_stack_scratch_merge25
  store i64 0, i64* %stackid19, align 8
  br label %merge_block21
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

!llvm.dbg.cu = !{!83}
!llvm.module.flags = !{!86}

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
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!20 = !DIGlobalVariableExpression(var: !21, expr: !DIExpression())
!21 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "AT_z", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!24 = !DIGlobalVariableExpression(var: !25, expr: !DIExpression())
!25 = distinct !DIGlobalVariable(name: "stack_perf_127", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!26 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !27)
!27 = !{!5, !28, !16, !33}
!28 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !29, size: 64, offset: 64)
!29 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !30, size: 64)
!30 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 4194304, elements: !31)
!31 = !{!32}
!32 = !DISubrange(count: 131072, lowerBound: 0)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !34, size: 64, offset: 192)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 8128, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 127, lowerBound: 0)
!38 = !DIGlobalVariableExpression(var: !39, expr: !DIExpression())
!39 = distinct !DIGlobalVariable(name: "stack_bpftrace_6", linkageName: "global", scope: !2, file: !2, type: !40, isLocal: false, isDefinition: true)
!40 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !41)
!41 = !{!5, !28, !16, !42}
!42 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !43, size: 64, offset: 192)
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !44, size: 64)
!44 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 384, elements: !45)
!45 = !{!46}
!46 = !DISubrange(count: 6, lowerBound: 0)
!47 = !DIGlobalVariableExpression(var: !48, expr: !DIExpression())
!48 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!49 = !DIGlobalVariableExpression(var: !50, expr: !DIExpression())
!50 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !51, isLocal: false, isDefinition: true)
!51 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !52)
!52 = !{!53, !56, !57, !33}
!53 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !54, size: 64)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !45)
!56 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!57 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !58, size: 64, offset: 128)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!59 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!60 = !DIGlobalVariableExpression(var: !61, expr: !DIExpression())
!61 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !62, isLocal: false, isDefinition: true)
!62 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !63)
!63 = !{!64, !69}
!64 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !65, size: 64)
!65 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !66, size: 64)
!66 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !67)
!67 = !{!68}
!68 = !DISubrange(count: 27, lowerBound: 0)
!69 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !70, size: 64, offset: 64)
!70 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !71, size: 64)
!71 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !72)
!72 = !{!73}
!73 = !DISubrange(count: 262144, lowerBound: 0)
!74 = !DIGlobalVariableExpression(var: !75, expr: !DIExpression())
!75 = distinct !DIGlobalVariable(name: "ringbuf_loss_counter", linkageName: "global", scope: !2, file: !2, type: !76, isLocal: false, isDefinition: true)
!76 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !77)
!77 = !{!78, !56, !57, !19}
!78 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !79, size: 64)
!79 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !80, size: 64)
!80 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !81)
!81 = !{!82}
!82 = !DISubrange(count: 2, lowerBound: 0)
!83 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !84, globals: !85)
!84 = !{}
!85 = !{!0, !20, !22, !24, !38, !47, !49, !60, !74}
!86 = !{i32 2, !"Debug Info Version", i32 3}
!87 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !2, file: !2, type: !88, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !83, retainedNodes: !92)
!88 = !DISubroutineType(types: !89)
!89 = !{!18, !90}
!90 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !91, size: 64)
!91 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!92 = !{!93, !94}
!93 = !DILocalVariable(name: "var0", scope: !87, file: !2, type: !18)
!94 = !DILocalVariable(name: "var1", arg: 1, scope: !87, file: !2, type: !90)
