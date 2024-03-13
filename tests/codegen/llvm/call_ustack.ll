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
@stack_bpftrace_6 = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !43
@stack_bpftrace_127 = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !52
@stack_scratch = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !54
@ringbuf = dso_local global %"struct map_t.6" zeroinitializer, section ".maps", !dbg !65
@ringbuf_loss_counter = dso_local global %"struct map_t.7" zeroinitializer, section ".maps", !dbg !79

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !93 {
entry:
  %"@z_key" = alloca i64, align 8
  %stack_args40 = alloca %stack_t, align 8
  %fmt_str37 = alloca [49 x i8], align 1
  %seed34 = alloca i64, align 8
  %lookup_stack_scratch_key26 = alloca i32, align 4
  %stackid23 = alloca i64, align 8
  %"@y_key" = alloca i64, align 8
  %stack_args20 = alloca %stack_t, align 8
  %fmt_str17 = alloca [49 x i8], align 1
  %seed14 = alloca i64, align 8
  %lookup_stack_scratch_key6 = alloca i32, align 4
  %stackid3 = alloca i64, align 8
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
  %13 = bitcast i64* %stackid3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  %14 = bitcast i32* %lookup_stack_scratch_key6 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i32 0, i32* %lookup_stack_scratch_key6, align 4
  %lookup_stack_scratch_map7 = call [6 x i64]* inttoptr (i64 1 to [6 x i64]* (%"struct map_t.5"*, i32*)*)(%"struct map_t.5"* @stack_scratch, i32* %lookup_stack_scratch_key6)
  %15 = bitcast i32* %lookup_stack_scratch_key6 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast [6 x i64]* %lookup_stack_scratch_map7 to i8*
  %lookup_stack_scratch_cond10 = icmp ne i8* %16, null
  br i1 %lookup_stack_scratch_cond10, label %lookup_stack_scratch_merge9, label %lookup_stack_scratch_failure8

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
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t.4"*, i64*, [127 x i64]*, i64)*)(%"struct map_t.4"* @stack_bpftrace_127, i64* %stackid, [127 x i64]* %lookup_stack_scratch_map, i64 0)
  br label %merge_block

get_stack_fail:                                   ; preds = %lookup_stack_scratch_merge
  store i64 0, i64* %stackid, align 8
  br label %merge_block

stack_scratch_failure4:                           ; preds = %lookup_stack_scratch_failure8
  store i64 0, i64* %stackid3, align 8
  br label %merge_block5

merge_block5:                                     ; preds = %stack_scratch_failure4, %get_stack_success11, %get_stack_fail12
  %27 = bitcast %stack_t* %stack_args20 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %27)
  %28 = getelementptr %stack_t, %stack_t* %stack_args20, i64 0, i32 0
  %29 = load i64, i64* %stackid3, align 8
  store i64 %29, i64* %28, align 8
  %30 = getelementptr %stack_t, %stack_t* %stack_args20, i64 0, i32 1
  %get_pid_tgid21 = call i64 inttoptr (i64 14 to i64 ()*)()
  %31 = trunc i64 %get_pid_tgid21 to i32
  store i32 %31, i32* %30, align 4
  %32 = getelementptr %stack_t, %stack_t* %stack_args20, i64 0, i32 2
  store i32 0, i32* %32, align 4
  %33 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %33)
  store i64 0, i64* %"@y_key", align 8
  %update_elem22 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.0"*, i64*, %stack_t*, i64)*)(%"struct map_t.0"* @AT_y, i64* %"@y_key", %stack_t* %stack_args20, i64 0)
  %34 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %34)
  %35 = bitcast i64* %stackid23 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %35)
  %36 = bitcast i32* %lookup_stack_scratch_key26 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %36)
  store i32 0, i32* %lookup_stack_scratch_key26, align 4
  %lookup_stack_scratch_map27 = call [127 x i64]* inttoptr (i64 1 to [127 x i64]* (%"struct map_t.5"*, i32*)*)(%"struct map_t.5"* @stack_scratch, i32* %lookup_stack_scratch_key26)
  %37 = bitcast i32* %lookup_stack_scratch_key26 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %37)
  %38 = bitcast [127 x i64]* %lookup_stack_scratch_map27 to i8*
  %lookup_stack_scratch_cond30 = icmp ne i8* %38, null
  br i1 %lookup_stack_scratch_cond30, label %lookup_stack_scratch_merge29, label %lookup_stack_scratch_failure28

lookup_stack_scratch_failure8:                    ; preds = %merge_block
  br label %stack_scratch_failure4

lookup_stack_scratch_merge9:                      ; preds = %merge_block
  %39 = bitcast [6 x i64]* %lookup_stack_scratch_map7 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %39, i8 0, i64 48, i1 false)
  %40 = bitcast [6 x i64]* %lookup_stack_scratch_map7 to i8*
  %get_stack13 = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %40, i32 48, i64 256)
  %41 = icmp sge i32 %get_stack13, 8
  br i1 %41, label %get_stack_success11, label %get_stack_fail12

get_stack_success11:                              ; preds = %lookup_stack_scratch_merge9
  %42 = udiv i32 %get_stack13, 8
  %43 = bitcast i64* %seed14 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %43)
  %get_pid_tgid15 = call i64 inttoptr (i64 14 to i64 ()*)()
  store i64 %get_pid_tgid15, i64* %seed14, align 8
  %44 = trunc i32 %42 to i8
  %45 = load i64, i64* %seed14, align 8
  %murmur_hash_216 = call i64 @murmur_hash_2(i8* %40, i8 %44, i64 %45)
  %46 = bitcast [49 x i8]* %fmt_str17 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %46)
  %47 = bitcast [49 x i8]* %fmt_str17 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %47, i8 0, i64 49, i1 false)
  store [49 x i8] c"[BPFTRACE_DEBUG_OUTPUT] Stack id %llu. Len: %llu\00", [49 x i8]* %fmt_str17, align 1
  %48 = bitcast [49 x i8]* %fmt_str17 to i8*
  %trace_printk18 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* %48, i32 49, i64 %murmur_hash_216, i32 %42)
  store i64 %murmur_hash_216, i64* %stackid3, align 8
  %update_elem19 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.3"*, i64*, [6 x i64]*, i64)*)(%"struct map_t.3"* @stack_bpftrace_6, i64* %stackid3, [6 x i64]* %lookup_stack_scratch_map7, i64 0)
  br label %merge_block5

get_stack_fail12:                                 ; preds = %lookup_stack_scratch_merge9
  store i64 0, i64* %stackid3, align 8
  br label %merge_block5

stack_scratch_failure24:                          ; preds = %lookup_stack_scratch_failure28
  store i64 0, i64* %stackid23, align 8
  br label %merge_block25

merge_block25:                                    ; preds = %stack_scratch_failure24, %get_stack_success31, %get_stack_fail32
  %49 = bitcast %stack_t* %stack_args40 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %49)
  %50 = getelementptr %stack_t, %stack_t* %stack_args40, i64 0, i32 0
  %51 = load i64, i64* %stackid23, align 8
  store i64 %51, i64* %50, align 8
  %52 = getelementptr %stack_t, %stack_t* %stack_args40, i64 0, i32 1
  %get_pid_tgid41 = call i64 inttoptr (i64 14 to i64 ()*)()
  %53 = trunc i64 %get_pid_tgid41 to i32
  store i32 %53, i32* %52, align 4
  %54 = getelementptr %stack_t, %stack_t* %stack_args40, i64 0, i32 2
  store i32 0, i32* %54, align 4
  %55 = bitcast i64* %"@z_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %55)
  store i64 0, i64* %"@z_key", align 8
  %update_elem42 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.1"*, i64*, %stack_t*, i64)*)(%"struct map_t.1"* @AT_z, i64* %"@z_key", %stack_t* %stack_args40, i64 0)
  %56 = bitcast i64* %"@z_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %56)
  ret i64 0

lookup_stack_scratch_failure28:                   ; preds = %merge_block5
  br label %stack_scratch_failure24

lookup_stack_scratch_merge29:                     ; preds = %merge_block5
  %57 = bitcast [127 x i64]* %lookup_stack_scratch_map27 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %57, i8 0, i64 1016, i1 false)
  %58 = bitcast [127 x i64]* %lookup_stack_scratch_map27 to i8*
  %get_stack33 = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %58, i32 1016, i64 256)
  %59 = icmp sge i32 %get_stack33, 8
  br i1 %59, label %get_stack_success31, label %get_stack_fail32

get_stack_success31:                              ; preds = %lookup_stack_scratch_merge29
  %60 = udiv i32 %get_stack33, 8
  %61 = bitcast i64* %seed34 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %61)
  %get_pid_tgid35 = call i64 inttoptr (i64 14 to i64 ()*)()
  store i64 %get_pid_tgid35, i64* %seed34, align 8
  %62 = trunc i32 %60 to i8
  %63 = load i64, i64* %seed34, align 8
  %murmur_hash_236 = call i64 @murmur_hash_2(i8* %58, i8 %62, i64 %63)
  %64 = bitcast [49 x i8]* %fmt_str37 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %64)
  %65 = bitcast [49 x i8]* %fmt_str37 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %65, i8 0, i64 49, i1 false)
  store [49 x i8] c"[BPFTRACE_DEBUG_OUTPUT] Stack id %llu. Len: %llu\00", [49 x i8]* %fmt_str37, align 1
  %66 = bitcast [49 x i8]* %fmt_str37 to i8*
  %trace_printk38 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* %66, i32 49, i64 %murmur_hash_236, i32 %60)
  store i64 %murmur_hash_236, i64* %stackid23, align 8
  %update_elem39 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.2"*, i64*, [127 x i64]*, i64)*)(%"struct map_t.2"* @stack_perf_127, i64* %stackid23, [127 x i64]* %lookup_stack_scratch_map27, i64 0)
  br label %merge_block25

get_stack_fail32:                                 ; preds = %lookup_stack_scratch_merge29
  store i64 0, i64* %stackid23, align 8
  br label %merge_block25
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

!llvm.dbg.cu = !{!89}
!llvm.module.flags = !{!92}

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
!32 = !{!5, !33, !16, !38}
!33 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !34, size: 64, offset: 64)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 4194304, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 131072, lowerBound: 0)
!38 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !39, size: 64, offset: 192)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 8128, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 127, lowerBound: 0)
!43 = !DIGlobalVariableExpression(var: !44, expr: !DIExpression())
!44 = distinct !DIGlobalVariable(name: "stack_bpftrace_6", linkageName: "global", scope: !2, file: !2, type: !45, isLocal: false, isDefinition: true)
!45 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !46)
!46 = !{!5, !33, !16, !47}
!47 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !48, size: 64, offset: 192)
!48 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !49, size: 64)
!49 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 384, elements: !50)
!50 = !{!51}
!51 = !DISubrange(count: 6, lowerBound: 0)
!52 = !DIGlobalVariableExpression(var: !53, expr: !DIExpression())
!53 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !31, isLocal: false, isDefinition: true)
!54 = !DIGlobalVariableExpression(var: !55, expr: !DIExpression())
!55 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !56, isLocal: false, isDefinition: true)
!56 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !57)
!57 = !{!58, !61, !62, !38}
!58 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !59, size: 64)
!59 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !60, size: 64)
!60 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !50)
!61 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!62 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !63, size: 64, offset: 128)
!63 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !64, size: 64)
!64 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!65 = !DIGlobalVariableExpression(var: !66, expr: !DIExpression())
!66 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !67, isLocal: false, isDefinition: true)
!67 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !68)
!68 = !{!69, !74}
!69 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !70, size: 64)
!70 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !71, size: 64)
!71 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !72)
!72 = !{!73}
!73 = !DISubrange(count: 27, lowerBound: 0)
!74 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !75, size: 64, offset: 64)
!75 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !76, size: 64)
!76 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !77)
!77 = !{!78}
!78 = !DISubrange(count: 262144, lowerBound: 0)
!79 = !DIGlobalVariableExpression(var: !80, expr: !DIExpression())
!80 = distinct !DIGlobalVariable(name: "ringbuf_loss_counter", linkageName: "global", scope: !2, file: !2, type: !81, isLocal: false, isDefinition: true)
!81 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !82)
!82 = !{!83, !61, !62, !88}
!83 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !84, size: 64)
!84 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !85, size: 64)
!85 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !86)
!86 = !{!87}
!87 = !DISubrange(count: 2, lowerBound: 0)
!88 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!89 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !90, globals: !91)
!90 = !{}
!91 = !{!0, !25, !27, !29, !43, !52, !54, !65, !79}
!92 = !{i32 2, !"Debug Info Version", i32 3}
!93 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !2, file: !2, type: !94, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !89, retainedNodes: !97)
!94 = !DISubroutineType(types: !95)
!95 = !{!18, !96}
!96 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!97 = !{!98, !99}
!98 = !DILocalVariable(name: "var0", scope: !93, file: !2, type: !18)
!99 = !DILocalVariable(name: "var1", arg: 1, scope: !93, file: !2, type: !96)
