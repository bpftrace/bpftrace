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
%stack_t = type { i64, i32, i32, i32 }
%stack_key = type { i64, i32 }

@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@AT_z = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !27
@stack_perf_127 = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !29
@stack_bpftrace_6 = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !53
@stack_bpftrace_127 = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !62
@stack_scratch = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !64
@ringbuf = dso_local global %"struct map_t.6" zeroinitializer, section ".maps", !dbg !75
@ringbuf_loss_counter = dso_local global %"struct map_t.7" zeroinitializer, section ".maps", !dbg !89

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !103 {
entry:
  %"@z_key" = alloca i64, align 8
  %stack_args31 = alloca %stack_t, align 8
  %lookup_stack_scratch_key21 = alloca i32, align 4
  %stack_key18 = alloca %stack_key, align 8
  %"@y_key" = alloca i64, align 8
  %stack_args15 = alloca %stack_t, align 8
  %lookup_stack_scratch_key5 = alloca i32, align 4
  %stack_key2 = alloca %stack_key, align 8
  %"@x_key" = alloca i64, align 8
  %stack_args = alloca %stack_t, align 8
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
  %7 = bitcast %stack_t* %stack_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %8 = getelementptr %stack_key, %stack_key* %stack_key, i64 0, i32 0
  %9 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 0
  %10 = load i64, i64* %8, align 8
  store i64 %10, i64* %9, align 8
  %11 = getelementptr %stack_key, %stack_key* %stack_key, i64 0, i32 1
  %12 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 1
  %13 = load i32, i32* %11, align 4
  store i32 %13, i32* %12, align 4
  %14 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 2
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %15 = trunc i64 %get_pid_tgid to i32
  store i32 %15, i32* %14, align 4
  %16 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 3
  store i32 0, i32* %16, align 4
  %17 = bitcast %stack_key* %stack_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  %18 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i64 0, i64* %"@x_key", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, %stack_t*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key", %stack_t* %stack_args, i64 0)
  %19 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = bitcast %stack_key* %stack_key2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %20)
  %21 = getelementptr %stack_key, %stack_key* %stack_key2, i64 0, i32 0
  store i64 0, i64* %21, align 8
  %22 = getelementptr %stack_key, %stack_key* %stack_key2, i64 0, i32 1
  store i32 0, i32* %22, align 4
  %23 = bitcast i32* %lookup_stack_scratch_key5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  store i32 0, i32* %lookup_stack_scratch_key5, align 4
  %lookup_stack_scratch_map6 = call [6 x i64]* inttoptr (i64 1 to [6 x i64]* (%"struct map_t.5"*, i32*)*)(%"struct map_t.5"* @stack_scratch, i32* %lookup_stack_scratch_key5)
  %24 = bitcast i32* %lookup_stack_scratch_key5 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  %25 = bitcast [6 x i64]* %lookup_stack_scratch_map6 to i8*
  %lookup_stack_scratch_cond9 = icmp ne i8* %25, null
  br i1 %lookup_stack_scratch_cond9, label %lookup_stack_scratch_merge8, label %lookup_stack_scratch_failure7

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %26 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %26, i8 0, i64 1016, i1 false)
  %27 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  %get_stack = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %27, i32 1016, i64 256)
  %28 = icmp sge i32 %get_stack, 0
  br i1 %28, label %get_stack_success, label %get_stack_fail

get_stack_success:                                ; preds = %lookup_stack_scratch_merge
  %29 = udiv i32 %get_stack, 8
  %30 = getelementptr %stack_key, %stack_key* %stack_key, i64 0, i32 1
  store i32 %29, i32* %30, align 4
  %31 = trunc i32 %29 to i8
  %murmur_hash_2 = call i64 @murmur_hash_2(i8* %27, i8 %31, i64 1)
  %32 = getelementptr %stack_key, %stack_key* %stack_key, i64 0, i32 0
  store i64 %murmur_hash_2, i64* %32, align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t.4"*, %stack_key*, [127 x i64]*, i64)*)(%"struct map_t.4"* @stack_bpftrace_127, %stack_key* %stack_key, [127 x i64]* %lookup_stack_scratch_map, i64 0)
  br label %merge_block

get_stack_fail:                                   ; preds = %lookup_stack_scratch_merge
  br label %merge_block

stack_scratch_failure3:                           ; preds = %lookup_stack_scratch_failure7
  br label %merge_block4

merge_block4:                                     ; preds = %stack_scratch_failure3, %get_stack_success10, %get_stack_fail11
  %33 = bitcast %stack_t* %stack_args15 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %33)
  %34 = getelementptr %stack_key, %stack_key* %stack_key2, i64 0, i32 0
  %35 = getelementptr %stack_t, %stack_t* %stack_args15, i64 0, i32 0
  %36 = load i64, i64* %34, align 8
  store i64 %36, i64* %35, align 8
  %37 = getelementptr %stack_key, %stack_key* %stack_key2, i64 0, i32 1
  %38 = getelementptr %stack_t, %stack_t* %stack_args15, i64 0, i32 1
  %39 = load i32, i32* %37, align 4
  store i32 %39, i32* %38, align 4
  %40 = getelementptr %stack_t, %stack_t* %stack_args15, i64 0, i32 2
  %get_pid_tgid16 = call i64 inttoptr (i64 14 to i64 ()*)()
  %41 = trunc i64 %get_pid_tgid16 to i32
  store i32 %41, i32* %40, align 4
  %42 = getelementptr %stack_t, %stack_t* %stack_args15, i64 0, i32 3
  store i32 0, i32* %42, align 4
  %43 = bitcast %stack_key* %stack_key2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %43)
  %44 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %44)
  store i64 0, i64* %"@y_key", align 8
  %update_elem17 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.0"*, i64*, %stack_t*, i64)*)(%"struct map_t.0"* @AT_y, i64* %"@y_key", %stack_t* %stack_args15, i64 0)
  %45 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %45)
  %46 = bitcast %stack_key* %stack_key18 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %46)
  %47 = getelementptr %stack_key, %stack_key* %stack_key18, i64 0, i32 0
  store i64 0, i64* %47, align 8
  %48 = getelementptr %stack_key, %stack_key* %stack_key18, i64 0, i32 1
  store i32 0, i32* %48, align 4
  %49 = bitcast i32* %lookup_stack_scratch_key21 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %49)
  store i32 0, i32* %lookup_stack_scratch_key21, align 4
  %lookup_stack_scratch_map22 = call [127 x i64]* inttoptr (i64 1 to [127 x i64]* (%"struct map_t.5"*, i32*)*)(%"struct map_t.5"* @stack_scratch, i32* %lookup_stack_scratch_key21)
  %50 = bitcast i32* %lookup_stack_scratch_key21 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %50)
  %51 = bitcast [127 x i64]* %lookup_stack_scratch_map22 to i8*
  %lookup_stack_scratch_cond25 = icmp ne i8* %51, null
  br i1 %lookup_stack_scratch_cond25, label %lookup_stack_scratch_merge24, label %lookup_stack_scratch_failure23

lookup_stack_scratch_failure7:                    ; preds = %merge_block
  br label %stack_scratch_failure3

lookup_stack_scratch_merge8:                      ; preds = %merge_block
  %52 = bitcast [6 x i64]* %lookup_stack_scratch_map6 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %52, i8 0, i64 48, i1 false)
  %53 = bitcast [6 x i64]* %lookup_stack_scratch_map6 to i8*
  %get_stack12 = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %53, i32 48, i64 256)
  %54 = icmp sge i32 %get_stack12, 0
  br i1 %54, label %get_stack_success10, label %get_stack_fail11

get_stack_success10:                              ; preds = %lookup_stack_scratch_merge8
  %55 = udiv i32 %get_stack12, 8
  %56 = getelementptr %stack_key, %stack_key* %stack_key2, i64 0, i32 1
  store i32 %55, i32* %56, align 4
  %57 = trunc i32 %55 to i8
  %murmur_hash_213 = call i64 @murmur_hash_2(i8* %53, i8 %57, i64 1)
  %58 = getelementptr %stack_key, %stack_key* %stack_key2, i64 0, i32 0
  store i64 %murmur_hash_213, i64* %58, align 8
  %update_elem14 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.3"*, %stack_key*, [6 x i64]*, i64)*)(%"struct map_t.3"* @stack_bpftrace_6, %stack_key* %stack_key2, [6 x i64]* %lookup_stack_scratch_map6, i64 0)
  br label %merge_block4

get_stack_fail11:                                 ; preds = %lookup_stack_scratch_merge8
  br label %merge_block4

stack_scratch_failure19:                          ; preds = %lookup_stack_scratch_failure23
  br label %merge_block20

merge_block20:                                    ; preds = %stack_scratch_failure19, %get_stack_success26, %get_stack_fail27
  %59 = bitcast %stack_t* %stack_args31 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %59)
  %60 = getelementptr %stack_key, %stack_key* %stack_key18, i64 0, i32 0
  %61 = getelementptr %stack_t, %stack_t* %stack_args31, i64 0, i32 0
  %62 = load i64, i64* %60, align 8
  store i64 %62, i64* %61, align 8
  %63 = getelementptr %stack_key, %stack_key* %stack_key18, i64 0, i32 1
  %64 = getelementptr %stack_t, %stack_t* %stack_args31, i64 0, i32 1
  %65 = load i32, i32* %63, align 4
  store i32 %65, i32* %64, align 4
  %66 = getelementptr %stack_t, %stack_t* %stack_args31, i64 0, i32 2
  %get_pid_tgid32 = call i64 inttoptr (i64 14 to i64 ()*)()
  %67 = trunc i64 %get_pid_tgid32 to i32
  store i32 %67, i32* %66, align 4
  %68 = getelementptr %stack_t, %stack_t* %stack_args31, i64 0, i32 3
  store i32 0, i32* %68, align 4
  %69 = bitcast %stack_key* %stack_key18 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %69)
  %70 = bitcast i64* %"@z_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %70)
  store i64 0, i64* %"@z_key", align 8
  %update_elem33 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.1"*, i64*, %stack_t*, i64)*)(%"struct map_t.1"* @AT_z, i64* %"@z_key", %stack_t* %stack_args31, i64 0)
  %71 = bitcast i64* %"@z_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %71)
  ret i64 0

lookup_stack_scratch_failure23:                   ; preds = %merge_block4
  br label %stack_scratch_failure19

lookup_stack_scratch_merge24:                     ; preds = %merge_block4
  %72 = bitcast [127 x i64]* %lookup_stack_scratch_map22 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %72, i8 0, i64 1016, i1 false)
  %73 = bitcast [127 x i64]* %lookup_stack_scratch_map22 to i8*
  %get_stack28 = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %73, i32 1016, i64 256)
  %74 = icmp sge i32 %get_stack28, 0
  br i1 %74, label %get_stack_success26, label %get_stack_fail27

get_stack_success26:                              ; preds = %lookup_stack_scratch_merge24
  %75 = udiv i32 %get_stack28, 8
  %76 = getelementptr %stack_key, %stack_key* %stack_key18, i64 0, i32 1
  store i32 %75, i32* %76, align 4
  %77 = trunc i32 %75 to i8
  %murmur_hash_229 = call i64 @murmur_hash_2(i8* %73, i8 %77, i64 1)
  %78 = getelementptr %stack_key, %stack_key* %stack_key18, i64 0, i32 0
  store i64 %murmur_hash_229, i64* %78, align 8
  %update_elem30 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.2"*, %stack_key*, [127 x i64]*, i64)*)(%"struct map_t.2"* @stack_perf_127, %stack_key* %stack_key18, [127 x i64]* %lookup_stack_scratch_map22, i64 0)
  br label %merge_block20

get_stack_fail27:                                 ; preds = %lookup_stack_scratch_merge24
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

!llvm.dbg.cu = !{!99}
!llvm.module.flags = !{!102}

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
!21 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 160, elements: !23)
!22 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!23 = !{!24}
!24 = !DISubrange(count: 20, lowerBound: 0)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!27 = !DIGlobalVariableExpression(var: !28, expr: !DIExpression())
!28 = distinct !DIGlobalVariable(name: "AT_z", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "stack_perf_127", linkageName: "global", scope: !2, file: !2, type: !31, isLocal: false, isDefinition: true)
!31 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !32)
!32 = !{!33, !38, !43, !48}
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
!43 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !44, size: 64, offset: 128)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 96, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 12, lowerBound: 0)
!48 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !49, size: 64, offset: 192)
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!50 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 8128, elements: !51)
!51 = !{!52}
!52 = !DISubrange(count: 127, lowerBound: 0)
!53 = !DIGlobalVariableExpression(var: !54, expr: !DIExpression())
!54 = distinct !DIGlobalVariable(name: "stack_bpftrace_6", linkageName: "global", scope: !2, file: !2, type: !55, isLocal: false, isDefinition: true)
!55 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !56)
!56 = !{!33, !38, !43, !57}
!57 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !58, size: 64, offset: 192)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!59 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 384, elements: !60)
!60 = !{!61}
!61 = !DISubrange(count: 6, lowerBound: 0)
!62 = !DIGlobalVariableExpression(var: !63, expr: !DIExpression())
!63 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !31, isLocal: false, isDefinition: true)
!64 = !DIGlobalVariableExpression(var: !65, expr: !DIExpression())
!65 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !66, isLocal: false, isDefinition: true)
!66 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !67)
!67 = !{!68, !71, !72, !48}
!68 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !69, size: 64)
!69 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !70, size: 64)
!70 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !60)
!71 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!72 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !73, size: 64, offset: 128)
!73 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !74, size: 64)
!74 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!75 = !DIGlobalVariableExpression(var: !76, expr: !DIExpression())
!76 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !77, isLocal: false, isDefinition: true)
!77 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !78)
!78 = !{!79, !84}
!79 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !80, size: 64)
!80 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !81, size: 64)
!81 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !82)
!82 = !{!83}
!83 = !DISubrange(count: 27, lowerBound: 0)
!84 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !85, size: 64, offset: 64)
!85 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !86, size: 64)
!86 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !87)
!87 = !{!88}
!88 = !DISubrange(count: 262144, lowerBound: 0)
!89 = !DIGlobalVariableExpression(var: !90, expr: !DIExpression())
!90 = distinct !DIGlobalVariable(name: "ringbuf_loss_counter", linkageName: "global", scope: !2, file: !2, type: !91, isLocal: false, isDefinition: true)
!91 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !92)
!92 = !{!93, !71, !72, !98}
!93 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !94, size: 64)
!94 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !95, size: 64)
!95 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !96)
!96 = !{!97}
!97 = !DISubrange(count: 2, lowerBound: 0)
!98 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!99 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !100, globals: !101)
!100 = !{}
!101 = !{!0, !25, !27, !29, !53, !62, !64, !75, !89}
!102 = !{i32 2, !"Debug Info Version", i32 3}
!103 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !2, file: !2, type: !104, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !99, retainedNodes: !107)
!104 = !DISubroutineType(types: !105)
!105 = !{!18, !106}
!106 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!107 = !{!108, !109}
!108 = !DILocalVariable(name: "var0", scope: !103, file: !2, type: !18)
!109 = !DILocalVariable(name: "var1", arg: 1, scope: !103, file: !2, type: !106)
