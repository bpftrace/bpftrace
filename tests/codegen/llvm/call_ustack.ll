; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"struct map_t.3" = type { ptr, ptr, ptr, ptr }
%"struct map_t.4" = type { ptr, ptr, ptr, ptr }
%"struct map_t.5" = type { ptr, ptr, ptr, ptr }
%"struct map_t.6" = type { ptr, ptr }
%"struct map_t.7" = type { ptr, ptr, ptr, ptr }
%stack_t = type { i64, i32, i32, i32 }
%stack_key = type { i64, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@AT_z = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !27
@stack_perf_127 = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !29
@stack_bpftrace_6 = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !54
@stack_bpftrace_127 = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !63
@stack_scratch = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !65
@ringbuf = dso_local global %"struct map_t.6" zeroinitializer, section ".maps", !dbg !72
@event_loss_counter = dso_local global %"struct map_t.7" zeroinitializer, section ".maps", !dbg !86

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !95 {
entry:
  %"@z_key" = alloca i64, align 8
  %stack_args32 = alloca %stack_t, align 8
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
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key)
  %1 = getelementptr %stack_key, ptr %stack_key, i64 0, i32 0
  store i64 0, ptr %1, align 8
  %2 = getelementptr %stack_key, ptr %stack_key, i64 0, i32 1
  store i32 0, ptr %2, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key)
  store i32 0, ptr %lookup_stack_scratch_key, align 4
  %lookup_stack_scratch_map = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key)
  %lookup_stack_scratch_cond = icmp ne ptr %lookup_stack_scratch_map, null
  br i1 %lookup_stack_scratch_cond, label %lookup_stack_scratch_merge, label %lookup_stack_scratch_failure

stack_scratch_failure:                            ; preds = %lookup_stack_scratch_failure
  br label %merge_block

merge_block:                                      ; preds = %stack_scratch_failure, %get_stack_success, %get_stack_fail
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_args)
  %3 = getelementptr %stack_key, ptr %stack_key, i64 0, i32 0
  %4 = getelementptr %stack_t, ptr %stack_args, i64 0, i32 0
  %5 = load i64, ptr %3, align 8
  store i64 %5, ptr %4, align 8
  %6 = getelementptr %stack_key, ptr %stack_key, i64 0, i32 1
  %7 = getelementptr %stack_t, ptr %stack_args, i64 0, i32 1
  %8 = load i32, ptr %6, align 4
  store i32 %8, ptr %7, align 4
  %9 = getelementptr %stack_t, ptr %stack_args, i64 0, i32 2
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)()
  %10 = trunc i64 %get_pid_tgid to i32
  store i32 %10, ptr %9, align 4
  %11 = getelementptr %stack_t, ptr %stack_args, i64 0, i32 3
  store i32 0, ptr %11, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %stack_key)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %stack_args, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key2)
  %12 = getelementptr %stack_key, ptr %stack_key2, i64 0, i32 0
  store i64 0, ptr %12, align 8
  %13 = getelementptr %stack_key, ptr %stack_key2, i64 0, i32 1
  store i32 0, ptr %13, align 4
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
  %get_stack = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map, i32 1016, i64 256)
  %14 = icmp sge i32 %get_stack, 0
  br i1 %14, label %get_stack_success, label %get_stack_fail

get_stack_success:                                ; preds = %lookup_stack_scratch_merge
  %15 = udiv i32 %get_stack, 8
  %16 = getelementptr %stack_key, ptr %stack_key, i64 0, i32 1
  store i32 %15, ptr %16, align 4
  %17 = trunc i32 %15 to i8
  %murmur_hash_2 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map, i8 %17, i64 1)
  %18 = getelementptr %stack_key, ptr %stack_key, i64 0, i32 0
  store i64 %murmur_hash_2, ptr %18, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key, ptr %lookup_stack_scratch_map, i64 0)
  br label %merge_block

get_stack_fail:                                   ; preds = %lookup_stack_scratch_merge
  br label %merge_block

stack_scratch_failure3:                           ; preds = %lookup_stack_scratch_failure7
  br label %merge_block4

merge_block4:                                     ; preds = %stack_scratch_failure3, %get_stack_success10, %get_stack_fail11
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_args15)
  %19 = getelementptr %stack_key, ptr %stack_key2, i64 0, i32 0
  %20 = getelementptr %stack_t, ptr %stack_args15, i64 0, i32 0
  %21 = load i64, ptr %19, align 8
  store i64 %21, ptr %20, align 8
  %22 = getelementptr %stack_key, ptr %stack_key2, i64 0, i32 1
  %23 = getelementptr %stack_t, ptr %stack_args15, i64 0, i32 1
  %24 = load i32, ptr %22, align 4
  store i32 %24, ptr %23, align 4
  %25 = getelementptr %stack_t, ptr %stack_args15, i64 0, i32 2
  %get_pid_tgid16 = call i64 inttoptr (i64 14 to ptr)()
  %26 = trunc i64 %get_pid_tgid16 to i32
  store i32 %26, ptr %25, align 4
  %27 = getelementptr %stack_t, ptr %stack_args15, i64 0, i32 3
  store i32 0, ptr %27, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %stack_key2)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  %update_elem17 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %stack_args15, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key18)
  %28 = getelementptr %stack_key, ptr %stack_key18, i64 0, i32 0
  store i64 0, ptr %28, align 8
  %29 = getelementptr %stack_key, ptr %stack_key18, i64 0, i32 1
  store i32 0, ptr %29, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key21)
  store i32 0, ptr %lookup_stack_scratch_key21, align 4
  %lookup_stack_scratch_map22 = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key21)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key21)
  %lookup_stack_scratch_cond25 = icmp ne ptr %lookup_stack_scratch_map22, null
  br i1 %lookup_stack_scratch_cond25, label %lookup_stack_scratch_merge24, label %lookup_stack_scratch_failure23

lookup_stack_scratch_failure7:                    ; preds = %merge_block
  br label %stack_scratch_failure3

lookup_stack_scratch_merge8:                      ; preds = %merge_block
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_stack_scratch_map6, i8 0, i64 48, i1 false)
  %get_stack12 = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map6, i32 48, i64 256)
  %30 = icmp sge i32 %get_stack12, 0
  br i1 %30, label %get_stack_success10, label %get_stack_fail11

get_stack_success10:                              ; preds = %lookup_stack_scratch_merge8
  %31 = udiv i32 %get_stack12, 8
  %32 = getelementptr %stack_key, ptr %stack_key2, i64 0, i32 1
  store i32 %31, ptr %32, align 4
  %33 = trunc i32 %31 to i8
  %murmur_hash_213 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map6, i8 %33, i64 1)
  %34 = getelementptr %stack_key, ptr %stack_key2, i64 0, i32 0
  store i64 %murmur_hash_213, ptr %34, align 8
  %update_elem14 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_6, ptr %stack_key2, ptr %lookup_stack_scratch_map6, i64 0)
  br label %merge_block4

get_stack_fail11:                                 ; preds = %lookup_stack_scratch_merge8
  br label %merge_block4

stack_scratch_failure19:                          ; preds = %lookup_stack_scratch_failure23
  br label %merge_block20

merge_block20:                                    ; preds = %stack_scratch_failure19, %get_stack_success27, %get_stack_fail28
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_args32)
  %35 = getelementptr %stack_key, ptr %stack_key18, i64 0, i32 0
  %36 = getelementptr %stack_t, ptr %stack_args32, i64 0, i32 0
  %37 = load i64, ptr %35, align 8
  store i64 %37, ptr %36, align 8
  %38 = getelementptr %stack_key, ptr %stack_key18, i64 0, i32 1
  %39 = getelementptr %stack_t, ptr %stack_args32, i64 0, i32 1
  %40 = load i32, ptr %38, align 4
  store i32 %40, ptr %39, align 4
  %41 = getelementptr %stack_t, ptr %stack_args32, i64 0, i32 2
  %get_pid_tgid33 = call i64 inttoptr (i64 14 to ptr)()
  %42 = trunc i64 %get_pid_tgid33 to i32
  store i32 %42, ptr %41, align 4
  %43 = getelementptr %stack_t, ptr %stack_args32, i64 0, i32 3
  store i32 0, ptr %43, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %stack_key18)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@z_key")
  store i64 0, ptr %"@z_key", align 8
  %update_elem34 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_z, ptr %"@z_key", ptr %stack_args32, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@z_key")
  ret i64 0

lookup_stack_scratch_failure23:                   ; preds = %merge_block4
  br label %stack_scratch_failure19

lookup_stack_scratch_merge24:                     ; preds = %merge_block4
  %probe_read_kernel26 = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map22, i32 1016, ptr null)
  %get_stack29 = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map22, i32 1016, i64 256)
  %44 = icmp sge i32 %get_stack29, 0
  br i1 %44, label %get_stack_success27, label %get_stack_fail28

get_stack_success27:                              ; preds = %lookup_stack_scratch_merge24
  %45 = udiv i32 %get_stack29, 8
  %46 = getelementptr %stack_key, ptr %stack_key18, i64 0, i32 1
  store i32 %45, ptr %46, align 4
  %47 = trunc i32 %45 to i8
  %murmur_hash_230 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map22, i8 %47, i64 1)
  %48 = getelementptr %stack_key, ptr %stack_key18, i64 0, i32 0
  store i64 %murmur_hash_230, ptr %48, align 8
  %update_elem31 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_perf_127, ptr %stack_key18, ptr %lookup_stack_scratch_map22, i64 0)
  br label %merge_block20

get_stack_fail28:                                 ; preds = %lookup_stack_scratch_merge24
  br label %merge_block20
}

; Function Attrs: alwaysinline
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
attributes #1 = { alwaysinline }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!92}
!llvm.module.flags = !{!94}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 2, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 1, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
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
!50 = !DICompositeType(tag: DW_TAG_array_type, baseType: !51, size: 8128, elements: !52)
!51 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!52 = !{!53}
!53 = !DISubrange(count: 127, lowerBound: 0)
!54 = !DIGlobalVariableExpression(var: !55, expr: !DIExpression())
!55 = distinct !DIGlobalVariable(name: "stack_bpftrace_6", linkageName: "global", scope: !2, file: !2, type: !56, isLocal: false, isDefinition: true)
!56 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !57)
!57 = !{!33, !38, !43, !58}
!58 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !59, size: 64, offset: 192)
!59 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !60, size: 64)
!60 = !DICompositeType(tag: DW_TAG_array_type, baseType: !51, size: 384, elements: !61)
!61 = !{!62}
!62 = !DISubrange(count: 6, lowerBound: 0)
!63 = !DIGlobalVariableExpression(var: !64, expr: !DIExpression())
!64 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !31, isLocal: false, isDefinition: true)
!65 = !DIGlobalVariableExpression(var: !66, expr: !DIExpression())
!66 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !67, isLocal: false, isDefinition: true)
!67 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !68)
!68 = !{!69, !11, !16, !48}
!69 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !70, size: 64)
!70 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !71, size: 64)
!71 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !61)
!72 = !DIGlobalVariableExpression(var: !73, expr: !DIExpression())
!73 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !74, isLocal: false, isDefinition: true)
!74 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !75)
!75 = !{!76, !81}
!76 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !77, size: 64)
!77 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !78, size: 64)
!78 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !79)
!79 = !{!80}
!80 = !DISubrange(count: 27, lowerBound: 0)
!81 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !82, size: 64, offset: 64)
!82 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !83, size: 64)
!83 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !84)
!84 = !{!85}
!85 = !DISubrange(count: 262144, lowerBound: 0)
!86 = !DIGlobalVariableExpression(var: !87, expr: !DIExpression())
!87 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !88, isLocal: false, isDefinition: true)
!88 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !89)
!89 = !{!5, !11, !16, !90}
!90 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !91, size: 64, offset: 192)
!91 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !51, size: 64)
!92 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !93)
!93 = !{!0, !25, !27, !29, !54, !63, !65, !72, !86}
!94 = !{i32 2, !"Debug Info Version", i32 3}
!95 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !96, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !92, retainedNodes: !99)
!96 = !DISubroutineType(types: !97)
!97 = !{!51, !98}
!98 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!99 = !{!100}
!100 = !DILocalVariable(name: "ctx", arg: 1, scope: !95, file: !2, type: !98)
