; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"struct map_t.3" = type { ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>
%kstack_key = type { i64, i32 }
%ustack_key = type { i64, i32, i32, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !21
@stack_bpftrace_127 = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !30
@stack_scratch = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !50
@ringbuf = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !62

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !79 {
entry:
  %helper_error_t35 = alloca %helper_error_t, align 8
  %"@y_key" = alloca i64, align 8
  %helper_error_t30 = alloca %helper_error_t, align 8
  %helper_error_t24 = alloca %helper_error_t, align 8
  %lookup_stack_scratch_key13 = alloca i32, align 4
  %stack_key10 = alloca %kstack_key, align 8
  %helper_error_t8 = alloca %helper_error_t, align 8
  %"@x_key" = alloca i64, align 8
  %helper_error_t3 = alloca %helper_error_t, align 8
  %helper_error_t = alloca %helper_error_t, align 8
  %lookup_stack_scratch_key = alloca i32, align 4
  %stack_key = alloca %ustack_key, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key)
  %1 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 0
  store i64 0, ptr %1, align 8
  %2 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 1
  store i32 0, ptr %2, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key)
  store i32 0, ptr %lookup_stack_scratch_key, align 4
  %lookup_stack_scratch_map = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key)
  %lookup_stack_scratch_cond = icmp ne ptr %lookup_stack_scratch_map, null
  br i1 %lookup_stack_scratch_cond, label %lookup_stack_scratch_merge, label %lookup_stack_scratch_failure

stack_scratch_failure:                            ; preds = %lookup_stack_scratch_failure
  br label %merge_block

merge_block:                                      ; preds = %stack_scratch_failure, %helper_merge2, %get_stack_fail
  %3 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 2
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)()
  %4 = lshr i64 %get_pid_tgid, 32
  %pid = trunc i64 %4 to i32
  store i32 %pid, ptr %3, align 4
  %5 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 3
  store i32 0, ptr %5, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %update_elem5 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %stack_key, i64 0)
  %6 = trunc i64 %update_elem5 to i32
  %7 = icmp sge i32 %6, 0
  br i1 %7, label %helper_merge7, label %helper_failure6

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map, i32 1016, ptr null)
  %get_stack = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map, i32 1016, i64 256)
  %8 = icmp sge i32 %get_stack, 0
  br i1 %8, label %helper_merge, label %helper_failure

get_stack_success:                                ; preds = %helper_merge
  %9 = udiv i32 %get_stack, 8
  %10 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 1
  store i32 %9, ptr %10, align 4
  %11 = trunc i32 %9 to i8
  %murmur_hash_2 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map, i8 %11, i64 1)
  %12 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 0
  store i64 %murmur_hash_2, ptr %12, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key, ptr %lookup_stack_scratch_map, i64 0)
  %13 = trunc i64 %update_elem to i32
  %14 = icmp sge i32 %13, 0
  br i1 %14, label %helper_merge2, label %helper_failure1

get_stack_fail:                                   ; preds = %helper_merge
  br label %merge_block

helper_failure:                                   ; preds = %lookup_stack_scratch_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %15 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %15, align 8
  %16 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %16, align 8
  %17 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %get_stack, ptr %17, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t)
  br label %helper_merge

helper_merge:                                     ; preds = %helper_failure, %lookup_stack_scratch_merge
  %18 = icmp sge i32 %get_stack, 0
  br i1 %18, label %get_stack_success, label %get_stack_fail

helper_failure1:                                  ; preds = %get_stack_success
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t3)
  %19 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 0
  store i64 30006, ptr %19, align 8
  %20 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 1
  store i64 1, ptr %20, align 8
  %21 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 2
  store i32 %13, ptr %21, align 4
  %ringbuf_output4 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t3, i64 20, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t3)
  br label %helper_merge2

helper_merge2:                                    ; preds = %helper_failure1, %get_stack_success
  br label %merge_block

helper_failure6:                                  ; preds = %merge_block
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t8)
  %22 = getelementptr %helper_error_t, ptr %helper_error_t8, i64 0, i32 0
  store i64 30006, ptr %22, align 8
  %23 = getelementptr %helper_error_t, ptr %helper_error_t8, i64 0, i32 1
  store i64 2, ptr %23, align 8
  %24 = getelementptr %helper_error_t, ptr %helper_error_t8, i64 0, i32 2
  store i32 %6, ptr %24, align 4
  %ringbuf_output9 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t8, i64 20, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t8)
  br label %helper_merge7

helper_merge7:                                    ; preds = %helper_failure6, %merge_block
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key10)
  %25 = getelementptr %kstack_key, ptr %stack_key10, i64 0, i32 0
  store i64 0, ptr %25, align 8
  %26 = getelementptr %kstack_key, ptr %stack_key10, i64 0, i32 1
  store i32 0, ptr %26, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key13)
  store i32 0, ptr %lookup_stack_scratch_key13, align 4
  %lookup_stack_scratch_map14 = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key13)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key13)
  %lookup_stack_scratch_cond17 = icmp ne ptr %lookup_stack_scratch_map14, null
  br i1 %lookup_stack_scratch_cond17, label %lookup_stack_scratch_merge16, label %lookup_stack_scratch_failure15

stack_scratch_failure11:                          ; preds = %lookup_stack_scratch_failure15
  br label %merge_block12

merge_block12:                                    ; preds = %stack_scratch_failure11, %helper_merge29, %get_stack_fail20
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  %update_elem32 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %stack_key10, i64 0)
  %27 = trunc i64 %update_elem32 to i32
  %28 = icmp sge i32 %27, 0
  br i1 %28, label %helper_merge34, label %helper_failure33

lookup_stack_scratch_failure15:                   ; preds = %helper_merge7
  br label %stack_scratch_failure11

lookup_stack_scratch_merge16:                     ; preds = %helper_merge7
  %probe_read_kernel18 = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map14, i32 1016, ptr null)
  %get_stack21 = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map14, i32 1016, i64 0)
  %29 = icmp sge i32 %get_stack21, 0
  br i1 %29, label %helper_merge23, label %helper_failure22

get_stack_success19:                              ; preds = %helper_merge23
  %30 = udiv i32 %get_stack21, 8
  %31 = getelementptr %kstack_key, ptr %stack_key10, i64 0, i32 1
  store i32 %30, ptr %31, align 4
  %32 = trunc i32 %30 to i8
  %murmur_hash_226 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map14, i8 %32, i64 1)
  %33 = getelementptr %kstack_key, ptr %stack_key10, i64 0, i32 0
  store i64 %murmur_hash_226, ptr %33, align 8
  %update_elem27 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key10, ptr %lookup_stack_scratch_map14, i64 0)
  %34 = trunc i64 %update_elem27 to i32
  %35 = icmp sge i32 %34, 0
  br i1 %35, label %helper_merge29, label %helper_failure28

get_stack_fail20:                                 ; preds = %helper_merge23
  br label %merge_block12

helper_failure22:                                 ; preds = %lookup_stack_scratch_merge16
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t24)
  %36 = getelementptr %helper_error_t, ptr %helper_error_t24, i64 0, i32 0
  store i64 30006, ptr %36, align 8
  %37 = getelementptr %helper_error_t, ptr %helper_error_t24, i64 0, i32 1
  store i64 3, ptr %37, align 8
  %38 = getelementptr %helper_error_t, ptr %helper_error_t24, i64 0, i32 2
  store i32 %get_stack21, ptr %38, align 4
  %ringbuf_output25 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t24, i64 20, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t24)
  br label %helper_merge23

helper_merge23:                                   ; preds = %helper_failure22, %lookup_stack_scratch_merge16
  %39 = icmp sge i32 %get_stack21, 0
  br i1 %39, label %get_stack_success19, label %get_stack_fail20

helper_failure28:                                 ; preds = %get_stack_success19
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t30)
  %40 = getelementptr %helper_error_t, ptr %helper_error_t30, i64 0, i32 0
  store i64 30006, ptr %40, align 8
  %41 = getelementptr %helper_error_t, ptr %helper_error_t30, i64 0, i32 1
  store i64 4, ptr %41, align 8
  %42 = getelementptr %helper_error_t, ptr %helper_error_t30, i64 0, i32 2
  store i32 %34, ptr %42, align 4
  %ringbuf_output31 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t30, i64 20, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t30)
  br label %helper_merge29

helper_merge29:                                   ; preds = %helper_failure28, %get_stack_success19
  br label %merge_block12

helper_failure33:                                 ; preds = %merge_block12
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t35)
  %43 = getelementptr %helper_error_t, ptr %helper_error_t35, i64 0, i32 0
  store i64 30006, ptr %43, align 8
  %44 = getelementptr %helper_error_t, ptr %helper_error_t35, i64 0, i32 1
  store i64 5, ptr %44, align 8
  %45 = getelementptr %helper_error_t, ptr %helper_error_t35, i64 0, i32 2
  store i32 %27, ptr %45, align 4
  %ringbuf_output36 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t35, i64 20, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t35)
  br label %helper_merge34

helper_merge34:                                   ; preds = %helper_failure33, %merge_block12
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  ret i64 0
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

attributes #0 = { nounwind }
attributes #1 = { alwaysinline }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!76}
!llvm.module.flags = !{!78}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !12, !15}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !13, size: 64, offset: 128)
!13 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !14, size: 64)
!14 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!15 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !16, size: 64, offset: 192)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !17, size: 64)
!17 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 160, elements: !19)
!18 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DISubrange(count: 20, lowerBound: 0)
!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())
!22 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !23, isLocal: false, isDefinition: true)
!23 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !24)
!24 = !{!5, !11, !12, !25}
!25 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !26, size: 64, offset: 192)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 96, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 12, lowerBound: 0)
!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())
!31 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !32, isLocal: false, isDefinition: true)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !33)
!33 = !{!34, !39, !44, !45}
!34 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !35, size: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 288, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 9, lowerBound: 0)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !40, size: 64, offset: 64)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 4194304, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 131072, lowerBound: 0)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !26, size: 64, offset: 128)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !46, size: 64, offset: 192)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8128, elements: !48)
!48 = !{!49}
!49 = !DISubrange(count: 127, lowerBound: 0)
!50 = !DIGlobalVariableExpression(var: !51, expr: !DIExpression())
!51 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !52, isLocal: false, isDefinition: true)
!52 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !53)
!53 = !{!54, !11, !59, !45}
!54 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !55, size: 64)
!55 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !56, size: 64)
!56 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !57)
!57 = !{!58}
!58 = !DISubrange(count: 6, lowerBound: 0)
!59 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !60, size: 64, offset: 128)
!60 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !61, size: 64)
!61 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!62 = !DIGlobalVariableExpression(var: !63, expr: !DIExpression())
!63 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !64, isLocal: false, isDefinition: true)
!64 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !65)
!65 = !{!66, !71}
!66 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !67, size: 64)
!67 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !68, size: 64)
!68 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !69)
!69 = !{!70}
!70 = !DISubrange(count: 27, lowerBound: 0)
!71 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !72, size: 64, offset: 64)
!72 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !73, size: 64)
!73 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !74)
!74 = !{!75}
!75 = !DISubrange(count: 262144, lowerBound: 0)
!76 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !77)
!77 = !{!0, !21, !30, !50, !62}
!78 = !{i32 2, !"Debug Info Version", i32 3}
!79 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !80, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !76, retainedNodes: !83)
!80 = !DISubroutineType(types: !81)
!81 = !{!14, !82}
!82 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!83 = !{!84}
!84 = !DILocalVariable(name: "ctx", arg: 1, scope: !79, file: !2, type: !82)
