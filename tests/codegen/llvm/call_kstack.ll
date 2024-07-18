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
%stack_key = type { i64, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@AT_z = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !27
@stack_perf_127 = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !29
@stack_bpftrace_6 = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !50
@stack_bpftrace_127 = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !59
@stack_scratch = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !61
@ringbuf = dso_local global %"struct map_t.6" zeroinitializer, section ".maps", !dbg !68
@event_loss_counter = dso_local global %"struct map_t.7" zeroinitializer, section ".maps", !dbg !82

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !91 {
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
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %stack_key, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key2)
  %3 = getelementptr %stack_key, ptr %stack_key2, i64 0, i32 0
  store i64 0, ptr %3, align 8
  %4 = getelementptr %stack_key, ptr %stack_key2, i64 0, i32 1
  store i32 0, ptr %4, align 4
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
  %get_stack = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map, i32 1016, i64 0)
  %5 = icmp sge i32 %get_stack, 0
  br i1 %5, label %get_stack_success, label %get_stack_fail

get_stack_success:                                ; preds = %lookup_stack_scratch_merge
  %6 = udiv i32 %get_stack, 8
  %7 = getelementptr %stack_key, ptr %stack_key, i64 0, i32 1
  store i32 %6, ptr %7, align 4
  %8 = trunc i32 %6 to i8
  %murmur_hash_2 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map, i8 %8, i64 1)
  %9 = getelementptr %stack_key, ptr %stack_key, i64 0, i32 0
  store i64 %murmur_hash_2, ptr %9, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key, ptr %lookup_stack_scratch_map, i64 0)
  br label %merge_block

get_stack_fail:                                   ; preds = %lookup_stack_scratch_merge
  br label %merge_block

stack_scratch_failure3:                           ; preds = %lookup_stack_scratch_failure7
  br label %merge_block4

merge_block4:                                     ; preds = %stack_scratch_failure3, %get_stack_success10, %get_stack_fail11
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  %update_elem15 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %stack_key2, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key16)
  %10 = getelementptr %stack_key, ptr %stack_key16, i64 0, i32 0
  store i64 0, ptr %10, align 8
  %11 = getelementptr %stack_key, ptr %stack_key16, i64 0, i32 1
  store i32 0, ptr %11, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key19)
  store i32 0, ptr %lookup_stack_scratch_key19, align 4
  %lookup_stack_scratch_map20 = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key19)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key19)
  %lookup_stack_scratch_cond23 = icmp ne ptr %lookup_stack_scratch_map20, null
  br i1 %lookup_stack_scratch_cond23, label %lookup_stack_scratch_merge22, label %lookup_stack_scratch_failure21

lookup_stack_scratch_failure7:                    ; preds = %merge_block
  br label %stack_scratch_failure3

lookup_stack_scratch_merge8:                      ; preds = %merge_block
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_stack_scratch_map6, i8 0, i64 48, i1 false)
  %get_stack12 = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map6, i32 48, i64 0)
  %12 = icmp sge i32 %get_stack12, 0
  br i1 %12, label %get_stack_success10, label %get_stack_fail11

get_stack_success10:                              ; preds = %lookup_stack_scratch_merge8
  %13 = udiv i32 %get_stack12, 8
  %14 = getelementptr %stack_key, ptr %stack_key2, i64 0, i32 1
  store i32 %13, ptr %14, align 4
  %15 = trunc i32 %13 to i8
  %murmur_hash_213 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map6, i8 %15, i64 1)
  %16 = getelementptr %stack_key, ptr %stack_key2, i64 0, i32 0
  store i64 %murmur_hash_213, ptr %16, align 8
  %update_elem14 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_6, ptr %stack_key2, ptr %lookup_stack_scratch_map6, i64 0)
  br label %merge_block4

get_stack_fail11:                                 ; preds = %lookup_stack_scratch_merge8
  br label %merge_block4

stack_scratch_failure17:                          ; preds = %lookup_stack_scratch_failure21
  br label %merge_block18

merge_block18:                                    ; preds = %stack_scratch_failure17, %get_stack_success25, %get_stack_fail26
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@z_key")
  store i64 0, ptr %"@z_key", align 8
  %update_elem30 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_z, ptr %"@z_key", ptr %stack_key16, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@z_key")
  ret i64 0

lookup_stack_scratch_failure21:                   ; preds = %merge_block4
  br label %stack_scratch_failure17

lookup_stack_scratch_merge22:                     ; preds = %merge_block4
  %probe_read_kernel24 = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map20, i32 1016, ptr null)
  %get_stack27 = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map20, i32 1016, i64 0)
  %17 = icmp sge i32 %get_stack27, 0
  br i1 %17, label %get_stack_success25, label %get_stack_fail26

get_stack_success25:                              ; preds = %lookup_stack_scratch_merge22
  %18 = udiv i32 %get_stack27, 8
  %19 = getelementptr %stack_key, ptr %stack_key16, i64 0, i32 1
  store i32 %18, ptr %19, align 4
  %20 = trunc i32 %18 to i8
  %murmur_hash_228 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map20, i8 %20, i64 1)
  %21 = getelementptr %stack_key, ptr %stack_key16, i64 0, i32 0
  store i64 %murmur_hash_228, ptr %21, align 8
  %update_elem29 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_perf_127, ptr %stack_key16, ptr %lookup_stack_scratch_map20, i64 0)
  br label %merge_block18

get_stack_fail26:                                 ; preds = %lookup_stack_scratch_merge22
  br label %merge_block18
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

!llvm.dbg.cu = !{!88}
!llvm.module.flags = !{!90}

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
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !47, size: 8128, elements: !48)
!47 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!48 = !{!49}
!49 = !DISubrange(count: 127, lowerBound: 0)
!50 = !DIGlobalVariableExpression(var: !51, expr: !DIExpression())
!51 = distinct !DIGlobalVariable(name: "stack_bpftrace_6", linkageName: "global", scope: !2, file: !2, type: !52, isLocal: false, isDefinition: true)
!52 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !53)
!53 = !{!33, !38, !43, !54}
!54 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !55, size: 64, offset: 192)
!55 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !56, size: 64)
!56 = !DICompositeType(tag: DW_TAG_array_type, baseType: !47, size: 384, elements: !57)
!57 = !{!58}
!58 = !DISubrange(count: 6, lowerBound: 0)
!59 = !DIGlobalVariableExpression(var: !60, expr: !DIExpression())
!60 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !31, isLocal: false, isDefinition: true)
!61 = !DIGlobalVariableExpression(var: !62, expr: !DIExpression())
!62 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !63, isLocal: false, isDefinition: true)
!63 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !64)
!64 = !{!65, !11, !16, !44}
!65 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !66, size: 64)
!66 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !67, size: 64)
!67 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !57)
!68 = !DIGlobalVariableExpression(var: !69, expr: !DIExpression())
!69 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !70, isLocal: false, isDefinition: true)
!70 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !71)
!71 = !{!72, !77}
!72 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !73, size: 64)
!73 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !74, size: 64)
!74 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !75)
!75 = !{!76}
!76 = !DISubrange(count: 27, lowerBound: 0)
!77 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !78, size: 64, offset: 64)
!78 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !79, size: 64)
!79 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !80)
!80 = !{!81}
!81 = !DISubrange(count: 262144, lowerBound: 0)
!82 = !DIGlobalVariableExpression(var: !83, expr: !DIExpression())
!83 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !84, isLocal: false, isDefinition: true)
!84 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !85)
!85 = !{!5, !11, !16, !86}
!86 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !87, size: 64, offset: 192)
!87 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!88 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !89)
!89 = !{!0, !25, !27, !29, !50, !59, !61, !68, !82}
!90 = !{i32 2, !"Debug Info Version", i32 3}
!91 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !92, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !88, retainedNodes: !95)
!92 = !DISubroutineType(types: !93)
!93 = !{!47, !94}
!94 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!95 = !{!96}
!96 = !DILocalVariable(name: "ctx", arg: 1, scope: !91, file: !2, type: !94)
