; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr }
%"struct map_t.3" = type { ptr, ptr, ptr, ptr }
%ustack_key = type { i64, i64, i32, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@stack_bpftrace_127 = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !21
@stack_scratch = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !45
@ringbuf = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !57
@event_loss_counter = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !71

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !84 {
entry:
  %"@x_key" = alloca i64, align 8
  %lookup_stack_scratch_key = alloca i32, align 4
  %stack_key = alloca %ustack_key, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key)
  call void @llvm.memset.p0.i64(ptr align 1 %stack_key, i8 0, i64 24, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key)
  store i32 0, ptr %lookup_stack_scratch_key, align 4
  %lookup_stack_scratch_map = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key)
  %lookup_stack_scratch_cond = icmp ne ptr %lookup_stack_scratch_map, null
  br i1 %lookup_stack_scratch_cond, label %lookup_stack_scratch_merge, label %lookup_stack_scratch_failure

stack_scratch_failure:                            ; preds = %lookup_stack_scratch_failure
  br label %merge_block

merge_block:                                      ; preds = %stack_scratch_failure, %get_stack_success, %get_stack_fail
  %1 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 2
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)()
  %2 = lshr i64 %get_pid_tgid, 32
  %pid = trunc i64 %2 to i32
  store i32 %pid, ptr %1, align 4
  %3 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 3
  store i32 0, ptr %3, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %stack_key, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  ret i64 0

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map, i32 1016, ptr null)
  %get_stack = call i64 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map, i32 1016, i64 256)
  %4 = icmp sge i64 %get_stack, 0
  br i1 %4, label %get_stack_success, label %get_stack_fail

get_stack_success:                                ; preds = %lookup_stack_scratch_merge
  %5 = udiv i64 %get_stack, 8
  %6 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 1
  store i64 %5, ptr %6, align 8
  %7 = trunc i64 %5 to i8
  %murmur_hash_2 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map, i8 %7, i64 1)
  %8 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 0
  store i64 %murmur_hash_2, ptr %8, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key, ptr %lookup_stack_scratch_map, i64 0)
  br label %merge_block

get_stack_fail:                                   ; preds = %lookup_stack_scratch_merge
  br label %merge_block
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

!llvm.dbg.cu = !{!81}
!llvm.module.flags = !{!83}

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
!17 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 192, elements: !19)
!18 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DISubrange(count: 24, lowerBound: 0)
!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())
!22 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !23, isLocal: false, isDefinition: true)
!23 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !24)
!24 = !{!25, !30, !35, !40}
!25 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !26, size: 64)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 288, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 9, lowerBound: 0)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !31, size: 64, offset: 64)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 4194304, elements: !33)
!33 = !{!34}
!34 = !DISubrange(count: 131072, lowerBound: 0)
!35 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !36, size: 64, offset: 128)
!36 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !37, size: 64)
!37 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 96, elements: !38)
!38 = !{!39}
!39 = !DISubrange(count: 12, lowerBound: 0)
!40 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !41, size: 64, offset: 192)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8128, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 127, lowerBound: 0)
!45 = !DIGlobalVariableExpression(var: !46, expr: !DIExpression())
!46 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !47, isLocal: false, isDefinition: true)
!47 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !48)
!48 = !{!49, !11, !54, !40}
!49 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !50, size: 64)
!50 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !51, size: 64)
!51 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !52)
!52 = !{!53}
!53 = !DISubrange(count: 6, lowerBound: 0)
!54 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !55, size: 64, offset: 128)
!55 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !56, size: 64)
!56 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!57 = !DIGlobalVariableExpression(var: !58, expr: !DIExpression())
!58 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !59, isLocal: false, isDefinition: true)
!59 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !60)
!60 = !{!61, !66}
!61 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !62, size: 64)
!62 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !63, size: 64)
!63 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !64)
!64 = !{!65}
!65 = !DISubrange(count: 27, lowerBound: 0)
!66 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !67, size: 64, offset: 64)
!67 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !68, size: 64)
!68 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !69)
!69 = !{!70}
!70 = !DISubrange(count: 262144, lowerBound: 0)
!71 = !DIGlobalVariableExpression(var: !72, expr: !DIExpression())
!72 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !73, isLocal: false, isDefinition: true)
!73 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !74)
!74 = !{!75, !11, !54, !80}
!75 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !76, size: 64)
!76 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !77, size: 64)
!77 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !78)
!78 = !{!79}
!79 = !DISubrange(count: 2, lowerBound: 0)
!80 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !13, size: 64, offset: 192)
!81 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !82)
!82 = !{!0, !21, !45, !57, !71}
!83 = !{i32 2, !"Debug Info Version", i32 3}
!84 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !85, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !81, retainedNodes: !88)
!85 = !DISubroutineType(types: !86)
!86 = !{!14, !87}
!87 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!88 = !{!89}
!89 = !DILocalVariable(name: "ctx", arg: 1, scope: !84, file: !2, type: !87)
