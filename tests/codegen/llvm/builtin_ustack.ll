; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%"struct map_t.2" = type { i8*, i8* }
%"struct map_t.3" = type { i8*, i8*, i8*, i8* }
%stack_t = type { i64, i32, i32, i32 }
%stack_key = type { i64, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@stack_bpftrace_127 = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@stack_scratch = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !49
@ringbuf = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !62
@event_loss_counter = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !76

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !90 {
entry:
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
  %lookup_stack_scratch_map = call [127 x i64]* inttoptr (i64 1 to [127 x i64]* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @stack_scratch, i32* %lookup_stack_scratch_key)
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
  ret i64 0

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([127 x i64]*, i32, i8*)*)([127 x i64]* %lookup_stack_scratch_map, i32 1016, i8* null)
  %20 = bitcast [127 x i64]* %lookup_stack_scratch_map to i8*
  %get_stack = call i32 inttoptr (i64 67 to i32 (i8*, i8*, i32, i64)*)(i8* %0, i8* %20, i32 1016, i64 256)
  %21 = icmp sge i32 %get_stack, 0
  br i1 %21, label %get_stack_success, label %get_stack_fail

get_stack_success:                                ; preds = %lookup_stack_scratch_merge
  %22 = udiv i32 %get_stack, 8
  %23 = getelementptr %stack_key, %stack_key* %stack_key, i64 0, i32 1
  store i32 %22, i32* %23, align 4
  %24 = trunc i32 %22 to i8
  %murmur_hash_2 = call i64 @murmur_hash_2(i8* %20, i8 %24, i64 1)
  %25 = getelementptr %stack_key, %stack_key* %stack_key, i64 0, i32 0
  store i64 %murmur_hash_2, i64* %25, align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t.0"*, %stack_key*, [127 x i64]*, i64)*)(%"struct map_t.0"* @stack_bpftrace_127, %stack_key* %stack_key, [127 x i64]* %lookup_stack_scratch_map, i64 0)
  br label %merge_block

get_stack_fail:                                   ; preds = %lookup_stack_scratch_merge
  br label %merge_block
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

attributes #0 = { nounwind }
attributes #1 = { alwaysinline }
attributes #2 = { argmemonly nofree nosync nounwind willreturn }

!llvm.dbg.cu = !{!86}
!llvm.module.flags = !{!89}

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
!26 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !28)
!28 = !{!29, !34, !39, !44}
!29 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !30, size: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 288, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 9, lowerBound: 0)
!34 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !35, size: 64, offset: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 4194304, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 131072, lowerBound: 0)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !40, size: 64, offset: 128)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 96, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 12, lowerBound: 0)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !45, size: 64, offset: 192)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 8128, elements: !47)
!47 = !{!48}
!48 = !DISubrange(count: 127, lowerBound: 0)
!49 = !DIGlobalVariableExpression(var: !50, expr: !DIExpression())
!50 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !51, isLocal: false, isDefinition: true)
!51 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !52)
!52 = !{!53, !58, !59, !44}
!53 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !54, size: 64)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !56)
!56 = !{!57}
!57 = !DISubrange(count: 6, lowerBound: 0)
!58 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
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
!76 = !DIGlobalVariableExpression(var: !77, expr: !DIExpression())
!77 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !78, isLocal: false, isDefinition: true)
!78 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !79)
!79 = !{!80, !58, !59, !85}
!80 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !81, size: 64)
!81 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !82, size: 64)
!82 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !83)
!83 = !{!84}
!84 = !DISubrange(count: 2, lowerBound: 0)
!85 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!86 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !87, globals: !88)
!87 = !{}
!88 = !{!0, !25, !49, !62, !76}
!89 = !{i32 2, !"Debug Info Version", i32 3}
!90 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !91, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !86, retainedNodes: !94)
!91 = !DISubroutineType(types: !92)
!92 = !{!18, !93}
!93 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!94 = !{!95}
!95 = !DILocalVariable(name: "ctx", arg: 1, scope: !90, file: !2, type: !93)
