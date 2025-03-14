; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !26
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !28
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !42
@num_cpus = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !59

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !64 {
entry:
  %"@x_key11" = alloca i64, align 8
  %"@x_key9" = alloca i64, align 8
  %initial_value7 = alloca i64, align 8
  %lookup_elem_val5 = alloca i64, align 8
  %"@y_key" = alloca i64, align 8
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 1, ptr %"@x_key", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %1 = load i64, ptr %lookup_elem, align 8
  %2 = add i64 %1, 1
  store i64 %2, ptr %lookup_elem, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %initial_value)
  store i64 1, ptr %initial_value, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %initial_value, i64 1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %initial_value)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  %log2 = call i64 @log2(i64 10, i64 0)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 %log2, ptr %"@y_key", align 8
  %lookup_elem1 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_y, ptr %"@y_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val5)
  %map_lookup_cond6 = icmp ne ptr %lookup_elem1, null
  br i1 %map_lookup_cond6, label %lookup_success2, label %lookup_failure3

lookup_success2:                                  ; preds = %lookup_merge
  %3 = load i64, ptr %lookup_elem1, align 8
  %4 = add i64 %3, 1
  store i64 %4, ptr %lookup_elem1, align 8
  br label %lookup_merge4

lookup_failure3:                                  ; preds = %lookup_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %initial_value7)
  store i64 1, ptr %initial_value7, align 8
  %update_elem8 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %initial_value7, i64 1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %initial_value7)
  br label %lookup_merge4

lookup_merge4:                                    ; preds = %lookup_failure3, %lookup_success2
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val5)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key9")
  store i64 1, ptr %"@x_key9", align 8
  %lookup_elem10 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key9")
  %has_key = icmp ne ptr %lookup_elem10, null
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key9")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key11")
  store i64 1, ptr %"@x_key11", align 8
  %delete_elem = call i64 inttoptr (i64 3 to ptr)(ptr @AT_x, ptr %"@x_key11")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key11")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: alwaysinline
define internal i64 @log2(i64 %0, i64 %1) #2 section "helpers" {
entry:
  %2 = alloca i64, align 8
  %3 = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %3)
  store i64 %0, ptr %3, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %2)
  store i64 %1, ptr %2, align 8
  %4 = load i64, ptr %3, align 8
  %5 = icmp slt i64 %4, 0
  br i1 %5, label %hist.is_less_than_zero, label %hist.is_not_less_than_zero

hist.is_less_than_zero:                           ; preds = %entry
  ret i64 0

hist.is_not_less_than_zero:                       ; preds = %entry
  %6 = load i64, ptr %2, align 8
  %7 = shl i64 1, %6
  %8 = sub i64 %7, 1
  %9 = icmp ule i64 %4, %8
  br i1 %9, label %hist.is_zero, label %hist.is_not_zero

hist.is_zero:                                     ; preds = %hist.is_not_less_than_zero
  %10 = add i64 %4, 1
  ret i64 %10

hist.is_not_zero:                                 ; preds = %hist.is_not_less_than_zero
  %11 = icmp sge i64 %4, 4294967296
  %12 = zext i1 %11 to i64
  %13 = shl i64 %12, 5
  %14 = lshr i64 %4, %13
  %15 = add i64 0, %13
  %16 = icmp sge i64 %14, 65536
  %17 = zext i1 %16 to i64
  %18 = shl i64 %17, 4
  %19 = lshr i64 %14, %18
  %20 = add i64 %15, %18
  %21 = icmp sge i64 %19, 256
  %22 = zext i1 %21 to i64
  %23 = shl i64 %22, 3
  %24 = lshr i64 %19, %23
  %25 = add i64 %20, %23
  %26 = icmp sge i64 %24, 16
  %27 = zext i1 %26 to i64
  %28 = shl i64 %27, 2
  %29 = lshr i64 %24, %28
  %30 = add i64 %25, %28
  %31 = icmp sge i64 %29, 4
  %32 = zext i1 %31 to i64
  %33 = shl i64 %32, 1
  %34 = lshr i64 %29, %33
  %35 = add i64 %30, %33
  %36 = icmp sge i64 %34, 2
  %37 = zext i1 %36 to i64
  %38 = shl i64 %37, 0
  %39 = lshr i64 %34, %38
  %40 = add i64 %35, %38
  %41 = sub i64 %40, %6
  %42 = load i64, ptr %3, align 8
  %43 = lshr i64 %42, %41
  %44 = and i64 %43, %8
  %45 = add i64 %41, 1
  %46 = shl i64 %45, %6
  %47 = add i64 %46, %44
  %48 = add i64 %47, 1
  ret i64 %48
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { alwaysinline }

!llvm.dbg.cu = !{!61}
!llvm.module.flags = !{!63}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !10)
!10 = !{!11, !17, !22, !25}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 160, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 5, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !18, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 131072, elements: !20)
!20 = !{!21}
!21 = !DISubrange(count: 4096, lowerBound: 0)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !23, size: 64, offset: 128)
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !23, size: 64, offset: 192)
!26 = !DIGlobalVariableExpression(var: !27, expr: !DIExpression())
!27 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!28 = !DIGlobalVariableExpression(var: !29, expr: !DIExpression())
!29 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !30, isLocal: false, isDefinition: true)
!30 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !31)
!31 = !{!32, !37}
!32 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !33, size: 64)
!33 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !34, size: 64)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !35)
!35 = !{!36}
!36 = !DISubrange(count: 27, lowerBound: 0)
!37 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !38, size: 64, offset: 64)
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !39, size: 64)
!39 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !40)
!40 = !{!41}
!41 = !DISubrange(count: 262144, lowerBound: 0)
!42 = !DIGlobalVariableExpression(var: !43, expr: !DIExpression())
!43 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !44, isLocal: false, isDefinition: true)
!44 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !45)
!45 = !{!46, !51, !56, !25}
!46 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !47, size: 64)
!47 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !48, size: 64)
!48 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 64, elements: !49)
!49 = !{!50}
!50 = !DISubrange(count: 2, lowerBound: 0)
!51 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !52, size: 64, offset: 64)
!52 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !53, size: 64)
!53 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !54)
!54 = !{!55}
!55 = !DISubrange(count: 1, lowerBound: 0)
!56 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !57, size: 64, offset: 128)
!57 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !58, size: 64)
!58 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!59 = !DIGlobalVariableExpression(var: !60, expr: !DIExpression())
!60 = distinct !DIGlobalVariable(name: "num_cpus", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!61 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !62)
!62 = !{!0, !7, !26, !28, !42, !59}
!63 = !{i32 2, !"Debug Info Version", i32 3}
!64 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !65, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !61, retainedNodes: !68)
!65 = !DISubroutineType(types: !66)
!66 = !{!24, !67}
!67 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!68 = !{!69}
!69 = !DILocalVariable(name: "ctx", arg: 1, scope: !64, file: !2, type: !67)
