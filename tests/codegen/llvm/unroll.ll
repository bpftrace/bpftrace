; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_i = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36
@write_map_val_buf = dso_local externally_initialized global [1 x [1 x [8 x i8]]] zeroinitializer, section ".data.write_map_val_buf", !dbg !38
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !46
@read_map_val_buf = dso_local externally_initialized global [1 x [1 x [8 x i8]]] zeroinitializer, section ".data.read_map_val_buf", !dbg !48

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !53 {
entry:
  %"@i_key52" = alloca i64, align 8
  %"@i_key44" = alloca i64, align 8
  %"@i_key40" = alloca i64, align 8
  %"@i_key32" = alloca i64, align 8
  %"@i_key28" = alloca i64, align 8
  %"@i_key20" = alloca i64, align 8
  %"@i_key16" = alloca i64, align 8
  %"@i_key8" = alloca i64, align 8
  %"@i_key4" = alloca i64, align 8
  %"@i_key1" = alloca i64, align 8
  %"@i_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key")
  store i64 0, ptr %"@i_key", align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  store i64 0, ptr %2, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key", ptr %2, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key1")
  store i64 0, ptr %"@i_key1", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key1")
  %get_cpu_id2 = call i64 inttoptr (i64 8 to ptr)()
  %3 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded3 = and i64 %get_cpu_id2, %3
  %4 = getelementptr [1 x [1 x [8 x i8]]], ptr @read_map_val_buf, i64 0, i64 %cpu.id.bounded3, i64 0, i64 0
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %5 = load i64, ptr %lookup_elem, align 8
  store i64 %5, ptr %4, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, ptr %4, align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %6 = load i64, ptr %4, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key1")
  %7 = add i64 %6, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key4")
  store i64 0, ptr %"@i_key4", align 8
  %get_cpu_id5 = call i64 inttoptr (i64 8 to ptr)()
  %8 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded6 = and i64 %get_cpu_id5, %8
  %9 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded6, i64 0, i64 0
  store i64 %7, ptr %9, align 8
  %update_elem7 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key4", ptr %9, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key4")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key8")
  store i64 0, ptr %"@i_key8", align 8
  %lookup_elem9 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key8")
  %get_cpu_id13 = call i64 inttoptr (i64 8 to ptr)()
  %10 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded14 = and i64 %get_cpu_id13, %10
  %11 = getelementptr [1 x [1 x [8 x i8]]], ptr @read_map_val_buf, i64 0, i64 %cpu.id.bounded14, i64 0, i64 0
  %map_lookup_cond15 = icmp ne ptr %lookup_elem9, null
  br i1 %map_lookup_cond15, label %lookup_success10, label %lookup_failure11

lookup_success10:                                 ; preds = %lookup_merge
  %12 = load i64, ptr %lookup_elem9, align 8
  store i64 %12, ptr %11, align 8
  br label %lookup_merge12

lookup_failure11:                                 ; preds = %lookup_merge
  store i64 0, ptr %11, align 8
  br label %lookup_merge12

lookup_merge12:                                   ; preds = %lookup_failure11, %lookup_success10
  %13 = load i64, ptr %11, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key8")
  %14 = add i64 %13, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key16")
  store i64 0, ptr %"@i_key16", align 8
  %get_cpu_id17 = call i64 inttoptr (i64 8 to ptr)()
  %15 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded18 = and i64 %get_cpu_id17, %15
  %16 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded18, i64 0, i64 0
  store i64 %14, ptr %16, align 8
  %update_elem19 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key16", ptr %16, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key16")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key20")
  store i64 0, ptr %"@i_key20", align 8
  %lookup_elem21 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key20")
  %get_cpu_id25 = call i64 inttoptr (i64 8 to ptr)()
  %17 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded26 = and i64 %get_cpu_id25, %17
  %18 = getelementptr [1 x [1 x [8 x i8]]], ptr @read_map_val_buf, i64 0, i64 %cpu.id.bounded26, i64 0, i64 0
  %map_lookup_cond27 = icmp ne ptr %lookup_elem21, null
  br i1 %map_lookup_cond27, label %lookup_success22, label %lookup_failure23

lookup_success22:                                 ; preds = %lookup_merge12
  %19 = load i64, ptr %lookup_elem21, align 8
  store i64 %19, ptr %18, align 8
  br label %lookup_merge24

lookup_failure23:                                 ; preds = %lookup_merge12
  store i64 0, ptr %18, align 8
  br label %lookup_merge24

lookup_merge24:                                   ; preds = %lookup_failure23, %lookup_success22
  %20 = load i64, ptr %18, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key20")
  %21 = add i64 %20, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key28")
  store i64 0, ptr %"@i_key28", align 8
  %get_cpu_id29 = call i64 inttoptr (i64 8 to ptr)()
  %22 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded30 = and i64 %get_cpu_id29, %22
  %23 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded30, i64 0, i64 0
  store i64 %21, ptr %23, align 8
  %update_elem31 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key28", ptr %23, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key28")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key32")
  store i64 0, ptr %"@i_key32", align 8
  %lookup_elem33 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key32")
  %get_cpu_id37 = call i64 inttoptr (i64 8 to ptr)()
  %24 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded38 = and i64 %get_cpu_id37, %24
  %25 = getelementptr [1 x [1 x [8 x i8]]], ptr @read_map_val_buf, i64 0, i64 %cpu.id.bounded38, i64 0, i64 0
  %map_lookup_cond39 = icmp ne ptr %lookup_elem33, null
  br i1 %map_lookup_cond39, label %lookup_success34, label %lookup_failure35

lookup_success34:                                 ; preds = %lookup_merge24
  %26 = load i64, ptr %lookup_elem33, align 8
  store i64 %26, ptr %25, align 8
  br label %lookup_merge36

lookup_failure35:                                 ; preds = %lookup_merge24
  store i64 0, ptr %25, align 8
  br label %lookup_merge36

lookup_merge36:                                   ; preds = %lookup_failure35, %lookup_success34
  %27 = load i64, ptr %25, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key32")
  %28 = add i64 %27, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key40")
  store i64 0, ptr %"@i_key40", align 8
  %get_cpu_id41 = call i64 inttoptr (i64 8 to ptr)()
  %29 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded42 = and i64 %get_cpu_id41, %29
  %30 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded42, i64 0, i64 0
  store i64 %28, ptr %30, align 8
  %update_elem43 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key40", ptr %30, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key40")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key44")
  store i64 0, ptr %"@i_key44", align 8
  %lookup_elem45 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key44")
  %get_cpu_id49 = call i64 inttoptr (i64 8 to ptr)()
  %31 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded50 = and i64 %get_cpu_id49, %31
  %32 = getelementptr [1 x [1 x [8 x i8]]], ptr @read_map_val_buf, i64 0, i64 %cpu.id.bounded50, i64 0, i64 0
  %map_lookup_cond51 = icmp ne ptr %lookup_elem45, null
  br i1 %map_lookup_cond51, label %lookup_success46, label %lookup_failure47

lookup_success46:                                 ; preds = %lookup_merge36
  %33 = load i64, ptr %lookup_elem45, align 8
  store i64 %33, ptr %32, align 8
  br label %lookup_merge48

lookup_failure47:                                 ; preds = %lookup_merge36
  store i64 0, ptr %32, align 8
  br label %lookup_merge48

lookup_merge48:                                   ; preds = %lookup_failure47, %lookup_success46
  %34 = load i64, ptr %32, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key44")
  %35 = add i64 %34, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key52")
  store i64 0, ptr %"@i_key52", align 8
  %get_cpu_id53 = call i64 inttoptr (i64 8 to ptr)()
  %36 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded54 = and i64 %get_cpu_id53, %36
  %37 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded54, i64 0, i64 0
  store i64 %35, ptr %37, align 8
  %update_elem55 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key52", ptr %37, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key52")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!50}
!llvm.module.flags = !{!52}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_i", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!21 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !25)
!25 = !{!26, !31}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 27, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !32, size: 64, offset: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 262144, lowerBound: 0)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!38 = !DIGlobalVariableExpression(var: !39, expr: !DIExpression())
!39 = distinct !DIGlobalVariable(name: "write_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !40, isLocal: false, isDefinition: true)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !41, size: 64, elements: !14)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !42, size: 64, elements: !14)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !43, size: 64, elements: !44)
!43 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!44 = !{!45}
!45 = !DISubrange(count: 8, lowerBound: 0)
!46 = !DIGlobalVariableExpression(var: !47, expr: !DIExpression())
!47 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !21, isLocal: false, isDefinition: true)
!48 = !DIGlobalVariableExpression(var: !49, expr: !DIExpression())
!49 = distinct !DIGlobalVariable(name: "read_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !40, isLocal: false, isDefinition: true)
!50 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !51)
!51 = !{!0, !22, !36, !38, !46, !48}
!52 = !{i32 2, !"Debug Info Version", i32 3}
!53 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !54, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !50, retainedNodes: !57)
!54 = !DISubroutineType(types: !55)
!55 = !{!21, !56}
!56 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!57 = !{!58}
!58 = !DILocalVariable(name: "ctx", arg: 1, scope: !53, file: !2, type: !56)
