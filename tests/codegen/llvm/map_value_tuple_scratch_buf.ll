; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"string[4]_int64__tuple_t" = type { [4 x i8], i64 }
%"string[8]_int64__tuple_t" = type { [8 x i8], i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !27
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !41
@map_key_buf = dso_local externally_initialized global [1 x [4 x [8 x i8]]] zeroinitializer, section ".data.map_key_buf", !dbg !54
@write_map_val_buf = dso_local externally_initialized global [1 x [1 x [16 x i8]]] zeroinitializer, section ".data.write_map_val_buf", !dbg !60
@read_map_val_buf = dso_local externally_initialized global [1 x [1 x [16 x i8]]] zeroinitializer, section ".data.read_map_val_buf", !dbg !67
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !69
@tuple_buf = dso_local externally_initialized global [1 x [2 x [16 x i8]]] zeroinitializer, section ".data.tuple_buf", !dbg !71
@xxx = global [4 x i8] c"xxx\00"
@xxxxxxx = global [8 x i8] c"xxxxxxx\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !78 {
entry:
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [2 x [16 x i8]]], ptr @tuple_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %2, i8 0, i64 16, i1 false)
  %3 = getelementptr %"string[4]_int64__tuple_t", ptr %2, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %3, ptr align 1 @xxx, i64 4, i1 false)
  %4 = getelementptr %"string[4]_int64__tuple_t", ptr %2, i32 0, i32 1
  store i64 1, ptr %4, align 8
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)()
  %5 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %5
  %6 = getelementptr [1 x [4 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded2, i64 0, i64 0
  store i64 0, ptr %6, align 8
  %get_cpu_id3 = call i64 inttoptr (i64 8 to ptr)()
  %7 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded4 = and i64 %get_cpu_id3, %7
  %8 = getelementptr [1 x [1 x [16 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded4, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %8, i8 0, i64 16, i1 false)
  %9 = getelementptr [16 x i8], ptr %2, i64 0, i64 0
  %10 = getelementptr %"string[8]_int64__tuple_t", ptr %8, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %10, ptr align 1 %9, i64 4, i1 false)
  %11 = getelementptr [16 x i8], ptr %2, i64 0, i64 8
  %12 = getelementptr %"string[8]_int64__tuple_t", ptr %8, i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %12, ptr align 1 %11, i64 8, i1 false)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %6, ptr %8, i64 0)
  %get_cpu_id5 = call i64 inttoptr (i64 8 to ptr)()
  %13 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded6 = and i64 %get_cpu_id5, %13
  %14 = getelementptr [1 x [2 x [16 x i8]]], ptr @tuple_buf, i64 0, i64 %cpu.id.bounded6, i64 1, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %14, i8 0, i64 16, i1 false)
  %15 = getelementptr %"string[8]_int64__tuple_t", ptr %14, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %15, ptr align 1 @xxxxxxx, i64 8, i1 false)
  %16 = getelementptr %"string[8]_int64__tuple_t", ptr %14, i32 0, i32 1
  store i64 1, ptr %16, align 8
  %get_cpu_id7 = call i64 inttoptr (i64 8 to ptr)()
  %17 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded8 = and i64 %get_cpu_id7, %17
  %18 = getelementptr [1 x [4 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded8, i64 1, i64 0
  store i64 0, ptr %18, align 8
  %update_elem9 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %18, ptr %14, i64 0)
  %get_cpu_id10 = call i64 inttoptr (i64 8 to ptr)()
  %19 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded11 = and i64 %get_cpu_id10, %19
  %20 = getelementptr [1 x [4 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded11, i64 2, i64 0
  store i64 0, ptr %20, align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %20)
  %get_cpu_id12 = call i64 inttoptr (i64 8 to ptr)()
  %21 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded13 = and i64 %get_cpu_id12, %21
  %22 = getelementptr [1 x [1 x [16 x i8]]], ptr @read_map_val_buf, i64 0, i64 %cpu.id.bounded13, i64 0, i64 0
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %22, ptr align 1 %lookup_elem, i64 16, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.memset.p0.i64(ptr align 1 %22, i8 0, i64 16, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %get_cpu_id14 = call i64 inttoptr (i64 8 to ptr)()
  %23 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded15 = and i64 %get_cpu_id14, %23
  %24 = getelementptr [1 x [4 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded15, i64 3, i64 0
  store i64 0, ptr %24, align 8
  %update_elem16 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %24, ptr %22, i64 0)
  ret i64 0
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #2

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!75}
!llvm.module.flags = !{!77}

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
!17 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !18)
!18 = !{!19, !24}
!19 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !20, size: 64)
!20 = !DICompositeType(tag: DW_TAG_array_type, baseType: !21, size: 64, elements: !22)
!21 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!22 = !{!23}
!23 = !DISubrange(count: 8, lowerBound: 0)
!24 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !14, size: 64, offset: 64)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!27 = !DIGlobalVariableExpression(var: !28, expr: !DIExpression())
!28 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !29, isLocal: false, isDefinition: true)
!29 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !30)
!30 = !{!31, !36}
!31 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !32, size: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 27, lowerBound: 0)
!36 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !37, size: 64, offset: 64)
!37 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !38, size: 64)
!38 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !39)
!39 = !{!40}
!40 = !DISubrange(count: 262144, lowerBound: 0)
!41 = !DIGlobalVariableExpression(var: !42, expr: !DIExpression())
!42 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !43, isLocal: false, isDefinition: true)
!43 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !44)
!44 = !{!45, !11, !50, !53}
!45 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !46, size: 64)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !48)
!48 = !{!49}
!49 = !DISubrange(count: 2, lowerBound: 0)
!50 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !51, size: 64, offset: 128)
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!53 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !13, size: 64, offset: 192)
!54 = !DIGlobalVariableExpression(var: !55, expr: !DIExpression())
!55 = distinct !DIGlobalVariable(name: "map_key_buf", linkageName: "global", scope: !2, file: !2, type: !56, isLocal: false, isDefinition: true)
!56 = !DICompositeType(tag: DW_TAG_array_type, baseType: !57, size: 256, elements: !9)
!57 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 256, elements: !58)
!58 = !{!59}
!59 = !DISubrange(count: 4, lowerBound: 0)
!60 = !DIGlobalVariableExpression(var: !61, expr: !DIExpression())
!61 = distinct !DIGlobalVariable(name: "write_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !62, isLocal: false, isDefinition: true)
!62 = !DICompositeType(tag: DW_TAG_array_type, baseType: !63, size: 128, elements: !9)
!63 = !DICompositeType(tag: DW_TAG_array_type, baseType: !64, size: 128, elements: !9)
!64 = !DICompositeType(tag: DW_TAG_array_type, baseType: !21, size: 128, elements: !65)
!65 = !{!66}
!66 = !DISubrange(count: 16, lowerBound: 0)
!67 = !DIGlobalVariableExpression(var: !68, expr: !DIExpression())
!68 = distinct !DIGlobalVariable(name: "read_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !62, isLocal: false, isDefinition: true)
!69 = !DIGlobalVariableExpression(var: !70, expr: !DIExpression())
!70 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !14, isLocal: false, isDefinition: true)
!71 = !DIGlobalVariableExpression(var: !72, expr: !DIExpression())
!72 = distinct !DIGlobalVariable(name: "tuple_buf", linkageName: "global", scope: !2, file: !2, type: !73, isLocal: false, isDefinition: true)
!73 = !DICompositeType(tag: DW_TAG_array_type, baseType: !74, size: 256, elements: !9)
!74 = !DICompositeType(tag: DW_TAG_array_type, baseType: !64, size: 256, elements: !48)
!75 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !76)
!76 = !{!0, !25, !27, !41, !54, !60, !67, !69, !71}
!77 = !{i32 2, !"Debug Info Version", i32 3}
!78 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !79, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !75, retainedNodes: !82)
!79 = !DISubroutineType(types: !80)
!80 = !{!14, !81}
!81 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!82 = !{!83}
!83 = !DILocalVariable(name: "ctx", arg: 1, scope: !78, file: !2, type: !81)
