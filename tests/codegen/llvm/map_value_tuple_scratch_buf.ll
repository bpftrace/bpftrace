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
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !30
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !32
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !46
@write_map_val_buf = dso_local externally_initialized global [1 x [1 x [16 x i8]]] zeroinitializer, section ".data.write_map_val_buf", !dbg !52
@read_map_val_buf = dso_local externally_initialized global [1 x [1 x [16 x i8]]] zeroinitializer, section ".data.read_map_val_buf", !dbg !59
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !61
@tuple_buf = dso_local externally_initialized global [1 x [2 x [16 x i8]]] zeroinitializer, section ".data.tuple_buf", !dbg !63

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !70 {
entry:
  %"@y_key" = alloca i64, align 8
  %"@x_key8" = alloca i64, align 8
  %"@x_key6" = alloca i64, align 8
  %str3 = alloca [8 x i8], align 1
  %"@x_key" = alloca i64, align 8
  %str = alloca [4 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %str)
  store [4 x i8] c"xxx\00", ptr %str, align 1
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [2 x [16 x i8]]], ptr @tuple_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %2, i8 0, i64 16, i1 false)
  %3 = getelementptr %"string[4]_int64__tuple_t", ptr %2, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %3, ptr align 1 %str, i64 4, i1 false)
  %4 = getelementptr %"string[4]_int64__tuple_t", ptr %2, i32 0, i32 1
  store i64 1, ptr %4, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %str)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)()
  %5 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %5
  %6 = getelementptr [1 x [1 x [16 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded2, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %6, i8 0, i64 16, i1 false)
  %7 = getelementptr [16 x i8], ptr %2, i64 0, i64 0
  %8 = getelementptr %"string[8]_int64__tuple_t", ptr %6, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %8, ptr align 1 %7, i64 4, i1 false)
  %9 = getelementptr [16 x i8], ptr %2, i64 0, i64 8
  %10 = getelementptr %"string[8]_int64__tuple_t", ptr %6, i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %10, ptr align 1 %9, i64 8, i1 false)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %6, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %str3)
  store [8 x i8] c"xxxxxxx\00", ptr %str3, align 1
  %get_cpu_id4 = call i64 inttoptr (i64 8 to ptr)()
  %11 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded5 = and i64 %get_cpu_id4, %11
  %12 = getelementptr [1 x [2 x [16 x i8]]], ptr @tuple_buf, i64 0, i64 %cpu.id.bounded5, i64 1, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %12, i8 0, i64 16, i1 false)
  %13 = getelementptr %"string[8]_int64__tuple_t", ptr %12, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %13, ptr align 1 %str3, i64 8, i1 false)
  %14 = getelementptr %"string[8]_int64__tuple_t", ptr %12, i32 0, i32 1
  store i64 1, ptr %14, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %str3)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key6")
  store i64 0, ptr %"@x_key6", align 8
  %update_elem7 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key6", ptr %12, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key6")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key8")
  store i64 0, ptr %"@x_key8", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key8")
  %get_cpu_id9 = call i64 inttoptr (i64 8 to ptr)()
  %15 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded10 = and i64 %get_cpu_id9, %15
  %16 = getelementptr [1 x [1 x [16 x i8]]], ptr @read_map_val_buf, i64 0, i64 %cpu.id.bounded10, i64 0, i64 0
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %16, ptr align 1 %lookup_elem, i64 16, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.memset.p0.i64(ptr align 1 %16, i8 0, i64 16, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key8")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  %update_elem11 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %16, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!67}
!llvm.module.flags = !{!69}

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
!21 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !22)
!22 = !{!23, !28}
!23 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !24, size: 64)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !25, size: 64, elements: !26)
!25 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!26 = !{!27}
!27 = !DISubrange(count: 8, lowerBound: 0)
!28 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !29, size: 64, offset: 64)
!29 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())
!31 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!32 = !DIGlobalVariableExpression(var: !33, expr: !DIExpression())
!33 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !34, isLocal: false, isDefinition: true)
!34 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !35)
!35 = !{!36, !41}
!36 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !37, size: 64)
!37 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !38, size: 64)
!38 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !39)
!39 = !{!40}
!40 = !DISubrange(count: 27, lowerBound: 0)
!41 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !42, size: 64, offset: 64)
!42 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!43 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !44)
!44 = !{!45}
!45 = !DISubrange(count: 262144, lowerBound: 0)
!46 = !DIGlobalVariableExpression(var: !47, expr: !DIExpression())
!47 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !48, isLocal: false, isDefinition: true)
!48 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !49)
!49 = !{!5, !11, !16, !50}
!50 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !51, size: 64, offset: 192)
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!52 = !DIGlobalVariableExpression(var: !53, expr: !DIExpression())
!53 = distinct !DIGlobalVariable(name: "write_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !54, isLocal: false, isDefinition: true)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !55, size: 128, elements: !14)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !56, size: 128, elements: !14)
!56 = !DICompositeType(tag: DW_TAG_array_type, baseType: !25, size: 128, elements: !57)
!57 = !{!58}
!58 = !DISubrange(count: 16, lowerBound: 0)
!59 = !DIGlobalVariableExpression(var: !60, expr: !DIExpression())
!60 = distinct !DIGlobalVariable(name: "read_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !54, isLocal: false, isDefinition: true)
!61 = !DIGlobalVariableExpression(var: !62, expr: !DIExpression())
!62 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !29, isLocal: false, isDefinition: true)
!63 = !DIGlobalVariableExpression(var: !64, expr: !DIExpression())
!64 = distinct !DIGlobalVariable(name: "tuple_buf", linkageName: "global", scope: !2, file: !2, type: !65, isLocal: false, isDefinition: true)
!65 = !DICompositeType(tag: DW_TAG_array_type, baseType: !66, size: 256, elements: !14)
!66 = !DICompositeType(tag: DW_TAG_array_type, baseType: !56, size: 256, elements: !9)
!67 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !68)
!68 = !{!0, !30, !32, !46, !52, !59, !61, !63}
!69 = !{i32 2, !"Debug Info Version", i32 3}
!70 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !71, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !67, retainedNodes: !74)
!71 = !DISubroutineType(types: !72)
!72 = !{!29, !73}
!73 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !25, size: 64)
!74 = !{!75}
!75 = !DILocalVariable(name: "ctx", arg: 1, scope: !70, file: !2, type: !73)
