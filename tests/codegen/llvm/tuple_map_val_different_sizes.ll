; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"int64_string[3]__tuple_t" = type { i64, [3 x i8] }
%"int64_string[13]__tuple_t" = type { i64, [13 x i8] }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_a = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !30
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !44
@write_map_val_buf = dso_local externally_initialized global [1 x [1 x [24 x i8]]] zeroinitializer, section ".data.write_map_val_buf", !dbg !50
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !57
@tuple_buf = dso_local externally_initialized global [1 x [2 x [24 x i8]]] zeroinitializer, section ".data.tuple_buf", !dbg !59

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !66 {
entry:
  %"@a_key6" = alloca i64, align 8
  %str3 = alloca [13 x i8], align 1
  %"@a_key" = alloca i64, align 8
  %str = alloca [3 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %str)
  store [3 x i8] c"hi\00", ptr %str, align 1
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [2 x [24 x i8]]], ptr @tuple_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %2, i8 0, i64 16, i1 false)
  %3 = getelementptr %"int64_string[3]__tuple_t", ptr %2, i32 0, i32 0
  store i64 1, ptr %3, align 8
  %4 = getelementptr %"int64_string[3]__tuple_t", ptr %2, i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %4, ptr align 1 %str, i64 3, i1 false)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %str)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_key")
  store i64 0, ptr %"@a_key", align 8
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)()
  %5 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %5
  %6 = getelementptr [1 x [1 x [24 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded2, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %6, i8 0, i64 24, i1 false)
  %7 = getelementptr [16 x i8], ptr %2, i64 0, i64 0
  %8 = getelementptr %"int64_string[13]__tuple_t", ptr %6, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %8, ptr align 1 %7, i64 8, i1 false)
  %9 = getelementptr [16 x i8], ptr %2, i64 0, i64 8
  %10 = getelementptr %"int64_string[13]__tuple_t", ptr %6, i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %10, ptr align 1 %9, i64 3, i1 false)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_a, ptr %"@a_key", ptr %6, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %str3)
  store [13 x i8] c"hellolongstr\00", ptr %str3, align 1
  %get_cpu_id4 = call i64 inttoptr (i64 8 to ptr)()
  %11 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded5 = and i64 %get_cpu_id4, %11
  %12 = getelementptr [1 x [2 x [24 x i8]]], ptr @tuple_buf, i64 0, i64 %cpu.id.bounded5, i64 1, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %12, i8 0, i64 24, i1 false)
  %13 = getelementptr %"int64_string[13]__tuple_t", ptr %12, i32 0, i32 0
  store i64 1, ptr %13, align 8
  %14 = getelementptr %"int64_string[13]__tuple_t", ptr %12, i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %14, ptr align 1 %str3, i64 13, i1 false)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %str3)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_key6")
  store i64 0, ptr %"@a_key6", align 8
  %update_elem7 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_a, ptr %"@a_key6", ptr %12, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_key6")
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

!llvm.dbg.cu = !{!63}
!llvm.module.flags = !{!65}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_a", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!21 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 192, elements: !22)
!22 = !{!23, !25}
!23 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !24, size: 64)
!24 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!25 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !26, size: 104, offset: 64)
!26 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 104, elements: !28)
!27 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!28 = !{!29}
!29 = !DISubrange(count: 13, lowerBound: 0)
!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())
!31 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !32, isLocal: false, isDefinition: true)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !33)
!33 = !{!34, !39}
!34 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !35, size: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 27, lowerBound: 0)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !40, size: 64, offset: 64)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 262144, lowerBound: 0)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !47)
!47 = !{!5, !11, !16, !48}
!48 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !49, size: 64, offset: 192)
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!50 = !DIGlobalVariableExpression(var: !51, expr: !DIExpression())
!51 = distinct !DIGlobalVariable(name: "write_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !52, isLocal: false, isDefinition: true)
!52 = !DICompositeType(tag: DW_TAG_array_type, baseType: !53, size: 192, elements: !14)
!53 = !DICompositeType(tag: DW_TAG_array_type, baseType: !54, size: 192, elements: !14)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 192, elements: !55)
!55 = !{!56}
!56 = !DISubrange(count: 24, lowerBound: 0)
!57 = !DIGlobalVariableExpression(var: !58, expr: !DIExpression())
!58 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!59 = !DIGlobalVariableExpression(var: !60, expr: !DIExpression())
!60 = distinct !DIGlobalVariable(name: "tuple_buf", linkageName: "global", scope: !2, file: !2, type: !61, isLocal: false, isDefinition: true)
!61 = !DICompositeType(tag: DW_TAG_array_type, baseType: !62, size: 384, elements: !14)
!62 = !DICompositeType(tag: DW_TAG_array_type, baseType: !54, size: 384, elements: !9)
!63 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !64)
!64 = !{!0, !30, !44, !50, !57, !59}
!65 = !{i32 2, !"Debug Info Version", i32 3}
!66 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !67, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !63, retainedNodes: !70)
!67 = !DISubroutineType(types: !68)
!68 = !{!24, !69}
!69 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!70 = !{!71}
!71 = !DILocalVariable(name: "ctx", arg: 1, scope: !66, file: !2, type: !69)
