; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"int64_string[13]__tuple_t" = type { i64, [13 x i8] }
%"int64_string[3]__tuple_t" = type { i64, [3 x i8] }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_a = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !30
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !44
@hi = global [3 x i8] c"hi\00"
@hellolongstr = global [13 x i8] c"hellolongstr\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !60 {
entry:
  %"@a_key2" = alloca i64, align 8
  %tuple1 = alloca %"int64_string[13]__tuple_t", align 8
  %"@a_val" = alloca %"int64_string[13]__tuple_t", align 8
  %"@a_key" = alloca i64, align 8
  %tuple = alloca %"int64_string[3]__tuple_t", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %tuple)
  call void @llvm.memset.p0.i64(ptr align 1 %tuple, i8 0, i64 16, i1 false)
  %1 = getelementptr %"int64_string[3]__tuple_t", ptr %tuple, i32 0, i32 0
  store i64 1, ptr %1, align 8
  %2 = getelementptr %"int64_string[3]__tuple_t", ptr %tuple, i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %2, ptr align 1 @hi, i64 3, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_key")
  store i64 0, ptr %"@a_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_val")
  call void @llvm.memset.p0.i64(ptr align 1 %"@a_val", i8 0, i64 24, i1 false)
  %3 = getelementptr [16 x i8], ptr %tuple, i64 0, i64 0
  %4 = getelementptr %"int64_string[13]__tuple_t", ptr %"@a_val", i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %4, ptr align 1 %3, i64 8, i1 false)
  %5 = getelementptr [16 x i8], ptr %tuple, i64 0, i64 8
  %6 = getelementptr %"int64_string[13]__tuple_t", ptr %"@a_val", i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %6, ptr align 1 %5, i64 3, i1 false)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_a, ptr %"@a_key", ptr %"@a_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %tuple)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %tuple1)
  call void @llvm.memset.p0.i64(ptr align 1 %tuple1, i8 0, i64 24, i1 false)
  %7 = getelementptr %"int64_string[13]__tuple_t", ptr %tuple1, i32 0, i32 0
  store i64 1, ptr %7, align 8
  %8 = getelementptr %"int64_string[13]__tuple_t", ptr %tuple1, i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %8, ptr align 1 @hellolongstr, i64 13, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_key2")
  store i64 0, ptr %"@a_key2", align 8
  %update_elem3 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_a, ptr %"@a_key2", ptr %tuple1, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_key2")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %tuple1)
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

!llvm.dbg.cu = !{!57}
!llvm.module.flags = !{!59}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_a", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !10)
!10 = !{!11, !17, !18, !21}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 1, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !19, size: 64, offset: 128)
!19 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !20, size: 64)
!20 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !22, size: 64, offset: 192)
!22 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !23, size: 64)
!23 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 192, elements: !24)
!24 = !{!25, !26}
!25 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !20, size: 64)
!26 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !27, size: 104, offset: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 104, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 13, lowerBound: 0)
!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())
!31 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !32, isLocal: false, isDefinition: true)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !33)
!33 = !{!34, !39}
!34 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !35, size: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 27, lowerBound: 0)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !40, size: 64, offset: 64)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 262144, lowerBound: 0)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !47)
!47 = !{!48, !17, !53, !56}
!48 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !49, size: 64)
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!50 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 64, elements: !51)
!51 = !{!52}
!52 = !DISubrange(count: 2, lowerBound: 0)
!53 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !54, size: 64, offset: 128)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!56 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !19, size: 64, offset: 192)
!57 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !58)
!58 = !{!0, !7, !30, !44}
!59 = !{i32 2, !"Debug Info Version", i32 3}
!60 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !61, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !57, retainedNodes: !64)
!61 = !DISubroutineType(types: !62)
!62 = !{!20, !63}
!63 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!64 = !{!65}
!65 = !DILocalVariable(name: "ctx", arg: 1, scope: !60, file: !2, type: !63)
