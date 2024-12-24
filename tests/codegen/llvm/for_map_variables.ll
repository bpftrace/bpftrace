; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%ctx_t = type { ptr, ptr }
%int64_int64__tuple_t = type { i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_len = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_map = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !25
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !39
@abc = global [4 x i8] c"abc\00"
@def = global [4 x i8] c"def\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !54 {
entry:
  %"@len_val" = alloca i64, align 8
  %"@len_key" = alloca i64, align 8
  %ctx = alloca %ctx_t, align 8
  %"$var3" = alloca [4 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var3")
  call void @llvm.memset.p0.i64(ptr align 1 %"$var3", i8 0, i64 4, i1 false)
  %"$var2" = alloca [4 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var2")
  call void @llvm.memset.p0.i64(ptr align 1 %"$var2", i8 0, i64 4, i1 false)
  %"$var1" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var1")
  store i64 0, ptr %"$var1", align 8
  %"@map_val" = alloca i64, align 8
  %"@map_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@map_key")
  store i64 16, ptr %"@map_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@map_val")
  store i64 32, ptr %"@map_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_map, ptr %"@map_key", ptr %"@map_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@map_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@map_key")
  store i64 123, ptr %"$var1", align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %"$var2", ptr align 1 @abc, i64 4, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %"$var3", ptr align 1 @def, i64 4, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ctx)
  %1 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$var1" = getelementptr %ctx_t, ptr %1, i64 0, i32 0
  store ptr %"$var1", ptr %"ctx.$var1", align 8
  %2 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$var3" = getelementptr %ctx_t, ptr %2, i64 0, i32 1
  store ptr %"$var3", ptr %"ctx.$var3", align 8
  %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr @AT_map, ptr @map_for_each_cb, ptr %ctx, i64 0)
  %3 = load i64, ptr %"$var1", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@len_key")
  store i64 0, ptr %"@len_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@len_val")
  store i64 %3, ptr %"@len_val", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_len, ptr %"@len_key", ptr %"@len_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@len_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@len_key")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #4

define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) section ".text" !dbg !61 {
  %"$can_read" = alloca [4 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$can_read")
  call void @llvm.memset.p0.i64(ptr align 1 %"$can_read", i8 0, i64 4, i1 false)
  %"$kv" = alloca %int64_int64__tuple_t, align 8
  %key = load i64, ptr %1, align 8
  %val = load i64, ptr %2, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$kv")
  call void @llvm.memset.p0.i64(ptr align 1 %"$kv", i8 0, i64 16, i1 false)
  %5 = getelementptr %int64_int64__tuple_t, ptr %"$kv", i32 0, i32 0
  store i64 %key, ptr %5, align 8
  %6 = getelementptr %int64_int64__tuple_t, ptr %"$kv", i32 0, i32 1
  store i64 %val, ptr %6, align 8
  %"ctx.$var1" = getelementptr %ctx_t, ptr %3, i64 0, i32 0
  %"$var1" = load ptr, ptr %"ctx.$var1", align 8
  %"ctx.$var3" = getelementptr %ctx_t, ptr %3, i64 0, i32 1
  %"$var3" = load ptr, ptr %"ctx.$var3", align 8
  %7 = load i64, ptr %"$var1", align 8
  %8 = add i64 %7, 1
  store i64 %8, ptr %"$var1", align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %"$can_read", ptr align 1 %"$var3", i64 4, i1 false)
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #4 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }

!llvm.dbg.cu = !{!51}
!llvm.module.flags = !{!53}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_len", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!15 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !13, size: 64, offset: 192)
!16 = !DIGlobalVariableExpression(var: !17, expr: !DIExpression())
!17 = distinct !DIGlobalVariable(name: "AT_map", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !19)
!19 = !{!5, !20, !12, !15}
!20 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !21, size: 64, offset: 64)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 131072, elements: !23)
!23 = !{!24}
!24 = !DISubrange(count: 4096, lowerBound: 0)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !28)
!28 = !{!29, !34}
!29 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !30, size: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 27, lowerBound: 0)
!34 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !35, size: 64, offset: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 262144, lowerBound: 0)
!39 = !DIGlobalVariableExpression(var: !40, expr: !DIExpression())
!40 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !41, isLocal: false, isDefinition: true)
!41 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !42)
!42 = !{!43, !11, !48, !15}
!43 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !44, size: 64)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 2, lowerBound: 0)
!48 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !49, size: 64, offset: 128)
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!50 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!51 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !52)
!52 = !{!0, !16, !25, !39}
!53 = !{i32 2, !"Debug Info Version", i32 3}
!54 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !55, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !51, retainedNodes: !59)
!55 = !DISubroutineType(types: !56)
!56 = !{!14, !57}
!57 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !58, size: 64)
!58 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!59 = !{!60}
!60 = !DILocalVariable(name: "ctx", arg: 1, scope: !54, file: !2, type: !57)
!61 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !62, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !51, retainedNodes: !64)
!62 = !DISubroutineType(types: !63)
!63 = !{!14, !57, !57, !57, !57}
!64 = !{!65, !66, !67, !68}
!65 = !DILocalVariable(name: "map", arg: 1, scope: !61, file: !2, type: !57)
!66 = !DILocalVariable(name: "key", arg: 2, scope: !61, file: !2, type: !57)
!67 = !DILocalVariable(name: "value", arg: 3, scope: !61, file: !2, type: !57)
!68 = !DILocalVariable(name: "ctx", arg: 4, scope: !61, file: !2, type: !57)
