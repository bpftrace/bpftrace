; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"string[8]_int64__tuple_t" = type { [8 x i8], i64 }
%"string[4]_int64__tuple_t" = type { [4 x i8], i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !30
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !32
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !46

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !55 {
entry:
  %"@y_key" = alloca i64, align 8
  %lookup_elem_val = alloca %"string[8]_int64__tuple_t", align 8
  %"@x_key5" = alloca i64, align 8
  %"@x_key3" = alloca i64, align 8
  %tuple2 = alloca %"string[8]_int64__tuple_t", align 8
  %str1 = alloca [8 x i8], align 1
  %"@x_val" = alloca %"string[8]_int64__tuple_t", align 8
  %"@x_key" = alloca i64, align 8
  %tuple = alloca %"string[4]_int64__tuple_t", align 8
  %str = alloca [4 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %str)
  store [4 x i8] c"xxx\00", ptr %str, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %tuple)
  call void @llvm.memset.p0.i64(ptr align 1 %tuple, i8 0, i64 16, i1 false)
  %1 = getelementptr %"string[4]_int64__tuple_t", ptr %tuple, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %1, ptr align 1 %str, i64 4, i1 false)
  %2 = getelementptr %"string[4]_int64__tuple_t", ptr %tuple, i32 0, i32 1
  store i64 1, ptr %2, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %str)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_val")
  call void @llvm.memset.p0.i64(ptr align 1 %"@x_val", i8 0, i64 16, i1 false)
  %3 = getelementptr [16 x i8], ptr %tuple, i64 0, i64 0
  %4 = getelementptr %"string[8]_int64__tuple_t", ptr %"@x_val", i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %4, ptr align 1 %3, i64 4, i1 false)
  %5 = getelementptr [16 x i8], ptr %tuple, i64 0, i64 8
  %6 = getelementptr %"string[8]_int64__tuple_t", ptr %"@x_val", i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %6, ptr align 1 %5, i64 8, i1 false)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %tuple)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %str1)
  store [8 x i8] c"xxxxxxx\00", ptr %str1, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %tuple2)
  call void @llvm.memset.p0.i64(ptr align 1 %tuple2, i8 0, i64 16, i1 false)
  %7 = getelementptr %"string[8]_int64__tuple_t", ptr %tuple2, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %7, ptr align 1 %str1, i64 8, i1 false)
  %8 = getelementptr %"string[8]_int64__tuple_t", ptr %tuple2, i32 0, i32 1
  store i64 1, ptr %8, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %str1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key3")
  store i64 0, ptr %"@x_key3", align 8
  %update_elem4 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key3", ptr %tuple2, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key3")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %tuple2)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key5")
  store i64 0, ptr %"@x_key5", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key5")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %lookup_elem_val, ptr align 1 %lookup_elem, i64 16, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_elem_val, i8 0, i64 16, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key5")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  %update_elem6 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %lookup_elem_val, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
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

!llvm.dbg.cu = !{!52}
!llvm.module.flags = !{!54}

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
!52 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !53)
!53 = !{!0, !30, !32, !46}
!54 = !{i32 2, !"Debug Info Version", i32 3}
!55 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !52, retainedNodes: !59)
!56 = !DISubroutineType(types: !57)
!57 = !{!29, !58}
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !25, size: 64)
!59 = !{!60}
!60 = !DILocalVariable(name: "ctx", arg: 1, scope: !55, file: !2, type: !58)
