; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_bar = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !48

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !62 {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %lookup_elem_val = alloca [2 x [2 x [4 x i8]]], align 1
  %"@bar_key1" = alloca i64, align 8
  %"@bar_val" = alloca [2 x [2 x [4 x i8]]], align 1
  %"@bar_key" = alloca i64, align 8
  %1 = getelementptr i64, ptr %0, i64 14
  %arg0 = load volatile i64, ptr %1, align 8
  %2 = add i64 %arg0, 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_key")
  store i64 42, ptr %"@bar_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_val")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"@bar_val", i32 16, i64 %2)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_bar, ptr %"@bar_key", ptr %"@bar_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_key1")
  store i64 42, ptr %"@bar_key1", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_bar, ptr %"@bar_key1")
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
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_key1")
  %3 = getelementptr [2 x [2 x [4 x i8]]], ptr %lookup_elem_val, i32 0, i64 0
  %4 = getelementptr [2 x [4 x i8]], ptr %3, i32 0, i64 1
  %5 = getelementptr [4 x i8], ptr %4, i32 0, i64 0
  %6 = load volatile i32, ptr %5, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key")
  store i64 0, ptr %"@_key", align 8
  %7 = sext i32 %6 to i64
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_val")
  store i64 %7, ptr %"@_val", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_, ptr %"@_key", ptr %"@_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!59}
!llvm.module.flags = !{!61}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!20 = !DIGlobalVariableExpression(var: !21, expr: !DIExpression())
!21 = distinct !DIGlobalVariable(name: "AT_bar", linkageName: "global", scope: !2, file: !2, type: !22, isLocal: false, isDefinition: true)
!22 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !23)
!23 = !{!5, !11, !16, !24}
!24 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !25, size: 64, offset: 192)
!25 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !26, size: 64)
!26 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 128, elements: !32)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !28, size: 64, elements: !32)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !29, size: 32, elements: !30)
!29 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!30 = !{!31}
!31 = !DISubrange(count: 4, lowerBound: 0)
!32 = !{!33}
!33 = !DISubrange(count: 2, lowerBound: 0)
!34 = !DIGlobalVariableExpression(var: !35, expr: !DIExpression())
!35 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!36 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !37)
!37 = !{!38, !43}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !39, size: 64)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 27, lowerBound: 0)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !44, size: 64, offset: 64)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 262144, lowerBound: 0)
!48 = !DIGlobalVariableExpression(var: !49, expr: !DIExpression())
!49 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !50, isLocal: false, isDefinition: true)
!50 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !51)
!51 = !{!52, !55, !56, !19}
!52 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !53, size: 64)
!53 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !54, size: 64)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !32)
!55 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!56 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !57, size: 64, offset: 128)
!57 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !58, size: 64)
!58 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!59 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !60)
!60 = !{!0, !20, !34, !48}
!61 = !{i32 2, !"Debug Info Version", i32 3}
!62 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !63, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !59, retainedNodes: !66)
!63 = !DISubroutineType(types: !64)
!64 = !{!18, !65}
!65 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!66 = !{!67}
!67 = !DILocalVariable(name: "ctx", arg: 1, scope: !62, file: !2, type: !65)
