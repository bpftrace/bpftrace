; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_foo = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_str = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !27
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !41

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !51 {
entry:
  %"@str_key" = alloca i64, align 8
  %lookup_elem_val = alloca [32 x i8], align 1
  %"@foo_key1" = alloca i64, align 8
  %"@foo_val" = alloca [32 x i8], align 1
  %"@foo_key" = alloca i64, align 8
  %1 = getelementptr i64, ptr %0, i64 14
  %arg0 = load volatile i64, ptr %1, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_key")
  store i64 0, ptr %"@foo_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_val")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"@foo_val", i32 32, i64 %arg0)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_foo, ptr %"@foo_key", ptr %"@foo_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_key1")
  store i64 0, ptr %"@foo_key1", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_foo, ptr %"@foo_key1")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %lookup_elem_val, ptr align 1 %lookup_elem, i64 32, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_elem_val, i8 0, i64 32, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_key1")
  %2 = getelementptr [32 x i8], ptr %lookup_elem_val, i32 0, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@str_key")
  store i64 0, ptr %"@str_key", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_str, ptr %"@str_key", ptr %2, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@str_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
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

!llvm.dbg.cu = !{!48}
!llvm.module.flags = !{!50}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_foo", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!21 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 256, elements: !23)
!22 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!23 = !{!24}
!24 = !DISubrange(count: 32, lowerBound: 0)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "AT_str", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!44 = !{!5, !11, !16, !45}
!45 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !46, size: 64, offset: 192)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!48 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !49)
!49 = !{!0, !25, !27, !41}
!50 = !{i32 2, !"Debug Info Version", i32 3}
!51 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !52, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !48, retainedNodes: !55)
!52 = !DISubroutineType(types: !53)
!53 = !{!47, !54}
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!55 = !{!56}
!56 = !DILocalVariable(name: "ctx", arg: 1, scope: !51, file: !2, type: !54)
