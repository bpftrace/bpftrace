; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !41 {
entry:
  %"@_newval" = alloca i64, align 8
  %lookup_elem_val7 = alloca i64, align 8
  %"@_key2" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@_key1" = alloca i64, align 8
  %"@_ptr" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key")
  store i64 0, ptr %"@_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_ptr")
  store i64 1000, ptr %"@_ptr", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_, ptr %"@_key", ptr %"@_ptr", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_ptr")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key1")
  store i64 0, ptr %"@_key1", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_, ptr %"@_key1")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %1 = load i64, ptr %lookup_elem, align 8
  store i64 %1, ptr %lookup_elem_val, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, ptr %lookup_elem_val, align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %2 = load i64, ptr %lookup_elem_val, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key1")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key2")
  store i64 0, ptr %"@_key2", align 8
  %lookup_elem3 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_, ptr %"@_key2")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val7)
  %map_lookup_cond8 = icmp ne ptr %lookup_elem3, null
  br i1 %map_lookup_cond8, label %lookup_success4, label %lookup_failure5

lookup_success4:                                  ; preds = %lookup_merge
  %3 = load i64, ptr %lookup_elem3, align 8
  store i64 %3, ptr %lookup_elem_val7, align 8
  br label %lookup_merge6

lookup_failure5:                                  ; preds = %lookup_merge
  store i64 0, ptr %lookup_elem_val7, align 8
  br label %lookup_merge6

lookup_merge6:                                    ; preds = %lookup_failure5, %lookup_success4
  %4 = load i64, ptr %lookup_elem_val7, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val7)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_newval")
  %5 = add i64 %4, 2
  store i64 %5, ptr %"@_newval", align 8
  %update_elem9 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_, ptr %"@_key2", ptr %"@_newval", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_newval")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key2")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!38}
!llvm.module.flags = !{!40}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!38 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !39)
!39 = !{!0, !22, !36}
!40 = !{i32 2, !"Debug Info Version", i32 3}
!41 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !42, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !38, retainedNodes: !46)
!42 = !DISubroutineType(types: !43)
!43 = !{!21, !44}
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!46 = !{!47}
!47 = !DILocalVariable(name: "ctx", arg: 1, scope: !41, file: !2, type: !44)
