; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !41 {
entry:
  %"@x_newval28" = alloca i64, align 8
  %lookup_elem_val26 = alloca i64, align 8
  %"@x_key21" = alloca i64, align 8
  %"@x_newval19" = alloca i64, align 8
  %lookup_elem_val17 = alloca i64, align 8
  %"@x_key12" = alloca i64, align 8
  %"@x_newval10" = alloca i64, align 8
  %lookup_elem_val8 = alloca i64, align 8
  %"@x_key3" = alloca i64, align 8
  %"@x_newval" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key1" = alloca i64, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_val")
  store i64 10, ptr %"@x_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key1")
  store i64 0, ptr %"@x_key1", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key1")
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
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_newval")
  %3 = add i64 %2, 1
  store i64 %3, ptr %"@x_newval", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key1", ptr %"@x_newval", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_newval")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key1")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key3")
  store i64 0, ptr %"@x_key3", align 8
  %lookup_elem4 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key3")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val8)
  %map_lookup_cond9 = icmp ne ptr %lookup_elem4, null
  br i1 %map_lookup_cond9, label %lookup_success5, label %lookup_failure6

lookup_success5:                                  ; preds = %lookup_merge
  %4 = load i64, ptr %lookup_elem4, align 8
  store i64 %4, ptr %lookup_elem_val8, align 8
  br label %lookup_merge7

lookup_failure6:                                  ; preds = %lookup_merge
  store i64 0, ptr %lookup_elem_val8, align 8
  br label %lookup_merge7

lookup_merge7:                                    ; preds = %lookup_failure6, %lookup_success5
  %5 = load i64, ptr %lookup_elem_val8, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val8)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_newval10")
  %6 = add i64 %5, 1
  store i64 %6, ptr %"@x_newval10", align 8
  %update_elem11 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key3", ptr %"@x_newval10", i64 0)
  %7 = load i64, ptr %"@x_newval10", align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_newval10")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key3")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key12")
  store i64 0, ptr %"@x_key12", align 8
  %lookup_elem13 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key12")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val17)
  %map_lookup_cond18 = icmp ne ptr %lookup_elem13, null
  br i1 %map_lookup_cond18, label %lookup_success14, label %lookup_failure15

lookup_success14:                                 ; preds = %lookup_merge7
  %8 = load i64, ptr %lookup_elem13, align 8
  store i64 %8, ptr %lookup_elem_val17, align 8
  br label %lookup_merge16

lookup_failure15:                                 ; preds = %lookup_merge7
  store i64 0, ptr %lookup_elem_val17, align 8
  br label %lookup_merge16

lookup_merge16:                                   ; preds = %lookup_failure15, %lookup_success14
  %9 = load i64, ptr %lookup_elem_val17, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val17)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_newval19")
  %10 = sub i64 %9, 1
  store i64 %10, ptr %"@x_newval19", align 8
  %update_elem20 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key12", ptr %"@x_newval19", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_newval19")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key12")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key21")
  store i64 0, ptr %"@x_key21", align 8
  %lookup_elem22 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key21")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val26)
  %map_lookup_cond27 = icmp ne ptr %lookup_elem22, null
  br i1 %map_lookup_cond27, label %lookup_success23, label %lookup_failure24

lookup_success23:                                 ; preds = %lookup_merge16
  %11 = load i64, ptr %lookup_elem22, align 8
  store i64 %11, ptr %lookup_elem_val26, align 8
  br label %lookup_merge25

lookup_failure24:                                 ; preds = %lookup_merge16
  store i64 0, ptr %lookup_elem_val26, align 8
  br label %lookup_merge25

lookup_merge25:                                   ; preds = %lookup_failure24, %lookup_success23
  %12 = load i64, ptr %lookup_elem_val26, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val26)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_newval28")
  %13 = sub i64 %12, 1
  store i64 %13, ptr %"@x_newval28", align 8
  %update_elem29 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key21", ptr %"@x_newval28", i64 0)
  %14 = load i64, ptr %"@x_newval28", align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_newval28")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key21")
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
!41 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !42, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !38, retainedNodes: !46)
!42 = !DISubroutineType(types: !43)
!43 = !{!21, !44}
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!46 = !{!47}
!47 = !DILocalVariable(name: "ctx", arg: 1, scope: !41, file: !2, type: !44)
