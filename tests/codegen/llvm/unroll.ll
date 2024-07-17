; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_i = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !50 {
entry:
  %"@i_val43" = alloca i64, align 8
  %"@i_key42" = alloca i64, align 8
  %lookup_elem_val40 = alloca i64, align 8
  %"@i_key35" = alloca i64, align 8
  %"@i_val33" = alloca i64, align 8
  %"@i_key32" = alloca i64, align 8
  %lookup_elem_val30 = alloca i64, align 8
  %"@i_key25" = alloca i64, align 8
  %"@i_val23" = alloca i64, align 8
  %"@i_key22" = alloca i64, align 8
  %lookup_elem_val20 = alloca i64, align 8
  %"@i_key15" = alloca i64, align 8
  %"@i_val13" = alloca i64, align 8
  %"@i_key12" = alloca i64, align 8
  %lookup_elem_val10 = alloca i64, align 8
  %"@i_key5" = alloca i64, align 8
  %"@i_val3" = alloca i64, align 8
  %"@i_key2" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@i_key1" = alloca i64, align 8
  %"@i_val" = alloca i64, align 8
  %"@i_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key")
  store i64 0, ptr %"@i_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val")
  store i64 0, ptr %"@i_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key", ptr %"@i_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key1")
  store i64 0, ptr %"@i_key1", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key1")
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
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key1")
  %3 = add i64 %2, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key2")
  store i64 0, ptr %"@i_key2", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val3")
  store i64 %3, ptr %"@i_val3", align 8
  %update_elem4 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key2", ptr %"@i_val3", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val3")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key2")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key5")
  store i64 0, ptr %"@i_key5", align 8
  %lookup_elem6 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key5")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val10)
  %map_lookup_cond11 = icmp ne ptr %lookup_elem6, null
  br i1 %map_lookup_cond11, label %lookup_success7, label %lookup_failure8

lookup_success7:                                  ; preds = %lookup_merge
  %4 = load i64, ptr %lookup_elem6, align 8
  store i64 %4, ptr %lookup_elem_val10, align 8
  br label %lookup_merge9

lookup_failure8:                                  ; preds = %lookup_merge
  store i64 0, ptr %lookup_elem_val10, align 8
  br label %lookup_merge9

lookup_merge9:                                    ; preds = %lookup_failure8, %lookup_success7
  %5 = load i64, ptr %lookup_elem_val10, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val10)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key5")
  %6 = add i64 %5, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key12")
  store i64 0, ptr %"@i_key12", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val13")
  store i64 %6, ptr %"@i_val13", align 8
  %update_elem14 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key12", ptr %"@i_val13", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val13")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key12")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key15")
  store i64 0, ptr %"@i_key15", align 8
  %lookup_elem16 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key15")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val20)
  %map_lookup_cond21 = icmp ne ptr %lookup_elem16, null
  br i1 %map_lookup_cond21, label %lookup_success17, label %lookup_failure18

lookup_success17:                                 ; preds = %lookup_merge9
  %7 = load i64, ptr %lookup_elem16, align 8
  store i64 %7, ptr %lookup_elem_val20, align 8
  br label %lookup_merge19

lookup_failure18:                                 ; preds = %lookup_merge9
  store i64 0, ptr %lookup_elem_val20, align 8
  br label %lookup_merge19

lookup_merge19:                                   ; preds = %lookup_failure18, %lookup_success17
  %8 = load i64, ptr %lookup_elem_val20, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val20)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key15")
  %9 = add i64 %8, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key22")
  store i64 0, ptr %"@i_key22", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val23")
  store i64 %9, ptr %"@i_val23", align 8
  %update_elem24 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key22", ptr %"@i_val23", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val23")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key22")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key25")
  store i64 0, ptr %"@i_key25", align 8
  %lookup_elem26 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key25")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val30)
  %map_lookup_cond31 = icmp ne ptr %lookup_elem26, null
  br i1 %map_lookup_cond31, label %lookup_success27, label %lookup_failure28

lookup_success27:                                 ; preds = %lookup_merge19
  %10 = load i64, ptr %lookup_elem26, align 8
  store i64 %10, ptr %lookup_elem_val30, align 8
  br label %lookup_merge29

lookup_failure28:                                 ; preds = %lookup_merge19
  store i64 0, ptr %lookup_elem_val30, align 8
  br label %lookup_merge29

lookup_merge29:                                   ; preds = %lookup_failure28, %lookup_success27
  %11 = load i64, ptr %lookup_elem_val30, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val30)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key25")
  %12 = add i64 %11, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key32")
  store i64 0, ptr %"@i_key32", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val33")
  store i64 %12, ptr %"@i_val33", align 8
  %update_elem34 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key32", ptr %"@i_val33", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val33")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key32")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key35")
  store i64 0, ptr %"@i_key35", align 8
  %lookup_elem36 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key35")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val40)
  %map_lookup_cond41 = icmp ne ptr %lookup_elem36, null
  br i1 %map_lookup_cond41, label %lookup_success37, label %lookup_failure38

lookup_success37:                                 ; preds = %lookup_merge29
  %13 = load i64, ptr %lookup_elem36, align 8
  store i64 %13, ptr %lookup_elem_val40, align 8
  br label %lookup_merge39

lookup_failure38:                                 ; preds = %lookup_merge29
  store i64 0, ptr %lookup_elem_val40, align 8
  br label %lookup_merge39

lookup_merge39:                                   ; preds = %lookup_failure38, %lookup_success37
  %14 = load i64, ptr %lookup_elem_val40, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val40)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key35")
  %15 = add i64 %14, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key42")
  store i64 0, ptr %"@i_key42", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val43")
  store i64 %15, ptr %"@i_val43", align 8
  %update_elem44 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key42", ptr %"@i_val43", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val43")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key42")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!47}
!llvm.module.flags = !{!49}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_i", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!21 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !22, isLocal: false, isDefinition: true)
!22 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !23)
!23 = !{!24, !29}
!24 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !25, size: 64)
!25 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !26, size: 64)
!26 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !27)
!27 = !{!28}
!28 = !DISubrange(count: 27, lowerBound: 0)
!29 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !30, size: 64, offset: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 262144, lowerBound: 0)
!34 = !DIGlobalVariableExpression(var: !35, expr: !DIExpression())
!35 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!36 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !37)
!37 = !{!38, !43, !44, !19}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !39, size: 64)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 2, lowerBound: 0)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !45, size: 64, offset: 128)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!47 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !48)
!48 = !{!0, !20, !34}
!49 = !{i32 2, !"Debug Info Version", i32 3}
!50 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !51, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !47, retainedNodes: !55)
!51 = !DISubroutineType(types: !52)
!52 = !{!18, !53}
!53 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !54, size: 64)
!54 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!55 = !{!56}
!56 = !DILocalVariable(name: "ctx", arg: 1, scope: !50, file: !2, type: !53)
