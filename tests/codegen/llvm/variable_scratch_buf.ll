; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@event_loss_counter = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !42
@var_buf = dso_local externally_initialized global [1 x [2 x [8 x i8]]] zeroinitializer, section ".data.var_buf", !dbg !44

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !55 {
entry:
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %1
  %2 = getelementptr [1 x [2 x [8 x i8]]], ptr @var_buf, i64 0, i64 %cpu.id.bounded2, i64 1, i64 0
  store i64 0, ptr %2, align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %3 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %3
  %4 = getelementptr [1 x [2 x [8 x i8]]], ptr @var_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  store i64 0, ptr %4, align 8
  %5 = call ptr @llvm.preserve.static.offset(ptr %0)
  %6 = getelementptr i64, ptr %5, i64 14
  %arg0 = load volatile i64, ptr %6, align 8
  %7 = icmp ugt i64 %arg0, 0
  %true_cond = icmp ne i1 %7, false
  br i1 %true_cond, label %if_body, label %else_body

if_body:                                          ; preds = %entry
  store i64 1, ptr %4, align 8
  br label %if_end

if_end:                                           ; preds = %else_body, %if_body
  ret i64 0

else_body:                                        ; preds = %entry
  store i64 2, ptr %2, align 8
  br label %if_end
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }

!llvm.dbg.cu = !{!51}
!llvm.module.flags = !{!53, !54}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !10)
!10 = !{!11, !17}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 27, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !18, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !20)
!20 = !{!21}
!21 = !DISubrange(count: 262144, lowerBound: 0)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !25)
!25 = !{!26, !31, !36, !39}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 64, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 2, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !32, size: 64, offset: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 1, lowerBound: 0)
!36 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !37, size: 64, offset: 128)
!37 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !38, size: 64)
!38 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !40, size: 64, offset: 192)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!42 = !DIGlobalVariableExpression(var: !43, expr: !DIExpression())
!43 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !41, isLocal: false, isDefinition: true)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "var_buf", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !47, size: 128, elements: !34)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !48, size: 128, elements: !29)
!48 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 64, elements: !49)
!49 = !{!50}
!50 = !DISubrange(count: 8, lowerBound: 0)
!51 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !52)
!52 = !{!0, !7, !22, !42, !44}
!53 = !{i32 2, !"Debug Info Version", i32 3}
!54 = !{i32 7, !"uwtable", i32 0}
!55 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !51, retainedNodes: !59)
!56 = !DISubroutineType(types: !57)
!57 = !{!41, !58}
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!59 = !{!60}
!60 = !DILocalVariable(name: "ctx", arg: 1, scope: !55, file: !2, type: !58)
