; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"unsigned int8_usym_int64__tuple_t" = type { i8, [24 x i8], i64 }
%usym_t = type { i64, i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_t = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !31
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !45

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !54 {
entry:
  %"@t_key" = alloca i64, align 8
  %tuple = alloca %"unsigned int8_usym_int64__tuple_t", align 8
  %usym = alloca %usym_t, align 8
  %1 = getelementptr i64, ptr %0, i64 16
  %reg_ip = load volatile i64, ptr %1, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %usym)
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)()
  %2 = lshr i64 %get_pid_tgid, 32
  %3 = getelementptr %usym_t, ptr %usym, i64 0, i32 0
  %4 = getelementptr %usym_t, ptr %usym, i64 0, i32 1
  %5 = getelementptr %usym_t, ptr %usym, i64 0, i32 2
  store i64 %reg_ip, ptr %3, align 8
  store i64 %2, ptr %4, align 8
  store i64 0, ptr %5, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %tuple)
  call void @llvm.memset.p0.i64(ptr align 1 %tuple, i8 0, i64 40, i1 false)
  %6 = getelementptr %"unsigned int8_usym_int64__tuple_t", ptr %tuple, i32 0, i32 0
  store i8 1, ptr %6, align 1
  %7 = getelementptr %"unsigned int8_usym_int64__tuple_t", ptr %tuple, i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %7, ptr align 1 %usym, i64 24, i1 false)
  %8 = getelementptr %"unsigned int8_usym_int64__tuple_t", ptr %tuple, i32 0, i32 2
  store i64 10, ptr %8, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@t_key")
  store i64 0, ptr %"@t_key", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_t, ptr %"@t_key", ptr %tuple, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@t_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %tuple)
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

!llvm.dbg.cu = !{!51}
!llvm.module.flags = !{!53}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_t", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!21 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 320, elements: !22)
!22 = !{!23, !25, !29}
!23 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !24, size: 8)
!24 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!25 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !26, size: 192, offset: 8)
!26 = !DICompositeType(tag: DW_TAG_array_type, baseType: !24, size: 192, elements: !27)
!27 = !{!28}
!28 = !DISubrange(count: 24, lowerBound: 0)
!29 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !30, size: 64, offset: 256)
!30 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!31 = !DIGlobalVariableExpression(var: !32, expr: !DIExpression())
!32 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !33, isLocal: false, isDefinition: true)
!33 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !34)
!34 = !{!35, !40}
!35 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !36, size: 64)
!36 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !37, size: 64)
!37 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !38)
!38 = !{!39}
!39 = !DISubrange(count: 27, lowerBound: 0)
!40 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !41, size: 64, offset: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 262144, lowerBound: 0)
!45 = !DIGlobalVariableExpression(var: !46, expr: !DIExpression())
!46 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !47, isLocal: false, isDefinition: true)
!47 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !48)
!48 = !{!5, !11, !16, !49}
!49 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !50, size: 64, offset: 192)
!50 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !30, size: 64)
!51 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !52)
!52 = !{!0, !31, !45}
!53 = !{i32 2, !"Debug Info Version", i32 3}
!54 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !55, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !51, retainedNodes: !58)
!55 = !DISubroutineType(types: !56)
!56 = !{!30, !57}
!57 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!58 = !{!59}
!59 = !DILocalVariable(name: "ctx", arg: 1, scope: !54, file: !2, type: !57)
