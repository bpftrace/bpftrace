; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"struct map_t.3" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !32
@str_buffer = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !46
@event_loss_counter = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !55

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !60 {
entry:
  %"@y_key" = alloca i64, align 8
  %str = alloca [1 x i8], align 1
  %lookup_str_key = alloca i32, align 4
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_val")
  store i64 0, ptr %"@x_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_str_key)
  store i32 0, ptr %lookup_str_key, align 4
  %lookup_str_map = call ptr inttoptr (i64 1 to ptr)(ptr @str_buffer, ptr %lookup_str_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_str_key)
  %lookup_str_cond = icmp ne ptr %lookup_str_map, null
  br i1 %lookup_str_cond, label %lookup_str_merge, label %lookup_str_failure

lookup_str_failure:                               ; preds = %entry
  ret i64 0

lookup_str_merge:                                 ; preds = %entry
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_str_map, i8 0, i64 64, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %str)
  call void @llvm.memset.p0.i64(ptr align 1 %str, i8 0, i64 1, i1 false)
  store [1 x i8] zeroinitializer, ptr %str, align 1
  %1 = ptrtoint ptr %str to i64
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to ptr)(ptr %lookup_str_map, i32 64, i64 %1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %str)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %lookup_str_map, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!57}
!llvm.module.flags = !{!59}

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
!23 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !25)
!25 = !{!5, !11, !16, !26}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !27, size: 64, offset: 192)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !29, size: 512, elements: !30)
!29 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!30 = !{!31}
!31 = !DISubrange(count: 64, lowerBound: 0)
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
!47 = distinct !DIGlobalVariable(name: "str_buffer", linkageName: "global", scope: !2, file: !2, type: !48, isLocal: false, isDefinition: true)
!48 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !49)
!49 = !{!50, !11, !16, !26}
!50 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !51, size: 64)
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !53)
!53 = !{!54}
!54 = !DISubrange(count: 6, lowerBound: 0)
!55 = !DIGlobalVariableExpression(var: !56, expr: !DIExpression())
!56 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!57 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !58)
!58 = !{!0, !22, !32, !46, !55}
!59 = !{i32 2, !"Debug Info Version", i32 3}
!60 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !61, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !57, retainedNodes: !64)
!61 = !DISubroutineType(types: !62)
!62 = !{!21, !63}
!63 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!64 = !{!65}
!65 = !DILocalVariable(name: "ctx", arg: 1, scope: !60, file: !2, type: !63)
