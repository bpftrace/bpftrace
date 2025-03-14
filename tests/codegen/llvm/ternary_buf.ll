; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%buffer_2_t = type <{ i32, [2 x i8] }>
%buffer_3_t = type <{ i32, [3 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@event_loss_counter = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !42
@get_str_buf = dso_local externally_initialized global [1 x [2 x [1024 x i8]]] zeroinitializer, section ".data.get_str_buf", !dbg !44
@hi = global [3 x i8] c"hi\00"
@bye = global [4 x i8] c"bye\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !54 {
entry:
  %"$x" = alloca [7 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$x")
  call void @llvm.memset.p0.i64(ptr align 1 %"$x", i8 0, i64 7, i1 false)
  %1 = alloca [7 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %1)
  call void @llvm.memset.p0.i64(ptr align 1 %1, i8 0, i64 7, i1 false)
  %get_ns = call i64 inttoptr (i64 125 to ptr)()
  %true_cond = icmp ne i64 %get_ns, 0
  br i1 %true_cond, label %left, label %right

left:                                             ; preds = %entry
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %2 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %2
  %3 = getelementptr [1 x [2 x [1024 x i8]]], ptr @get_str_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  %4 = getelementptr %buffer_2_t, ptr %3, i32 0, i32 0
  store i32 2, ptr %4, align 4
  %5 = getelementptr %buffer_2_t, ptr %3, i32 0, i32 1
  call void @llvm.memset.p0.i64(ptr align 1 %5, i8 0, i64 2, i1 false)
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %5, i32 2, ptr @hi)
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %1, ptr align 1 %3, i64 7, i1 false)
  br label %done

right:                                            ; preds = %entry
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)()
  %6 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %6
  %7 = getelementptr [1 x [2 x [1024 x i8]]], ptr @get_str_buf, i64 0, i64 %cpu.id.bounded2, i64 1, i64 0
  %8 = getelementptr %buffer_3_t, ptr %7, i32 0, i32 0
  store i32 3, ptr %8, align 4
  %9 = getelementptr %buffer_3_t, ptr %7, i32 0, i32 1
  call void @llvm.memset.p0.i64(ptr align 1 %9, i8 0, i64 3, i1 false)
  %probe_read_kernel3 = call i64 inttoptr (i64 113 to ptr)(ptr %9, i32 3, ptr @bye)
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %1, ptr align 1 %7, i64 7, i1 false)
  br label %done

done:                                             ; preds = %right, %left
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %"$x", ptr align 1 %1, i64 7, i1 false)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %1)
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
!45 = distinct !DIGlobalVariable(name: "get_str_buf", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !47, size: 16384, elements: !34)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !48, size: 16384, elements: !29)
!48 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 8192, elements: !49)
!49 = !{!50}
!50 = !DISubrange(count: 1024, lowerBound: 0)
!51 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !52)
!52 = !{!0, !7, !22, !42, !44}
!53 = !{i32 2, !"Debug Info Version", i32 3}
!54 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !55, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !51, retainedNodes: !58)
!55 = !DISubroutineType(types: !56)
!56 = !{!41, !57}
!57 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!58 = !{!59}
!59 = !DILocalVariable(name: "ctx", arg: 1, scope: !54, file: !2, type: !57)
