; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr }
%buffer_2_t = type <{ i32, [2 x i8] }>
%buffer_3_t = type <{ i32, [3 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !16
@get_str_buf = dso_local externally_initialized global [1 x [2 x [1024 x i8]]] zeroinitializer, section ".data.get_str_buf", !dbg !19
@hi = global [3 x i8] c"hi\00"
@bye = global [4 x i8] c"bye\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !34 {
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

!llvm.dbg.cu = !{!31}
!llvm.module.flags = !{!33}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !4)
!4 = !{!5, !11}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 27, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 262144, lowerBound: 0)
!16 = !DIGlobalVariableExpression(var: !17, expr: !DIExpression())
!17 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!18 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!19 = !DIGlobalVariableExpression(var: !20, expr: !DIExpression())
!20 = distinct !DIGlobalVariable(name: "get_str_buf", linkageName: "global", scope: !2, file: !2, type: !21, isLocal: false, isDefinition: true)
!21 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 16384, elements: !29)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !23, size: 16384, elements: !27)
!23 = !DICompositeType(tag: DW_TAG_array_type, baseType: !24, size: 8192, elements: !25)
!24 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!25 = !{!26}
!26 = !DISubrange(count: 1024, lowerBound: 0)
!27 = !{!28}
!28 = !DISubrange(count: 2, lowerBound: 0)
!29 = !{!30}
!30 = !DISubrange(count: 1, lowerBound: 0)
!31 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !32)
!32 = !{!0, !16, !19}
!33 = !{i32 2, !"Debug Info Version", i32 3}
!34 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !35, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !31, retainedNodes: !38)
!35 = !DISubroutineType(types: !36)
!36 = !{!18, !37}
!37 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!38 = !{!39}
!39 = !DILocalVariable(name: "ctx", arg: 1, scope: !34, file: !2, type: !37)
