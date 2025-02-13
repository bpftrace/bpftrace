; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%buffer_2_t = type <{ i32, [2 x i8] }>
%buffer_3_t = type <{ i32, [3 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@event_loss_counter = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !36
@get_str_buf = dso_local externally_initialized global [1 x [2 x [1024 x i8]]] zeroinitializer, section ".data.get_str_buf", !dbg !38
@hi = global [3 x i8] c"hi\00"
@bye = global [4 x i8] c"bye\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !49 {
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

!llvm.dbg.cu = !{!46}
!llvm.module.flags = !{!48}

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
!17 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !19)
!19 = !{!20, !25, !30, !33}
!20 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !21, size: 64)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !23)
!23 = !{!24}
!24 = !DISubrange(count: 2, lowerBound: 0)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !26, size: 64, offset: 64)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 1, lowerBound: 0)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !31, size: 64, offset: 128)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !34, size: 64, offset: 192)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !35, isLocal: false, isDefinition: true)
!38 = !DIGlobalVariableExpression(var: !39, expr: !DIExpression())
!39 = distinct !DIGlobalVariable(name: "get_str_buf", linkageName: "global", scope: !2, file: !2, type: !40, isLocal: false, isDefinition: true)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !41, size: 16384, elements: !28)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !42, size: 16384, elements: !23)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !43, size: 8192, elements: !44)
!43 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!44 = !{!45}
!45 = !DISubrange(count: 1024, lowerBound: 0)
!46 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !47)
!47 = !{!0, !16, !36, !38}
!48 = !{i32 2, !"Debug Info Version", i32 3}
!49 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !50, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !46, retainedNodes: !53)
!50 = !DISubroutineType(types: !51)
!51 = !{!35, !52}
!52 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!53 = !{!54}
!54 = !DILocalVariable(name: "ctx", arg: 1, scope: !49, file: !2, type: !52)
