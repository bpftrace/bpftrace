; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_mystr = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !21
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !35
@get_str_buf = dso_local externally_initialized global [1 x [1 x [1024 x i8]]] zeroinitializer, section ".data.get_str_buf", !dbg !37

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !44 {
entry:
  %"@mystr_key" = alloca i64, align 8
  %"struct Foo.str" = alloca i64, align 8
  %"$foo" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$foo")
  store i64 0, ptr %"$foo", align 8
  %1 = call ptr @llvm.preserve.static.offset(ptr %0)
  %2 = getelementptr i64, ptr %1, i64 14
  %arg0 = load volatile i64, ptr %2, align 8
  store i64 %arg0, ptr %"$foo", align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %3 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %3
  %4 = getelementptr [1 x [1 x [1024 x i8]]], ptr @get_str_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %4, i32 1024, ptr null)
  %5 = load i64, ptr %"$foo", align 8
  %6 = inttoptr i64 %5 to ptr
  %7 = call ptr @llvm.preserve.static.offset(ptr %6)
  %8 = getelementptr i8, ptr %7, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct Foo.str")
  %probe_read_kernel1 = call i64 inttoptr (i64 113 to ptr)(ptr %"struct Foo.str", i32 8, ptr %8)
  %9 = load i64, ptr %"struct Foo.str", align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct Foo.str")
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to ptr)(ptr %4, i32 1024, i64 %9)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@mystr_key")
  store i64 0, ptr %"@mystr_key", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_mystr, ptr %"@mystr_key", ptr %4, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@mystr_key")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!41}
!llvm.module.flags = !{!43}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_mystr", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !12, !15}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !13, size: 64, offset: 128)
!13 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !14, size: 64)
!14 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!15 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !16, size: 64, offset: 192)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !17, size: 64)
!17 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 8192, elements: !19)
!18 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DISubrange(count: 1024, lowerBound: 0)
!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())
!22 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !23, isLocal: false, isDefinition: true)
!23 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !24)
!24 = !{!25, !30}
!25 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !26, size: 64)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 27, lowerBound: 0)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !31, size: 64, offset: 64)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !33)
!33 = !{!34}
!34 = !DISubrange(count: 262144, lowerBound: 0)
!35 = !DIGlobalVariableExpression(var: !36, expr: !DIExpression())
!36 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !14, isLocal: false, isDefinition: true)
!37 = !DIGlobalVariableExpression(var: !38, expr: !DIExpression())
!38 = distinct !DIGlobalVariable(name: "get_str_buf", linkageName: "global", scope: !2, file: !2, type: !39, isLocal: false, isDefinition: true)
!39 = !DICompositeType(tag: DW_TAG_array_type, baseType: !40, size: 8192, elements: !9)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !17, size: 8192, elements: !9)
!41 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !42)
!42 = !{!0, !21, !35, !37}
!43 = !{i32 2, !"Debug Info Version", i32 3}
!44 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !45, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !41, retainedNodes: !48)
!45 = !DISubroutineType(types: !46)
!46 = !{!14, !47}
!47 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!48 = !{!49}
!49 = !DILocalVariable(name: "ctx", arg: 1, scope: !44, file: !2, type: !47)
