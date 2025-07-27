; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.0" = type { ptr, ptr }
%join_t = type <{ i64, i64, [16384 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@join = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_internal_repr_t.0" zeroinitializer, section ".maps", !dbg !30
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !44
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !49

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !55 {
entry:
  %join_r0 = alloca i64, align 8
  %lookup_join_key = alloca i32, align 4
  %"struct arg.argv" = alloca i64, align 8
  %"$x" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$x")
  store i64 0, ptr %"$x", align 8
  store i64 0, ptr %"$x", align 8
  %1 = load i64, ptr %"$x", align 8
  %2 = inttoptr i64 %1 to ptr
  %3 = call ptr @llvm.preserve.static.offset(ptr %2)
  %4 = getelementptr i8, ptr %3, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct arg.argv")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"struct arg.argv", i32 8, ptr %4)
  %5 = load i64, ptr %"struct arg.argv", align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct arg.argv")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_join_key)
  store i32 0, ptr %lookup_join_key, align 4
  %lookup_join_map = call ptr inttoptr (i64 1 to ptr)(ptr @join, ptr %lookup_join_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_join_key)
  %lookup_join_cond = icmp ne ptr %lookup_join_map, null
  br i1 %lookup_join_cond, label %lookup_join_merge, label %lookup_join_failure

failure_callback:                                 ; preds = %counter_merge, %lookup_join_failure
  ret i64 0

lookup_join_failure:                              ; preds = %entry
  br label %failure_callback

lookup_join_merge:                                ; preds = %entry
  %6 = getelementptr %join_t, ptr %lookup_join_map, i64 0, i32 0
  store i64 30005, ptr %6, align 8
  %7 = getelementptr %join_t, ptr %lookup_join_map, i64 0, i32 1
  store i64 0, ptr %7, align 8
  %8 = getelementptr %join_t, ptr %lookup_join_map, i64 0, i32 2
  call void @llvm.lifetime.start.p0(i64 -1, ptr %join_r0)
  %probe_read_kernel1 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %5)
  %9 = getelementptr i8, ptr %8, i64 0
  %10 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to ptr)(ptr %9, i32 1024, i64 %10)
  %11 = add i64 %5, 8
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %11)
  %12 = getelementptr i8, ptr %8, i64 1024
  %13 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str3 = call i64 inttoptr (i64 115 to ptr)(ptr %12, i32 1024, i64 %13)
  %14 = add i64 %11, 8
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %14)
  %15 = getelementptr i8, ptr %8, i64 2048
  %16 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str5 = call i64 inttoptr (i64 115 to ptr)(ptr %15, i32 1024, i64 %16)
  %17 = add i64 %14, 8
  %probe_read_kernel6 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %17)
  %18 = getelementptr i8, ptr %8, i64 3072
  %19 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str7 = call i64 inttoptr (i64 115 to ptr)(ptr %18, i32 1024, i64 %19)
  %20 = add i64 %17, 8
  %probe_read_kernel8 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %20)
  %21 = getelementptr i8, ptr %8, i64 4096
  %22 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str9 = call i64 inttoptr (i64 115 to ptr)(ptr %21, i32 1024, i64 %22)
  %23 = add i64 %20, 8
  %probe_read_kernel10 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %23)
  %24 = getelementptr i8, ptr %8, i64 5120
  %25 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str11 = call i64 inttoptr (i64 115 to ptr)(ptr %24, i32 1024, i64 %25)
  %26 = add i64 %23, 8
  %probe_read_kernel12 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %26)
  %27 = getelementptr i8, ptr %8, i64 6144
  %28 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str13 = call i64 inttoptr (i64 115 to ptr)(ptr %27, i32 1024, i64 %28)
  %29 = add i64 %26, 8
  %probe_read_kernel14 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %29)
  %30 = getelementptr i8, ptr %8, i64 7168
  %31 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str15 = call i64 inttoptr (i64 115 to ptr)(ptr %30, i32 1024, i64 %31)
  %32 = add i64 %29, 8
  %probe_read_kernel16 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %32)
  %33 = getelementptr i8, ptr %8, i64 8192
  %34 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str17 = call i64 inttoptr (i64 115 to ptr)(ptr %33, i32 1024, i64 %34)
  %35 = add i64 %32, 8
  %probe_read_kernel18 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %35)
  %36 = getelementptr i8, ptr %8, i64 9216
  %37 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str19 = call i64 inttoptr (i64 115 to ptr)(ptr %36, i32 1024, i64 %37)
  %38 = add i64 %35, 8
  %probe_read_kernel20 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %38)
  %39 = getelementptr i8, ptr %8, i64 10240
  %40 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str21 = call i64 inttoptr (i64 115 to ptr)(ptr %39, i32 1024, i64 %40)
  %41 = add i64 %38, 8
  %probe_read_kernel22 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %41)
  %42 = getelementptr i8, ptr %8, i64 11264
  %43 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str23 = call i64 inttoptr (i64 115 to ptr)(ptr %42, i32 1024, i64 %43)
  %44 = add i64 %41, 8
  %probe_read_kernel24 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %44)
  %45 = getelementptr i8, ptr %8, i64 12288
  %46 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str25 = call i64 inttoptr (i64 115 to ptr)(ptr %45, i32 1024, i64 %46)
  %47 = add i64 %44, 8
  %probe_read_kernel26 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %47)
  %48 = getelementptr i8, ptr %8, i64 13312
  %49 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str27 = call i64 inttoptr (i64 115 to ptr)(ptr %48, i32 1024, i64 %49)
  %50 = add i64 %47, 8
  %probe_read_kernel28 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %50)
  %51 = getelementptr i8, ptr %8, i64 14336
  %52 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str29 = call i64 inttoptr (i64 115 to ptr)(ptr %51, i32 1024, i64 %52)
  %53 = add i64 %50, 8
  %probe_read_kernel30 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %53)
  %54 = getelementptr i8, ptr %8, i64 15360
  %55 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str31 = call i64 inttoptr (i64 115 to ptr)(ptr %54, i32 1024, i64 %55)
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_join_map, i64 16400, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %lookup_join_merge
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #3
  %56 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %56
  %57 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %58 = load i64, ptr %57, align 8
  %59 = add i64 %58, 1
  store i64 %59, ptr %57, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %lookup_join_merge
  br label %failure_callback
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #3 = { memory(none) }

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
!8 = distinct !DIGlobalVariable(name: "join", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !10)
!10 = !{!11, !17, !22, !25}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 192, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 6, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !18, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !20)
!20 = !{!21}
!21 = !DISubrange(count: 1, lowerBound: 0)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !23, size: 64, offset: 128)
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !26, size: 64, offset: 192)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 131200, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 16400, lowerBound: 0)
!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())
!31 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !32, isLocal: false, isDefinition: true)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !33)
!33 = !{!34, !39}
!34 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !35, size: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 27, lowerBound: 0)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !40, size: 64, offset: 64)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 262144, lowerBound: 0)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !47, size: 64, elements: !20)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !48, size: 64, elements: !20)
!48 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!49 = !DIGlobalVariableExpression(var: !50, expr: !DIExpression())
!50 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !48, isLocal: false, isDefinition: true)
!51 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !52)
!52 = !{!0, !7, !30, !44, !49}
!53 = !{i32 2, !"Debug Info Version", i32 3}
!54 = !{i32 7, !"uwtable", i32 0}
!55 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !51, retainedNodes: !59)
!56 = !DISubroutineType(types: !57)
!57 = !{!48, !58}
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!59 = !{!60}
!60 = !DILocalVariable(name: "ctx", arg: 1, scope: !55, file: !2, type: !58)
