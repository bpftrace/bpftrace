; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.149" = type { ptr, ptr }
%join_t = type <{ i64, i64, [16384 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@join = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_internal_repr_t.149" zeroinitializer, section ".maps", !dbg !30
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !44
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !49

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !55 {
entry:
  %join_r0 = alloca i64, align 8
  %lookup_join_key = alloca i32, align 4
  %"struct arg.argv" = alloca ptr, align 8
  %"$x" = alloca ptr, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$x")
  store i0 0, ptr %"$x", align 1
  store ptr null, ptr %"$x", align 8
  %1 = load ptr, ptr %"$x", align 8
  %2 = call ptr @llvm.preserve.static.offset(ptr %1)
  %3 = getelementptr i8, ptr %2, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct arg.argv")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"struct arg.argv", i32 8, ptr %3)
  %4 = load ptr, ptr %"struct arg.argv", align 8
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
  %5 = getelementptr %join_t, ptr %lookup_join_map, i64 0, i32 0
  store i64 30005, ptr %5, align 8
  %6 = getelementptr %join_t, ptr %lookup_join_map, i64 0, i32 1
  store i64 0, ptr %6, align 8
  %7 = getelementptr %join_t, ptr %lookup_join_map, i64 0, i32 2
  call void @llvm.lifetime.start.p0(i64 -1, ptr %join_r0)
  %probe_read_kernel1 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %4)
  %8 = getelementptr i8, ptr %7, i64 0
  %9 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to ptr)(ptr %8, i32 1024, i64 %9)
  %10 = getelementptr ptr, ptr %4, i32 1
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %10)
  %11 = getelementptr i8, ptr %7, i64 1024
  %12 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str3 = call i64 inttoptr (i64 115 to ptr)(ptr %11, i32 1024, i64 %12)
  %13 = getelementptr ptr, ptr %10, i32 2
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %13)
  %14 = getelementptr i8, ptr %7, i64 2048
  %15 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str5 = call i64 inttoptr (i64 115 to ptr)(ptr %14, i32 1024, i64 %15)
  %16 = getelementptr ptr, ptr %13, i32 3
  %probe_read_kernel6 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %16)
  %17 = getelementptr i8, ptr %7, i64 3072
  %18 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str7 = call i64 inttoptr (i64 115 to ptr)(ptr %17, i32 1024, i64 %18)
  %19 = getelementptr ptr, ptr %16, i32 4
  %probe_read_kernel8 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %19)
  %20 = getelementptr i8, ptr %7, i64 4096
  %21 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str9 = call i64 inttoptr (i64 115 to ptr)(ptr %20, i32 1024, i64 %21)
  %22 = getelementptr ptr, ptr %19, i32 5
  %probe_read_kernel10 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %22)
  %23 = getelementptr i8, ptr %7, i64 5120
  %24 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str11 = call i64 inttoptr (i64 115 to ptr)(ptr %23, i32 1024, i64 %24)
  %25 = getelementptr ptr, ptr %22, i32 6
  %probe_read_kernel12 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %25)
  %26 = getelementptr i8, ptr %7, i64 6144
  %27 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str13 = call i64 inttoptr (i64 115 to ptr)(ptr %26, i32 1024, i64 %27)
  %28 = getelementptr ptr, ptr %25, i32 7
  %probe_read_kernel14 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %28)
  %29 = getelementptr i8, ptr %7, i64 7168
  %30 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str15 = call i64 inttoptr (i64 115 to ptr)(ptr %29, i32 1024, i64 %30)
  %31 = getelementptr ptr, ptr %28, i32 8
  %probe_read_kernel16 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %31)
  %32 = getelementptr i8, ptr %7, i64 8192
  %33 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str17 = call i64 inttoptr (i64 115 to ptr)(ptr %32, i32 1024, i64 %33)
  %34 = getelementptr ptr, ptr %31, i32 9
  %probe_read_kernel18 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %34)
  %35 = getelementptr i8, ptr %7, i64 9216
  %36 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str19 = call i64 inttoptr (i64 115 to ptr)(ptr %35, i32 1024, i64 %36)
  %37 = getelementptr ptr, ptr %34, i32 10
  %probe_read_kernel20 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %37)
  %38 = getelementptr i8, ptr %7, i64 10240
  %39 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str21 = call i64 inttoptr (i64 115 to ptr)(ptr %38, i32 1024, i64 %39)
  %40 = getelementptr ptr, ptr %37, i32 11
  %probe_read_kernel22 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %40)
  %41 = getelementptr i8, ptr %7, i64 11264
  %42 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str23 = call i64 inttoptr (i64 115 to ptr)(ptr %41, i32 1024, i64 %42)
  %43 = getelementptr ptr, ptr %40, i32 12
  %probe_read_kernel24 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %43)
  %44 = getelementptr i8, ptr %7, i64 12288
  %45 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str25 = call i64 inttoptr (i64 115 to ptr)(ptr %44, i32 1024, i64 %45)
  %46 = getelementptr ptr, ptr %43, i32 13
  %probe_read_kernel26 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %46)
  %47 = getelementptr i8, ptr %7, i64 13312
  %48 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str27 = call i64 inttoptr (i64 115 to ptr)(ptr %47, i32 1024, i64 %48)
  %49 = getelementptr ptr, ptr %46, i32 14
  %probe_read_kernel28 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %49)
  %50 = getelementptr i8, ptr %7, i64 14336
  %51 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str29 = call i64 inttoptr (i64 115 to ptr)(ptr %50, i32 1024, i64 %51)
  %52 = getelementptr ptr, ptr %49, i32 15
  %probe_read_kernel30 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, ptr %52)
  %53 = getelementptr i8, ptr %7, i64 15360
  %54 = load i64, ptr %join_r0, align 8
  %probe_read_kernel_str31 = call i64 inttoptr (i64 115 to ptr)(ptr %53, i32 1024, i64 %54)
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_join_map, i64 16400, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %lookup_join_merge
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #3
  %55 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %55
  %56 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %57 = load i64, ptr %56, align 8
  %58 = add i64 %57, 1
  store i64 %58, ptr %56, align 8
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
