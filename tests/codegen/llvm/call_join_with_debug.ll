; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@join = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !30
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !44

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !59 {
entry:
  %key = alloca i32, align 4
  %join_r0 = alloca i64, align 8
  %fmt_str = alloca [70 x i8], align 1
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
  call void @llvm.lifetime.start.p0(i64 -1, ptr %fmt_str)
  call void @llvm.memset.p0.i64(ptr align 1 %fmt_str, i8 0, i64 70, i1 false)
  store [70 x i8] c"[BPFTRACE_DEBUG_OUTPUT] unable to find the scratch map value for join\00", ptr %fmt_str, align 1
  %trace_printk = call i64 (ptr, i32, ...) inttoptr (i64 6 to ptr)(ptr %fmt_str, i32 70)
  br label %failure_callback

lookup_join_merge:                                ; preds = %entry
  store i64 30005, ptr %lookup_join_map, align 8
  %6 = getelementptr i8, ptr %lookup_join_map, i64 8
  store i64 0, ptr %6, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %join_r0)
  %probe_read_kernel1 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %5)
  %7 = load i64, ptr %join_r0, align 8
  %8 = getelementptr i8, ptr %lookup_join_map, i64 16
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to ptr)(ptr %8, i32 1024, i64 %7)
  %9 = add i64 %5, 8
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %9)
  %10 = load i64, ptr %join_r0, align 8
  %11 = getelementptr i8, ptr %lookup_join_map, i64 1040
  %probe_read_kernel_str3 = call i64 inttoptr (i64 115 to ptr)(ptr %11, i32 1024, i64 %10)
  %12 = add i64 %9, 8
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %12)
  %13 = load i64, ptr %join_r0, align 8
  %14 = getelementptr i8, ptr %lookup_join_map, i64 2064
  %probe_read_kernel_str5 = call i64 inttoptr (i64 115 to ptr)(ptr %14, i32 1024, i64 %13)
  %15 = add i64 %12, 8
  %probe_read_kernel6 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %15)
  %16 = load i64, ptr %join_r0, align 8
  %17 = getelementptr i8, ptr %lookup_join_map, i64 3088
  %probe_read_kernel_str7 = call i64 inttoptr (i64 115 to ptr)(ptr %17, i32 1024, i64 %16)
  %18 = add i64 %15, 8
  %probe_read_kernel8 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %18)
  %19 = load i64, ptr %join_r0, align 8
  %20 = getelementptr i8, ptr %lookup_join_map, i64 4112
  %probe_read_kernel_str9 = call i64 inttoptr (i64 115 to ptr)(ptr %20, i32 1024, i64 %19)
  %21 = add i64 %18, 8
  %probe_read_kernel10 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %21)
  %22 = load i64, ptr %join_r0, align 8
  %23 = getelementptr i8, ptr %lookup_join_map, i64 5136
  %probe_read_kernel_str11 = call i64 inttoptr (i64 115 to ptr)(ptr %23, i32 1024, i64 %22)
  %24 = add i64 %21, 8
  %probe_read_kernel12 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %24)
  %25 = load i64, ptr %join_r0, align 8
  %26 = getelementptr i8, ptr %lookup_join_map, i64 6160
  %probe_read_kernel_str13 = call i64 inttoptr (i64 115 to ptr)(ptr %26, i32 1024, i64 %25)
  %27 = add i64 %24, 8
  %probe_read_kernel14 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %27)
  %28 = load i64, ptr %join_r0, align 8
  %29 = getelementptr i8, ptr %lookup_join_map, i64 7184
  %probe_read_kernel_str15 = call i64 inttoptr (i64 115 to ptr)(ptr %29, i32 1024, i64 %28)
  %30 = add i64 %27, 8
  %probe_read_kernel16 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %30)
  %31 = load i64, ptr %join_r0, align 8
  %32 = getelementptr i8, ptr %lookup_join_map, i64 8208
  %probe_read_kernel_str17 = call i64 inttoptr (i64 115 to ptr)(ptr %32, i32 1024, i64 %31)
  %33 = add i64 %30, 8
  %probe_read_kernel18 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %33)
  %34 = load i64, ptr %join_r0, align 8
  %35 = getelementptr i8, ptr %lookup_join_map, i64 9232
  %probe_read_kernel_str19 = call i64 inttoptr (i64 115 to ptr)(ptr %35, i32 1024, i64 %34)
  %36 = add i64 %33, 8
  %probe_read_kernel20 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %36)
  %37 = load i64, ptr %join_r0, align 8
  %38 = getelementptr i8, ptr %lookup_join_map, i64 10256
  %probe_read_kernel_str21 = call i64 inttoptr (i64 115 to ptr)(ptr %38, i32 1024, i64 %37)
  %39 = add i64 %36, 8
  %probe_read_kernel22 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %39)
  %40 = load i64, ptr %join_r0, align 8
  %41 = getelementptr i8, ptr %lookup_join_map, i64 11280
  %probe_read_kernel_str23 = call i64 inttoptr (i64 115 to ptr)(ptr %41, i32 1024, i64 %40)
  %42 = add i64 %39, 8
  %probe_read_kernel24 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %42)
  %43 = load i64, ptr %join_r0, align 8
  %44 = getelementptr i8, ptr %lookup_join_map, i64 12304
  %probe_read_kernel_str25 = call i64 inttoptr (i64 115 to ptr)(ptr %44, i32 1024, i64 %43)
  %45 = add i64 %42, 8
  %probe_read_kernel26 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %45)
  %46 = load i64, ptr %join_r0, align 8
  %47 = getelementptr i8, ptr %lookup_join_map, i64 13328
  %probe_read_kernel_str27 = call i64 inttoptr (i64 115 to ptr)(ptr %47, i32 1024, i64 %46)
  %48 = add i64 %45, 8
  %probe_read_kernel28 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %48)
  %49 = load i64, ptr %join_r0, align 8
  %50 = getelementptr i8, ptr %lookup_join_map, i64 14352
  %probe_read_kernel_str29 = call i64 inttoptr (i64 115 to ptr)(ptr %50, i32 1024, i64 %49)
  %51 = add i64 %48, 8
  %probe_read_kernel30 = call i64 inttoptr (i64 113 to ptr)(ptr %join_r0, i32 8, i64 %51)
  %52 = load i64, ptr %join_r0, align 8
  %53 = getelementptr i8, ptr %lookup_join_map, i64 15376
  %probe_read_kernel_str31 = call i64 inttoptr (i64 115 to ptr)(ptr %53, i32 1024, i64 %52)
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_join_map, i64 16400, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %lookup_join_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %lookup_join_merge
  br label %failure_callback

lookup_success:                                   ; preds = %event_loss_counter
  %54 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!56}
!llvm.module.flags = !{!58}

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
!45 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !47)
!47 = !{!48, !17, !22, !53}
!48 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !49, size: 64)
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!50 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 64, elements: !51)
!51 = !{!52}
!52 = !DISubrange(count: 2, lowerBound: 0)
!53 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !54, size: 64, offset: 192)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!56 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !57)
!57 = !{!0, !7, !30, !44}
!58 = !{i32 2, !"Debug Info Version", i32 3}
!59 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !60, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !56, retainedNodes: !63)
!60 = !DISubroutineType(types: !61)
!61 = !{!55, !62}
!62 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!63 = !{!64}
!64 = !DILocalVariable(name: "ctx", arg: 1, scope: !59, file: !2, type: !62)
