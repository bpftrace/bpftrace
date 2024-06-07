; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@join = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !39

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !55 {
entry:
  %key = alloca i32, align 4
  %join_r0 = alloca i64, align 8
  %fmt_str = alloca [70 x i8], align 1
  %lookup_join_key = alloca i32, align 4
  %"struct arg.argv" = alloca i64, align 8
  %"$x" = alloca i64, align 8
  %1 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$x", align 8
  store i64 0, i64* %"$x", align 8
  %2 = load i64, i64* %"$x", align 8
  %3 = add i64 %2, 0
  %4 = bitcast i64* %"struct arg.argv" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %"struct arg.argv", i32 8, i64 %3)
  %5 = load i64, i64* %"struct arg.argv", align 8
  %6 = bitcast i64* %"struct arg.argv" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = bitcast i32* %lookup_join_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i32 0, i32* %lookup_join_key, align 4
  %lookup_join_map = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i32*)*)(%"struct map_t"* @join, i32* %lookup_join_key)
  %8 = bitcast i32* %lookup_join_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %lookup_join_cond = icmp ne i8* %lookup_join_map, null
  br i1 %lookup_join_cond, label %lookup_join_merge, label %lookup_join_failure

failure_callback:                                 ; preds = %counter_merge, %lookup_join_failure
  ret i64 0

lookup_join_failure:                              ; preds = %entry
  %9 = bitcast [70 x i8]* %fmt_str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %10 = bitcast [70 x i8]* %fmt_str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %10, i8 0, i64 70, i1 false)
  store [70 x i8] c"[BPFTRACE_DEBUG_OUTPUT] unable to find the scratch map value for join\00", [70 x i8]* %fmt_str, align 1
  %11 = bitcast [70 x i8]* %fmt_str to i8*
  %trace_printk = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* %11, i32 70)
  br label %failure_callback

lookup_join_merge:                                ; preds = %entry
  %12 = bitcast i8* %lookup_join_map to i64*
  store i64 30005, i64* %12, align 8
  %13 = getelementptr i8, i8* %lookup_join_map, i64 8
  %14 = bitcast i8* %13 to i64*
  store i64 0, i64* %14, align 8
  %15 = bitcast i64* %join_r0 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  %probe_read_kernel1 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %5)
  %16 = load i64, i64* %join_r0, align 8
  %17 = getelementptr i8, i8* %lookup_join_map, i64 16
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %17, i32 1024, i64 %16)
  %18 = add i64 %5, 8
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %18)
  %19 = load i64, i64* %join_r0, align 8
  %20 = getelementptr i8, i8* %lookup_join_map, i64 1040
  %probe_read_kernel_str3 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %20, i32 1024, i64 %19)
  %21 = add i64 %18, 8
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %21)
  %22 = load i64, i64* %join_r0, align 8
  %23 = getelementptr i8, i8* %lookup_join_map, i64 2064
  %probe_read_kernel_str5 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %23, i32 1024, i64 %22)
  %24 = add i64 %21, 8
  %probe_read_kernel6 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %24)
  %25 = load i64, i64* %join_r0, align 8
  %26 = getelementptr i8, i8* %lookup_join_map, i64 3088
  %probe_read_kernel_str7 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %26, i32 1024, i64 %25)
  %27 = add i64 %24, 8
  %probe_read_kernel8 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %27)
  %28 = load i64, i64* %join_r0, align 8
  %29 = getelementptr i8, i8* %lookup_join_map, i64 4112
  %probe_read_kernel_str9 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %29, i32 1024, i64 %28)
  %30 = add i64 %27, 8
  %probe_read_kernel10 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %30)
  %31 = load i64, i64* %join_r0, align 8
  %32 = getelementptr i8, i8* %lookup_join_map, i64 5136
  %probe_read_kernel_str11 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %32, i32 1024, i64 %31)
  %33 = add i64 %30, 8
  %probe_read_kernel12 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %33)
  %34 = load i64, i64* %join_r0, align 8
  %35 = getelementptr i8, i8* %lookup_join_map, i64 6160
  %probe_read_kernel_str13 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %35, i32 1024, i64 %34)
  %36 = add i64 %33, 8
  %probe_read_kernel14 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %36)
  %37 = load i64, i64* %join_r0, align 8
  %38 = getelementptr i8, i8* %lookup_join_map, i64 7184
  %probe_read_kernel_str15 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %38, i32 1024, i64 %37)
  %39 = add i64 %36, 8
  %probe_read_kernel16 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %39)
  %40 = load i64, i64* %join_r0, align 8
  %41 = getelementptr i8, i8* %lookup_join_map, i64 8208
  %probe_read_kernel_str17 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %41, i32 1024, i64 %40)
  %42 = add i64 %39, 8
  %probe_read_kernel18 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %42)
  %43 = load i64, i64* %join_r0, align 8
  %44 = getelementptr i8, i8* %lookup_join_map, i64 9232
  %probe_read_kernel_str19 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %44, i32 1024, i64 %43)
  %45 = add i64 %42, 8
  %probe_read_kernel20 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %45)
  %46 = load i64, i64* %join_r0, align 8
  %47 = getelementptr i8, i8* %lookup_join_map, i64 10256
  %probe_read_kernel_str21 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %47, i32 1024, i64 %46)
  %48 = add i64 %45, 8
  %probe_read_kernel22 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %48)
  %49 = load i64, i64* %join_r0, align 8
  %50 = getelementptr i8, i8* %lookup_join_map, i64 11280
  %probe_read_kernel_str23 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %50, i32 1024, i64 %49)
  %51 = add i64 %48, 8
  %probe_read_kernel24 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %51)
  %52 = load i64, i64* %join_r0, align 8
  %53 = getelementptr i8, i8* %lookup_join_map, i64 12304
  %probe_read_kernel_str25 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %53, i32 1024, i64 %52)
  %54 = add i64 %51, 8
  %probe_read_kernel26 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %54)
  %55 = load i64, i64* %join_r0, align 8
  %56 = getelementptr i8, i8* %lookup_join_map, i64 13328
  %probe_read_kernel_str27 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %56, i32 1024, i64 %55)
  %57 = add i64 %54, 8
  %probe_read_kernel28 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %57)
  %58 = load i64, i64* %join_r0, align 8
  %59 = getelementptr i8, i8* %lookup_join_map, i64 14352
  %probe_read_kernel_str29 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %59, i32 1024, i64 %58)
  %60 = add i64 %57, 8
  %probe_read_kernel30 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %60)
  %61 = load i64, i64* %join_r0, align 8
  %62 = getelementptr i8, i8* %lookup_join_map, i64 15376
  %probe_read_kernel_str31 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %62, i32 1024, i64 %61)
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, i8*, i64, i64)*)(%"struct map_t.0"* @ringbuf, i8* %lookup_join_map, i64 16400, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %lookup_join_merge
  %63 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %63)
  store i32 0, i32* %key, align 4
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %lookup_join_merge
  br label %failure_callback

lookup_success:                                   ; preds = %event_loss_counter
  %64 = bitcast i8* %lookup_elem to i64*
  %65 = atomicrmw add i64* %64, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %66 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %66)
  br label %counter_merge
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!51}
!llvm.module.flags = !{!54}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "join", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 6, lowerBound: 0)
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
!21 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 131200, elements: !23)
!22 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!23 = !{!24}
!24 = !DISubrange(count: 16400, lowerBound: 0)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !28)
!28 = !{!29, !34}
!29 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !30, size: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 27, lowerBound: 0)
!34 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !35, size: 64, offset: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 262144, lowerBound: 0)
!39 = !DIGlobalVariableExpression(var: !40, expr: !DIExpression())
!40 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !41, isLocal: false, isDefinition: true)
!41 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !42)
!42 = !{!43, !11, !16, !48}
!43 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !44, size: 64)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 2, lowerBound: 0)
!48 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !49, size: 64, offset: 192)
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!50 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!51 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !52, globals: !53)
!52 = !{}
!53 = !{!0, !25, !39}
!54 = !{i32 2, !"Debug Info Version", i32 3}
!55 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !51, retainedNodes: !59)
!56 = !DISubroutineType(types: !57)
!57 = !{!50, !58}
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!59 = !{!60}
!60 = !DILocalVariable(name: "ctx", arg: 1, scope: !55, file: !2, type: !58)
