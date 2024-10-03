; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%printf_t = type { i64, i64 }
%printf_t.1 = type { i64, i64 }
%printf_t.2 = type { i64, i64 }
%printf_t.3 = type { i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@event_loss_counter = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !36
@fmt_str_buf = dso_local externally_initialized global [1 x [1 x [16 x i8]]] zeroinitializer, section ".data.fmt_str_buf", !dbg !38

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !49 {
entry:
  %key34 = alloca i32, align 4
  %key21 = alloca i32, align 4
  %key8 = alloca i32, align 4
  %key = alloca i32, align 4
  %"$x" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$x")
  store i64 0, ptr %"$x", align 8
  store i64 10, ptr %"$x", align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpuid.min.cmp = icmp ule i64 %get_cpu_id, %1
  %cpuid.min.select = select i1 %cpuid.min.cmp, i64 %get_cpu_id, i64 %1
  %2 = getelementptr [1 x [1 x [16 x i8]]], ptr @fmt_str_buf, i64 0, i64 %cpuid.min.select, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %2, i8 0, i64 16, i1 false)
  %3 = getelementptr %printf_t, ptr %2, i32 0, i32 0
  store i64 0, ptr %3, align 8
  %4 = load i64, ptr %"$x", align 8
  %5 = add i64 %4, 1
  store i64 %5, ptr %"$x", align 8
  %6 = getelementptr %printf_t, ptr %2, i32 0, i32 1
  store i64 %4, ptr %6, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %2, i64 16, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %entry
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)()
  %7 = load i64, ptr @max_cpu_id, align 8
  %cpuid.min.cmp2 = icmp ule i64 %get_cpu_id1, %7
  %cpuid.min.select3 = select i1 %cpuid.min.cmp2, i64 %get_cpu_id1, i64 %7
  %8 = getelementptr [1 x [1 x [16 x i8]]], ptr @fmt_str_buf, i64 0, i64 %cpuid.min.select3, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %8, i8 0, i64 16, i1 false)
  %9 = getelementptr %printf_t.1, ptr %8, i32 0, i32 0
  store i64 1, ptr %9, align 8
  %10 = load i64, ptr %"$x", align 8
  %11 = add i64 %10, 1
  store i64 %11, ptr %"$x", align 8
  %12 = getelementptr %printf_t.1, ptr %8, i32 0, i32 1
  store i64 %11, ptr %12, align 8
  %ringbuf_output4 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %8, i64 16, i64 0)
  %ringbuf_loss7 = icmp slt i64 %ringbuf_output4, 0
  br i1 %ringbuf_loss7, label %event_loss_counter5, label %counter_merge6

lookup_success:                                   ; preds = %event_loss_counter
  %13 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

event_loss_counter5:                              ; preds = %counter_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key8)
  store i32 0, ptr %key8, align 4
  %lookup_elem9 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key8)
  %map_lookup_cond13 = icmp ne ptr %lookup_elem9, null
  br i1 %map_lookup_cond13, label %lookup_success10, label %lookup_failure11

counter_merge6:                                   ; preds = %lookup_merge12, %counter_merge
  %get_cpu_id14 = call i64 inttoptr (i64 8 to ptr)()
  %14 = load i64, ptr @max_cpu_id, align 8
  %cpuid.min.cmp15 = icmp ule i64 %get_cpu_id14, %14
  %cpuid.min.select16 = select i1 %cpuid.min.cmp15, i64 %get_cpu_id14, i64 %14
  %15 = getelementptr [1 x [1 x [16 x i8]]], ptr @fmt_str_buf, i64 0, i64 %cpuid.min.select16, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %15, i8 0, i64 16, i1 false)
  %16 = getelementptr %printf_t.2, ptr %15, i32 0, i32 0
  store i64 2, ptr %16, align 8
  %17 = load i64, ptr %"$x", align 8
  %18 = sub i64 %17, 1
  store i64 %18, ptr %"$x", align 8
  %19 = getelementptr %printf_t.2, ptr %15, i32 0, i32 1
  store i64 %17, ptr %19, align 8
  %ringbuf_output17 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %15, i64 16, i64 0)
  %ringbuf_loss20 = icmp slt i64 %ringbuf_output17, 0
  br i1 %ringbuf_loss20, label %event_loss_counter18, label %counter_merge19

lookup_success10:                                 ; preds = %event_loss_counter5
  %20 = atomicrmw add ptr %lookup_elem9, i64 1 seq_cst, align 8
  br label %lookup_merge12

lookup_failure11:                                 ; preds = %event_loss_counter5
  br label %lookup_merge12

lookup_merge12:                                   ; preds = %lookup_failure11, %lookup_success10
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key8)
  br label %counter_merge6

event_loss_counter18:                             ; preds = %counter_merge6
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key21)
  store i32 0, ptr %key21, align 4
  %lookup_elem22 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key21)
  %map_lookup_cond26 = icmp ne ptr %lookup_elem22, null
  br i1 %map_lookup_cond26, label %lookup_success23, label %lookup_failure24

counter_merge19:                                  ; preds = %lookup_merge25, %counter_merge6
  %get_cpu_id27 = call i64 inttoptr (i64 8 to ptr)()
  %21 = load i64, ptr @max_cpu_id, align 8
  %cpuid.min.cmp28 = icmp ule i64 %get_cpu_id27, %21
  %cpuid.min.select29 = select i1 %cpuid.min.cmp28, i64 %get_cpu_id27, i64 %21
  %22 = getelementptr [1 x [1 x [16 x i8]]], ptr @fmt_str_buf, i64 0, i64 %cpuid.min.select29, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %22, i8 0, i64 16, i1 false)
  %23 = getelementptr %printf_t.3, ptr %22, i32 0, i32 0
  store i64 3, ptr %23, align 8
  %24 = load i64, ptr %"$x", align 8
  %25 = sub i64 %24, 1
  store i64 %25, ptr %"$x", align 8
  %26 = getelementptr %printf_t.3, ptr %22, i32 0, i32 1
  store i64 %25, ptr %26, align 8
  %ringbuf_output30 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %22, i64 16, i64 0)
  %ringbuf_loss33 = icmp slt i64 %ringbuf_output30, 0
  br i1 %ringbuf_loss33, label %event_loss_counter31, label %counter_merge32

lookup_success23:                                 ; preds = %event_loss_counter18
  %27 = atomicrmw add ptr %lookup_elem22, i64 1 seq_cst, align 8
  br label %lookup_merge25

lookup_failure24:                                 ; preds = %event_loss_counter18
  br label %lookup_merge25

lookup_merge25:                                   ; preds = %lookup_failure24, %lookup_success23
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key21)
  br label %counter_merge19

event_loss_counter31:                             ; preds = %counter_merge19
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key34)
  store i32 0, ptr %key34, align 4
  %lookup_elem35 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key34)
  %map_lookup_cond39 = icmp ne ptr %lookup_elem35, null
  br i1 %map_lookup_cond39, label %lookup_success36, label %lookup_failure37

counter_merge32:                                  ; preds = %lookup_merge38, %counter_merge19
  ret i64 0

lookup_success36:                                 ; preds = %event_loss_counter31
  %28 = atomicrmw add ptr %lookup_elem35, i64 1 seq_cst, align 8
  br label %lookup_merge38

lookup_failure37:                                 ; preds = %event_loss_counter31
  br label %lookup_merge38

lookup_merge38:                                   ; preds = %lookup_failure37, %lookup_success36
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key34)
  br label %counter_merge32
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }

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
!39 = distinct !DIGlobalVariable(name: "fmt_str_buf", linkageName: "global", scope: !2, file: !2, type: !40, isLocal: false, isDefinition: true)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !41, size: 128, elements: !28)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !42, size: 128, elements: !28)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !43, size: 128, elements: !44)
!43 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!44 = !{!45}
!45 = !DISubrange(count: 16, lowerBound: 0)
!46 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !47)
!47 = !{!0, !16, !36, !38}
!48 = !{i32 2, !"Debug Info Version", i32 3}
!49 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !50, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !46, retainedNodes: !53)
!50 = !DISubroutineType(types: !51)
!51 = !{!35, !52}
!52 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!53 = !{!54}
!54 = !DILocalVariable(name: "ctx", arg: 1, scope: !49, file: !2, type: !52)
