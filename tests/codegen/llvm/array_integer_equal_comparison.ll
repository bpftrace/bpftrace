; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr }
%exit_t = type <{ i64, i8 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !35 {
entry:
  %exit = alloca %exit_t, align 8
  %n = alloca i32, align 4
  %i = alloca i32, align 4
  %arraycmp.result = alloca i1, align 1
  %v2 = alloca i32, align 4
  %v1 = alloca i32, align 4
  %"$b" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$b")
  store i64 0, ptr %"$b", align 8
  %"$a" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$a")
  store i64 0, ptr %"$a", align 8
  %1 = call ptr @llvm.preserve.static.offset(ptr %0)
  %2 = getelementptr i8, ptr %1, i64 112
  %arg0 = load volatile i64, ptr %2, align 8
  %3 = inttoptr i64 %arg0 to ptr
  %4 = call ptr @llvm.preserve.static.offset(ptr %3)
  %5 = getelementptr i8, ptr %4, i64 0
  %6 = ptrtoint ptr %5 to i64
  store i64 %6, ptr %"$a", align 8
  %7 = call ptr @llvm.preserve.static.offset(ptr %0)
  %8 = getelementptr i8, ptr %7, i64 112
  %arg01 = load volatile i64, ptr %8, align 8
  %9 = inttoptr i64 %arg01 to ptr
  %10 = call ptr @llvm.preserve.static.offset(ptr %9)
  %11 = getelementptr i8, ptr %10, i64 0
  %12 = ptrtoint ptr %11 to i64
  store i64 %12, ptr %"$b", align 8
  %13 = load i64, ptr %"$a", align 8
  %14 = load i64, ptr %"$b", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %v1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %v2)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %arraycmp.result)
  store i1 true, ptr %arraycmp.result, align 1
  %15 = inttoptr i64 %13 to ptr
  %16 = inttoptr i64 %14 to ptr
  call void @llvm.lifetime.start.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %n)
  store i32 0, ptr %i, align 4
  store i32 4, ptr %n, align 4
  br label %while_cond

if_body:                                          ; preds = %arraycmp.done
  call void @llvm.lifetime.start.p0(i64 -1, ptr %exit)
  %17 = getelementptr %exit_t, ptr %exit, i64 0, i32 0
  store i64 30000, ptr %17, align 8
  %18 = getelementptr %exit_t, ptr %exit, i64 0, i32 1
  store i8 0, ptr %18, align 1
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %exit, i64 9, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

if_end:                                           ; preds = %deadcode, %arraycmp.done
  ret i64 0

while_cond:                                       ; preds = %arraycmp.loop, %entry
  %19 = load i32, ptr %n, align 4
  %20 = load i32, ptr %i, align 4
  %size_check = icmp slt i32 %20, %19
  br i1 %size_check, label %while_body, label %arraycmp.done, !llvm.loop !41

while_body:                                       ; preds = %while_cond
  %21 = load i32, ptr %i, align 4
  %22 = getelementptr [4 x i32], ptr %15, i32 0, i32 %21
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %v1, i32 4, ptr %22)
  %23 = load i32, ptr %v1, align 4
  %24 = load i32, ptr %i, align 4
  %25 = getelementptr [4 x i32], ptr %16, i32 0, i32 %24
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to ptr)(ptr %v2, i32 4, ptr %25)
  %26 = load i32, ptr %v2, align 4
  %arraycmp.cmp = icmp ne i32 %23, %26
  br i1 %arraycmp.cmp, label %arraycmp.false, label %arraycmp.loop

arraycmp.false:                                   ; preds = %while_body
  store i1 false, ptr %arraycmp.result, align 1
  br label %arraycmp.done

arraycmp.done:                                    ; preds = %arraycmp.false, %while_cond
  %27 = load i1, ptr %arraycmp.result, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %arraycmp.result)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %v1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %v2)
  %28 = zext i1 %27 to i64
  %true_cond = icmp ne i64 %28, 0
  br i1 %true_cond, label %if_body, label %if_end

arraycmp.loop:                                    ; preds = %while_body
  %29 = load i32, ptr %i, align 4
  %30 = add i32 %29, 1
  store i32 %30, ptr %i, align 4
  br label %while_cond

event_loss_counter:                               ; preds = %if_body
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #3
  %31 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %31
  %32 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %33 = load i64, ptr %32, align 8
  %34 = add i64 %33, 1
  store i64 %34, ptr %32, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %if_body
  call void @llvm.lifetime.end.p0(i64 -1, ptr %exit)
  ret i64 0

deadcode:                                         ; No predecessors!
  br label %if_end
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
attributes #3 = { memory(none) }

!llvm.dbg.cu = !{!31}
!llvm.module.flags = !{!33, !34}

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
!23 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !25, size: 64, elements: !27)
!25 = !DICompositeType(tag: DW_TAG_array_type, baseType: !26, size: 64, elements: !27)
!26 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!27 = !{!28}
!28 = !DISubrange(count: 1, lowerBound: 0)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!31 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !32)
!32 = !{!0, !7, !22, !29}
!33 = !{i32 2, !"Debug Info Version", i32 3}
!34 = !{i32 7, !"uwtable", i32 0}
!35 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !36, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !31, retainedNodes: !39)
!36 = !DISubroutineType(types: !37)
!37 = !{!26, !38}
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!39 = !{!40}
!40 = !DILocalVariable(name: "ctx", arg: 1, scope: !35, file: !2, type: !38)
!41 = distinct !{!41, !42}
!42 = !{!"llvm.loop.unroll.disable"}
