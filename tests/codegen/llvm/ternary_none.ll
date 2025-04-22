; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_t" = type { ptr, ptr }
%exit_t = type <{ i64, i8 }>
%printf_t = type { i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@event_loss_counter = dso_local externally_initialized global i64 0, section ".data.event_loss_counter", !dbg !22

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !29 {
entry:
  %exit = alloca %exit_t, align 8
  %printf_args = alloca %printf_t, align 8
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)()
  %1 = lshr i64 %get_pid_tgid, 32
  %pid = trunc i64 %1 to i32
  %2 = zext i32 %pid to i64
  %3 = icmp ult i64 %2, 10000
  %true_cond = icmp ne i1 %3, false
  br i1 %true_cond, label %left, label %right

left:                                             ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %printf_args)
  call void @llvm.memset.p0.i64(ptr align 1 %printf_args, i8 0, i64 8, i1 false)
  %4 = getelementptr %printf_t, ptr %printf_args, i32 0, i32 0
  store i64 0, ptr %4, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %printf_args, i64 8, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

right:                                            ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %exit)
  %5 = getelementptr %exit_t, ptr %exit, i64 0, i32 0
  store i64 30000, ptr %5, align 8
  %6 = getelementptr %exit_t, ptr %exit, i64 0, i32 1
  store i8 0, ptr %6, align 1
  %ringbuf_output1 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %exit, i64 9, i64 0)
  %ringbuf_loss4 = icmp slt i64 %ringbuf_output1, 0
  br i1 %ringbuf_loss4, label %event_loss_counter2, label %counter_merge3

done:                                             ; preds = %deadcode, %counter_merge
  ret i64 0

event_loss_counter:                               ; preds = %left
  %7 = atomicrmw add ptr @event_loss_counter, i64 1 seq_cst, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %left
  call void @llvm.lifetime.end.p0(i64 -1, ptr %printf_args)
  br label %done

event_loss_counter2:                              ; preds = %right
  %8 = atomicrmw add ptr @event_loss_counter, i64 1 seq_cst, align 8
  br label %counter_merge3

counter_merge3:                                   ; preds = %event_loss_counter2, %right
  call void @llvm.lifetime.end.p0(i64 -1, ptr %exit)
  ret i64 0

deadcode:                                         ; No predecessors!
  br label %done
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

!llvm.dbg.cu = !{!25}
!llvm.module.flags = !{!27, !28}

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
!24 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!25 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !26)
!26 = !{!0, !7, !22}
!27 = !{i32 2, !"Debug Info Version", i32 3}
!28 = !{i32 7, !"uwtable", i32 0}
!29 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !30, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !25, retainedNodes: !33)
!30 = !DISubroutineType(types: !31)
!31 = !{!24, !32}
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!33 = !{!34}
!34 = !DILocalVariable(name: "ctx", arg: 1, scope: !29, file: !2, type: !32)
