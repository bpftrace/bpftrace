; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%helper_error_t = type <{ i64, i64, i32 }>

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !4 {
entry:
  %key15 = alloca i32, align 4
  %helper_error_t9 = alloca %helper_error_t, align 8
  %"@_newval" = alloca i64, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %1 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo, i64* %"@_key")
  %2 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %3 = load i64, i64* %cast, align 8
  store i64 %3, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, i64* %lookup_elem_val, align 8
  %4 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  %5 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %5, align 8
  %6 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %6, align 8
  %7 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 0, i32* %7, align 4
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (i64, %helper_error_t*, i64, i64)*)(i64 %pseudo1, %helper_error_t* %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

lookup_merge:                                     ; preds = %counter_merge, %lookup_success
  %8 = load i64, i64* %lookup_elem_val, align 8
  %9 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %"@_newval" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  %11 = add i64 %8, 1
  store i64 %11, i64* %"@_newval", align 8
  %pseudo8 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo8, i64* %"@_key", i64* %"@_newval", i64 0)
  %12 = trunc i64 %update_elem to i32
  %13 = icmp sge i32 %12, 0
  br i1 %13, label %helper_merge, label %helper_failure

event_loss_counter:                               ; preds = %lookup_failure
  %14 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i32 0, i32* %key, align 4
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %lookup_elem3 = call i8* inttoptr (i64 1 to i8* (i64, i32*)*)(i64 %pseudo2, i32* %key)
  %map_lookup_cond7 = icmp ne i8* %lookup_elem3, null
  br i1 %map_lookup_cond7, label %lookup_success4, label %lookup_failure5

counter_merge:                                    ; preds = %lookup_merge6, %lookup_failure
  %15 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  br label %lookup_merge

lookup_success4:                                  ; preds = %event_loss_counter
  %16 = bitcast i8* %lookup_elem3 to i64*
  %17 = atomicrmw add i64* %16, i64 1 seq_cst
  br label %lookup_merge6

lookup_failure5:                                  ; preds = %event_loss_counter
  br label %lookup_merge6

lookup_merge6:                                    ; preds = %lookup_failure5, %lookup_success4
  %18 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  br label %counter_merge

helper_failure:                                   ; preds = %lookup_merge
  %19 = bitcast %helper_error_t* %helper_error_t9 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  %20 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t9, i64 0, i32 0
  store i64 30006, i64* %20, align 8
  %21 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t9, i64 0, i32 1
  store i64 1, i64* %21, align 8
  %22 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t9, i64 0, i32 2
  store i32 %12, i32* %22, align 4
  %pseudo10 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %ringbuf_output11 = call i64 inttoptr (i64 130 to i64 (i64, %helper_error_t*, i64, i64)*)(i64 %pseudo10, %helper_error_t* %helper_error_t9, i64 20, i64 0)
  %ringbuf_loss14 = icmp slt i64 %ringbuf_output11, 0
  br i1 %ringbuf_loss14, label %event_loss_counter12, label %counter_merge13

helper_merge:                                     ; preds = %counter_merge13, %lookup_merge
  %23 = bitcast i64* %"@_newval" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  %24 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  ret i64 0

event_loss_counter12:                             ; preds = %helper_failure
  %25 = bitcast i32* %key15 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %25)
  store i32 0, i32* %key15, align 4
  %pseudo16 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %lookup_elem17 = call i8* inttoptr (i64 1 to i8* (i64, i32*)*)(i64 %pseudo16, i32* %key15)
  %map_lookup_cond21 = icmp ne i8* %lookup_elem17, null
  br i1 %map_lookup_cond21, label %lookup_success18, label %lookup_failure19

counter_merge13:                                  ; preds = %lookup_merge20, %helper_failure
  %26 = bitcast %helper_error_t* %helper_error_t9 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %26)
  br label %helper_merge

lookup_success18:                                 ; preds = %event_loss_counter12
  %27 = bitcast i8* %lookup_elem17 to i64*
  %28 = atomicrmw add i64* %27, i64 1 seq_cst
  br label %lookup_merge20

lookup_failure19:                                 ; preds = %event_loss_counter12
  br label %lookup_merge20

lookup_merge20:                                   ; preds = %lookup_failure19, %lookup_success18
  %29 = bitcast i32* %key15 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %29)
  br label %counter_merge13
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3}

!0 = distinct !DICompileUnit(language: DW_LANG_C, file: !1, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !2)
!1 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!2 = !{}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !10)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !8}
!7 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!10 = !{!11, !12}
!11 = !DILocalVariable(name: "var0", scope: !4, file: !1, type: !7)
!12 = !DILocalVariable(name: "var1", arg: 1, scope: !4, file: !1, type: !8)
