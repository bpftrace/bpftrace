; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%printf_t.2 = type { i64, i64 }
%printf_t.1 = type { i64, i64 }
%printf_t.0 = type { i64, i64 }
%printf_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN(i8* %0) section "s_BEGIN_1" !dbg !4 {
entry:
  %key34 = alloca i32, align 4
  %printf_args28 = alloca %printf_t.2, align 8
  %key21 = alloca i32, align 4
  %printf_args15 = alloca %printf_t.1, align 8
  %key8 = alloca i32, align 4
  %printf_args2 = alloca %printf_t.0, align 8
  %key = alloca i32, align 4
  %printf_args = alloca %printf_t, align 8
  %"$x" = alloca i64, align 8
  %1 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$x", align 8
  store i64 10, i64* %"$x", align 8
  %2 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %3, i8 0, i64 16, i1 false)
  %4 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %4, align 8
  %5 = load i64, i64* %"$x", align 8
  %6 = add i64 %5, 1
  store i64 %6, i64* %"$x", align 8
  %7 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  store i64 %5, i64* %7, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (i64, %printf_t*, i64, i64)*)(i64 %pseudo, %printf_t* %printf_args, i64 16, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %entry
  %8 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  store i32 0, i32* %key, align 4
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i32*)*)(i64 %pseudo1, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %entry
  %9 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast %printf_t.0* %printf_args2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  %11 = bitcast %printf_t.0* %printf_args2 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %11, i8 0, i64 16, i1 false)
  %12 = getelementptr %printf_t.0, %printf_t.0* %printf_args2, i32 0, i32 0
  store i64 1, i64* %12, align 8
  %13 = load i64, i64* %"$x", align 8
  %14 = add i64 %13, 1
  store i64 %14, i64* %"$x", align 8
  %15 = getelementptr %printf_t.0, %printf_t.0* %printf_args2, i32 0, i32 1
  store i64 %14, i64* %15, align 8
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %ringbuf_output4 = call i64 inttoptr (i64 130 to i64 (i64, %printf_t.0*, i64, i64)*)(i64 %pseudo3, %printf_t.0* %printf_args2, i64 16, i64 0)
  %ringbuf_loss7 = icmp slt i64 %ringbuf_output4, 0
  br i1 %ringbuf_loss7, label %event_loss_counter5, label %counter_merge6

lookup_success:                                   ; preds = %event_loss_counter
  %16 = bitcast i8* %lookup_elem to i64*
  %17 = atomicrmw add i64* %16, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %18 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  br label %counter_merge

event_loss_counter5:                              ; preds = %counter_merge
  %19 = bitcast i32* %key8 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  store i32 0, i32* %key8, align 4
  %pseudo9 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem10 = call i8* inttoptr (i64 1 to i8* (i64, i32*)*)(i64 %pseudo9, i32* %key8)
  %map_lookup_cond14 = icmp ne i8* %lookup_elem10, null
  br i1 %map_lookup_cond14, label %lookup_success11, label %lookup_failure12

counter_merge6:                                   ; preds = %lookup_merge13, %counter_merge
  %20 = bitcast %printf_t.0* %printf_args2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = bitcast %printf_t.1* %printf_args15 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  %22 = bitcast %printf_t.1* %printf_args15 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %22, i8 0, i64 16, i1 false)
  %23 = getelementptr %printf_t.1, %printf_t.1* %printf_args15, i32 0, i32 0
  store i64 2, i64* %23, align 8
  %24 = load i64, i64* %"$x", align 8
  %25 = sub i64 %24, 1
  store i64 %25, i64* %"$x", align 8
  %26 = getelementptr %printf_t.1, %printf_t.1* %printf_args15, i32 0, i32 1
  store i64 %24, i64* %26, align 8
  %pseudo16 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %ringbuf_output17 = call i64 inttoptr (i64 130 to i64 (i64, %printf_t.1*, i64, i64)*)(i64 %pseudo16, %printf_t.1* %printf_args15, i64 16, i64 0)
  %ringbuf_loss20 = icmp slt i64 %ringbuf_output17, 0
  br i1 %ringbuf_loss20, label %event_loss_counter18, label %counter_merge19

lookup_success11:                                 ; preds = %event_loss_counter5
  %27 = bitcast i8* %lookup_elem10 to i64*
  %28 = atomicrmw add i64* %27, i64 1 seq_cst
  br label %lookup_merge13

lookup_failure12:                                 ; preds = %event_loss_counter5
  br label %lookup_merge13

lookup_merge13:                                   ; preds = %lookup_failure12, %lookup_success11
  %29 = bitcast i32* %key8 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %29)
  br label %counter_merge6

event_loss_counter18:                             ; preds = %counter_merge6
  %30 = bitcast i32* %key21 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %30)
  store i32 0, i32* %key21, align 4
  %pseudo22 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem23 = call i8* inttoptr (i64 1 to i8* (i64, i32*)*)(i64 %pseudo22, i32* %key21)
  %map_lookup_cond27 = icmp ne i8* %lookup_elem23, null
  br i1 %map_lookup_cond27, label %lookup_success24, label %lookup_failure25

counter_merge19:                                  ; preds = %lookup_merge26, %counter_merge6
  %31 = bitcast %printf_t.1* %printf_args15 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = bitcast %printf_t.2* %printf_args28 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %32)
  %33 = bitcast %printf_t.2* %printf_args28 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %33, i8 0, i64 16, i1 false)
  %34 = getelementptr %printf_t.2, %printf_t.2* %printf_args28, i32 0, i32 0
  store i64 3, i64* %34, align 8
  %35 = load i64, i64* %"$x", align 8
  %36 = sub i64 %35, 1
  store i64 %36, i64* %"$x", align 8
  %37 = getelementptr %printf_t.2, %printf_t.2* %printf_args28, i32 0, i32 1
  store i64 %36, i64* %37, align 8
  %pseudo29 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %ringbuf_output30 = call i64 inttoptr (i64 130 to i64 (i64, %printf_t.2*, i64, i64)*)(i64 %pseudo29, %printf_t.2* %printf_args28, i64 16, i64 0)
  %ringbuf_loss33 = icmp slt i64 %ringbuf_output30, 0
  br i1 %ringbuf_loss33, label %event_loss_counter31, label %counter_merge32

lookup_success24:                                 ; preds = %event_loss_counter18
  %38 = bitcast i8* %lookup_elem23 to i64*
  %39 = atomicrmw add i64* %38, i64 1 seq_cst
  br label %lookup_merge26

lookup_failure25:                                 ; preds = %event_loss_counter18
  br label %lookup_merge26

lookup_merge26:                                   ; preds = %lookup_failure25, %lookup_success24
  %40 = bitcast i32* %key21 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %40)
  br label %counter_merge19

event_loss_counter31:                             ; preds = %counter_merge19
  %41 = bitcast i32* %key34 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %41)
  store i32 0, i32* %key34, align 4
  %pseudo35 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem36 = call i8* inttoptr (i64 1 to i8* (i64, i32*)*)(i64 %pseudo35, i32* %key34)
  %map_lookup_cond40 = icmp ne i8* %lookup_elem36, null
  br i1 %map_lookup_cond40, label %lookup_success37, label %lookup_failure38

counter_merge32:                                  ; preds = %lookup_merge39, %counter_merge19
  %42 = bitcast %printf_t.2* %printf_args28 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %42)
  ret i64 0

lookup_success37:                                 ; preds = %event_loss_counter31
  %43 = bitcast i8* %lookup_elem36 to i64*
  %44 = atomicrmw add i64* %43, i64 1 seq_cst
  br label %lookup_merge39

lookup_failure38:                                 ; preds = %event_loss_counter31
  br label %lookup_merge39

lookup_merge39:                                   ; preds = %lookup_failure38, %lookup_success37
  %45 = bitcast i32* %key34 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %45)
  br label %counter_merge32
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3}

!0 = distinct !DICompileUnit(language: DW_LANG_C, file: !1, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !2)
!1 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!2 = !{}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "BEGIN", linkageName: "BEGIN", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !10)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !8}
!7 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!10 = !{!11, !12}
!11 = !DILocalVariable(name: "var0", scope: !4, file: !1, type: !7)
!12 = !DILocalVariable(name: "var1", arg: 1, scope: !4, file: !1, type: !8)
