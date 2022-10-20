; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%print_tuple_16_t = type <{ i64, i64, [16 x i8] }>
%"int64_string[4]__tuple_t" = type { i64, [4 x i8] }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !4 {
entry:
  %key = alloca i32, align 4
  %print_tuple_16_t = alloca %print_tuple_16_t, align 8
  %str = alloca [4 x i8], align 1
  %tuple = alloca %"int64_string[4]__tuple_t", align 8
  %1 = bitcast %"int64_string[4]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast %"int64_string[4]__tuple_t"* %tuple to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 16, i1 false)
  %3 = getelementptr %"int64_string[4]__tuple_t", %"int64_string[4]__tuple_t"* %tuple, i32 0, i32 0
  store i64 1, i64* %3, align 8
  %4 = bitcast [4 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store [4 x i8] c"abc\00", [4 x i8]* %str, align 1
  %5 = getelementptr %"int64_string[4]__tuple_t", %"int64_string[4]__tuple_t"* %tuple, i32 0, i32 1
  %6 = bitcast [4 x i8]* %5 to i8*
  %7 = bitcast [4 x i8]* %str to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %6, i8* align 1 %7, i64 4, i1 false)
  %8 = bitcast [4 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast %print_tuple_16_t* %print_tuple_16_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %10 = getelementptr %print_tuple_16_t, %print_tuple_16_t* %print_tuple_16_t, i64 0, i32 0
  store i64 30007, i64* %10, align 8
  %11 = getelementptr %print_tuple_16_t, %print_tuple_16_t* %print_tuple_16_t, i64 0, i32 1
  store i64 0, i64* %11, align 8
  %12 = getelementptr %print_tuple_16_t, %print_tuple_16_t* %print_tuple_16_t, i32 0, i32 2
  %13 = bitcast [16 x i8]* %12 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %13, i8 0, i64 16, i1 false)
  %14 = bitcast [16 x i8]* %12 to i8*
  %15 = bitcast %"int64_string[4]__tuple_t"* %tuple to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %14, i8* align 1 %15, i64 16, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (i64, %print_tuple_16_t*, i64, i64)*)(i64 %pseudo, %print_tuple_16_t* %print_tuple_16_t, i64 32, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %entry
  %16 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  store i32 0, i32* %key, align 4
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i32*)*)(i64 %pseudo1, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %entry
  %17 = bitcast %print_tuple_16_t* %print_tuple_16_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  %18 = bitcast %"int64_string[4]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  ret i64 0

lookup_success:                                   ; preds = %event_loss_counter
  %19 = bitcast i8* %lookup_elem to i64*
  %20 = atomicrmw add i64* %19, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %21 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  br label %counter_merge
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) #1

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
!4 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !10)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !8}
!7 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!10 = !{!11, !12}
!11 = !DILocalVariable(name: "var0", scope: !4, file: !1, type: !7)
!12 = !DILocalVariable(name: "var1", arg: 1, scope: !4, file: !1, type: !8)
