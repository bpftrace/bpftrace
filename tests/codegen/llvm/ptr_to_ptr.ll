; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%printf_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !4 {
entry:
  %key = alloca i32, align 4
  %deref1 = alloca i32, align 4
  %deref = alloca i64, align 8
  %printf_args = alloca %printf_t, align 8
  %"$pp" = alloca i64, align 8
  %1 = bitcast i64* %"$pp" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$pp", align 8
  store i64 0, i64* %"$pp", align 8
  %2 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %3, i8 0, i64 16, i1 false)
  %4 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %4, align 8
  %5 = load i64, i64* %"$pp", align 8
  %6 = bitcast i64* %deref to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %deref, i32 8, i64 %5)
  %7 = load i64, i64* %deref, align 8
  %8 = bitcast i64* %deref to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast i32* %deref1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i64)*)(i32* %deref1, i32 4, i64 %7)
  %10 = load i32, i32* %deref1, align 4
  %11 = bitcast i32* %deref1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  %13 = sext i32 %10 to i64
  store i64 %13, i64* %12, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (i64, %printf_t*, i64, i64)*)(i64 %pseudo, %printf_t* %printf_args, i64 16, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %entry
  %14 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i32 0, i32* %key, align 4
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i32*)*)(i64 %pseudo3, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %entry
  %15 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  ret i64 0

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
!4 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !10)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !8}
!7 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!10 = !{!11, !12}
!11 = !DILocalVariable(name: "var0", scope: !4, file: !1, type: !7)
!12 = !DILocalVariable(name: "var1", arg: 1, scope: !4, file: !1, type: !8)
