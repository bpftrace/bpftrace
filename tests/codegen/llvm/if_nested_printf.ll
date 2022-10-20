; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%printf_t = type { i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !4 {
entry:
  %key = alloca i32, align 4
  %printf_args = alloca %printf_t, align 8
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %1 = lshr i64 %get_pid_tgid, 32
  %2 = icmp ugt i64 %1, 10000
  %3 = zext i1 %2 to i64
  %true_cond = icmp ne i64 %3, 0
  br i1 %true_cond, label %if_body, label %if_end

if_body:                                          ; preds = %entry
  %get_pid_tgid3 = call i64 inttoptr (i64 14 to i64 ()*)()
  %4 = lshr i64 %get_pid_tgid3, 32
  %5 = urem i64 %4, 2
  %6 = icmp eq i64 %5, 0
  %7 = zext i1 %6 to i64
  %true_cond4 = icmp ne i64 %7, 0
  br i1 %true_cond4, label %if_body1, label %if_end2

if_end:                                           ; preds = %if_end2, %entry
  ret i64 0

if_body1:                                         ; preds = %if_body
  %8 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %9 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %9, i8 0, i64 8, i1 false)
  %10 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %10, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (i64, %printf_t*, i64, i64)*)(i64 %pseudo, %printf_t* %printf_args, i64 8, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

if_end2:                                          ; preds = %counter_merge, %if_body
  br label %if_end

event_loss_counter:                               ; preds = %if_body1
  %11 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i32 0, i32* %key, align 4
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i32*)*)(i64 %pseudo5, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %if_body1
  %12 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  br label %if_end2

lookup_success:                                   ; preds = %event_loss_counter
  %13 = bitcast i8* %lookup_elem to i64*
  %14 = atomicrmw add i64* %13, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %15 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
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
