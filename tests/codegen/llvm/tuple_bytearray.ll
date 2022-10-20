; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%usym_t = type { i64, i64, i64 }
%"unsigned int8_usym_int64__tuple_t" = type { i8, [24 x i8], i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !4 {
entry:
  %"@t_key" = alloca i64, align 8
  %usym = alloca %usym_t, align 8
  %tuple = alloca %"unsigned int8_usym_int64__tuple_t", align 8
  %1 = bitcast %"unsigned int8_usym_int64__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast %"unsigned int8_usym_int64__tuple_t"* %tuple to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 40, i1 false)
  %3 = getelementptr %"unsigned int8_usym_int64__tuple_t", %"unsigned int8_usym_int64__tuple_t"* %tuple, i32 0, i32 0
  store i8 1, i8* %3, align 1
  %4 = bitcast i8* %0 to i64*
  %5 = getelementptr i64, i64* %4, i64 16
  %reg_ip = load volatile i64, i64* %5, align 8
  %6 = bitcast %usym_t* %usym to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %7 = lshr i64 %get_pid_tgid, 32
  %8 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 0
  %9 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 1
  %10 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 2
  store i64 %reg_ip, i64* %8, align 8
  store i64 %7, i64* %9, align 8
  store i64 0, i64* %10, align 8
  %11 = getelementptr %"unsigned int8_usym_int64__tuple_t", %"unsigned int8_usym_int64__tuple_t"* %tuple, i32 0, i32 1
  %12 = bitcast [24 x i8]* %11 to i8*
  %13 = bitcast %usym_t* %usym to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %12, i8* align 1 %13, i64 24, i1 false)
  %14 = getelementptr %"unsigned int8_usym_int64__tuple_t", %"unsigned int8_usym_int64__tuple_t"* %tuple, i32 0, i32 2
  store i64 10, i64* %14, align 8
  %15 = bitcast i64* %"@t_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  store i64 0, i64* %"@t_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %"unsigned int8_usym_int64__tuple_t"*, i64)*)(i64 %pseudo, i64* %"@t_key", %"unsigned int8_usym_int64__tuple_t"* %tuple, i64 0)
  %16 = bitcast i64* %"@t_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast %"unsigned int8_usym_int64__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  ret i64 0
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
