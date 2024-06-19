; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%printf_t = type { i64 }
%printf_t.2 = type { i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@event_loss_counter = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@fmt_string_args = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !55 {
entry:
  %key10 = alloca i32, align 4
  %lookup_fmtstr_key1 = alloca i32, align 4
  %key = alloca i32, align 4
  %lookup_fmtstr_key = alloca i32, align 4
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %1 = lshr i64 %get_pid_tgid, 32
  %2 = icmp ugt i64 %1, 10
  %3 = zext i1 %2 to i64
  %true_cond = icmp ne i64 %3, 0
  br i1 %true_cond, label %if_body, label %else_body

if_body:                                          ; preds = %entry
  %4 = bitcast i32* %lookup_fmtstr_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i32 0, i32* %lookup_fmtstr_key, align 4
  %lookup_fmtstr_map = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @fmt_string_args, i32* %lookup_fmtstr_key)
  %5 = bitcast i32* %lookup_fmtstr_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %lookup_fmtstr_cond = icmp ne i8* %lookup_fmtstr_map, null
  br i1 %lookup_fmtstr_cond, label %lookup_fmtstr_merge, label %lookup_fmtstr_failure

if_end:                                           ; preds = %counter_merge8, %counter_merge
  ret i64 0

else_body:                                        ; preds = %entry
  %6 = bitcast i32* %lookup_fmtstr_key1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  store i32 0, i32* %lookup_fmtstr_key1, align 4
  %lookup_fmtstr_map2 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @fmt_string_args, i32* %lookup_fmtstr_key1)
  %7 = bitcast i32* %lookup_fmtstr_key1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  %lookup_fmtstr_cond5 = icmp ne i8* %lookup_fmtstr_map2, null
  br i1 %lookup_fmtstr_cond5, label %lookup_fmtstr_merge4, label %lookup_fmtstr_failure3

lookup_fmtstr_failure:                            ; preds = %if_body
  ret i64 0

lookup_fmtstr_merge:                              ; preds = %if_body
  call void @llvm.memset.p0i8.i64(i8* align 1 %lookup_fmtstr_map, i8 0, i64 8, i1 false)
  %8 = bitcast i8* %lookup_fmtstr_map to %printf_t*
  %9 = getelementptr %printf_t, %printf_t* %8, i32 0, i32 0
  store i64 0, i64* %9, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t"*, i8*, i64, i64)*)(%"struct map_t"* @ringbuf, i8* %lookup_fmtstr_map, i64 8, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %lookup_fmtstr_merge
  %10 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i32 0, i32* %key, align 4
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t.0"*, i32*)*)(%"struct map_t.0"* @event_loss_counter, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %lookup_fmtstr_merge
  br label %if_end

lookup_success:                                   ; preds = %event_loss_counter
  %11 = bitcast i8* %lookup_elem to i64*
  %12 = atomicrmw add i64* %11, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %13 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  br label %counter_merge

lookup_fmtstr_failure3:                           ; preds = %else_body
  ret i64 0

lookup_fmtstr_merge4:                             ; preds = %else_body
  call void @llvm.memset.p0i8.i64(i8* align 1 %lookup_fmtstr_map2, i8 0, i64 8, i1 false)
  %14 = bitcast i8* %lookup_fmtstr_map2 to %printf_t.2*
  %15 = getelementptr %printf_t.2, %printf_t.2* %14, i32 0, i32 0
  store i64 1, i64* %15, align 8
  %ringbuf_output6 = call i64 inttoptr (i64 130 to i64 (%"struct map_t"*, i8*, i64, i64)*)(%"struct map_t"* @ringbuf, i8* %lookup_fmtstr_map2, i64 8, i64 0)
  %ringbuf_loss9 = icmp slt i64 %ringbuf_output6, 0
  br i1 %ringbuf_loss9, label %event_loss_counter7, label %counter_merge8

event_loss_counter7:                              ; preds = %lookup_fmtstr_merge4
  %16 = bitcast i32* %key10 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  store i32 0, i32* %key10, align 4
  %lookup_elem11 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.0"*, i32*)*)(%"struct map_t.0"* @event_loss_counter, i32* %key10)
  %map_lookup_cond15 = icmp ne i8* %lookup_elem11, null
  br i1 %map_lookup_cond15, label %lookup_success12, label %lookup_failure13

counter_merge8:                                   ; preds = %lookup_merge14, %lookup_fmtstr_merge4
  br label %if_end

lookup_success12:                                 ; preds = %event_loss_counter7
  %17 = bitcast i8* %lookup_elem11 to i64*
  %18 = atomicrmw add i64* %17, i64 1 seq_cst
  br label %lookup_merge14

lookup_failure13:                                 ; preds = %event_loss_counter7
  br label %lookup_merge14

lookup_merge14:                                   ; preds = %lookup_failure13, %lookup_success12
  %19 = bitcast i32* %key10 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  br label %counter_merge8
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
!37 = distinct !DIGlobalVariable(name: "fmt_string_args", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !39)
!39 = !{!40, !25, !30, !45}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 6, lowerBound: 0)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !46, size: 64, offset: 192)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !48, size: 64, elements: !49)
!48 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!49 = !{!50}
!50 = !DISubrange(count: 8, lowerBound: 0)
!51 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !52, globals: !53)
!52 = !{}
!53 = !{!0, !16, !36}
!54 = !{i32 2, !"Debug Info Version", i32 3}
!55 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !51, retainedNodes: !59)
!56 = !DISubroutineType(types: !57)
!57 = !{!35, !58}
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !48, size: 64)
!59 = !{!60}
!60 = !DILocalVariable(name: "ctx", arg: 1, scope: !55, file: !2, type: !58)
