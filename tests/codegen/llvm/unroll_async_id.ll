; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%"struct map_t.2" = type { i8*, i8*, i8*, i8* }
%printf_t = type { i64 }
%printf_t.3 = type { i64 }
%printf_t.4 = type { i64 }
%printf_t.5 = type { i64 }
%printf_t.6 = type { i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_i = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34
@fmt_string_args = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !47

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(i8* %0) section "s_BEGIN_1" !dbg !66 {
entry:
  %key55 = alloca i32, align 4
  %lookup_fmtstr_key46 = alloca i32, align 4
  %key40 = alloca i32, align 4
  %lookup_fmtstr_key31 = alloca i32, align 4
  %key25 = alloca i32, align 4
  %lookup_fmtstr_key16 = alloca i32, align 4
  %key10 = alloca i32, align 4
  %lookup_fmtstr_key1 = alloca i32, align 4
  %key = alloca i32, align 4
  %lookup_fmtstr_key = alloca i32, align 4
  %"@i_val" = alloca i64, align 8
  %"@i_key" = alloca i64, align 8
  %1 = bitcast i64* %"@i_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@i_key", align 8
  %2 = bitcast i64* %"@i_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"@i_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_i, i64* %"@i_key", i64* %"@i_val", i64 0)
  %3 = bitcast i64* %"@i_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@i_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast i32* %lookup_fmtstr_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i32 0, i32* %lookup_fmtstr_key, align 4
  %lookup_fmtstr_map = call i8* inttoptr (i64 1 to i8* (%"struct map_t.2"*, i32*)*)(%"struct map_t.2"* @fmt_string_args, i32* %lookup_fmtstr_key)
  %6 = bitcast i32* %lookup_fmtstr_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %lookup_fmtstr_cond = icmp ne i8* %lookup_fmtstr_map, null
  br i1 %lookup_fmtstr_cond, label %lookup_fmtstr_merge, label %lookup_fmtstr_failure

lookup_fmtstr_failure:                            ; preds = %entry
  ret i64 0

lookup_fmtstr_merge:                              ; preds = %entry
  call void @llvm.memset.p0i8.i64(i8* align 1 %lookup_fmtstr_map, i8 0, i64 8, i1 false)
  %7 = bitcast i8* %lookup_fmtstr_map to %printf_t*
  %8 = getelementptr %printf_t, %printf_t* %7, i32 0, i32 0
  store i64 0, i64* %8, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, i8*, i64, i64)*)(%"struct map_t.0"* @ringbuf, i8* %lookup_fmtstr_map, i64 8, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %lookup_fmtstr_merge
  %9 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i32 0, i32* %key, align 4
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %lookup_fmtstr_merge
  %10 = bitcast i32* %lookup_fmtstr_key1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i32 0, i32* %lookup_fmtstr_key1, align 4
  %lookup_fmtstr_map2 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.2"*, i32*)*)(%"struct map_t.2"* @fmt_string_args, i32* %lookup_fmtstr_key1)
  %11 = bitcast i32* %lookup_fmtstr_key1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %lookup_fmtstr_cond5 = icmp ne i8* %lookup_fmtstr_map2, null
  br i1 %lookup_fmtstr_cond5, label %lookup_fmtstr_merge4, label %lookup_fmtstr_failure3

lookup_success:                                   ; preds = %event_loss_counter
  %12 = bitcast i8* %lookup_elem to i64*
  %13 = atomicrmw add i64* %12, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %14 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  br label %counter_merge

lookup_fmtstr_failure3:                           ; preds = %counter_merge
  ret i64 0

lookup_fmtstr_merge4:                             ; preds = %counter_merge
  call void @llvm.memset.p0i8.i64(i8* align 1 %lookup_fmtstr_map2, i8 0, i64 8, i1 false)
  %15 = bitcast i8* %lookup_fmtstr_map2 to %printf_t.3*
  %16 = getelementptr %printf_t.3, %printf_t.3* %15, i32 0, i32 0
  store i64 0, i64* %16, align 8
  %ringbuf_output6 = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, i8*, i64, i64)*)(%"struct map_t.0"* @ringbuf, i8* %lookup_fmtstr_map2, i64 8, i64 0)
  %ringbuf_loss9 = icmp slt i64 %ringbuf_output6, 0
  br i1 %ringbuf_loss9, label %event_loss_counter7, label %counter_merge8

event_loss_counter7:                              ; preds = %lookup_fmtstr_merge4
  %17 = bitcast i32* %key10 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  store i32 0, i32* %key10, align 4
  %lookup_elem11 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key10)
  %map_lookup_cond15 = icmp ne i8* %lookup_elem11, null
  br i1 %map_lookup_cond15, label %lookup_success12, label %lookup_failure13

counter_merge8:                                   ; preds = %lookup_merge14, %lookup_fmtstr_merge4
  %18 = bitcast i32* %lookup_fmtstr_key16 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i32 0, i32* %lookup_fmtstr_key16, align 4
  %lookup_fmtstr_map17 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.2"*, i32*)*)(%"struct map_t.2"* @fmt_string_args, i32* %lookup_fmtstr_key16)
  %19 = bitcast i32* %lookup_fmtstr_key16 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %lookup_fmtstr_cond20 = icmp ne i8* %lookup_fmtstr_map17, null
  br i1 %lookup_fmtstr_cond20, label %lookup_fmtstr_merge19, label %lookup_fmtstr_failure18

lookup_success12:                                 ; preds = %event_loss_counter7
  %20 = bitcast i8* %lookup_elem11 to i64*
  %21 = atomicrmw add i64* %20, i64 1 seq_cst
  br label %lookup_merge14

lookup_failure13:                                 ; preds = %event_loss_counter7
  br label %lookup_merge14

lookup_merge14:                                   ; preds = %lookup_failure13, %lookup_success12
  %22 = bitcast i32* %key10 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  br label %counter_merge8

lookup_fmtstr_failure18:                          ; preds = %counter_merge8
  ret i64 0

lookup_fmtstr_merge19:                            ; preds = %counter_merge8
  call void @llvm.memset.p0i8.i64(i8* align 1 %lookup_fmtstr_map17, i8 0, i64 8, i1 false)
  %23 = bitcast i8* %lookup_fmtstr_map17 to %printf_t.4*
  %24 = getelementptr %printf_t.4, %printf_t.4* %23, i32 0, i32 0
  store i64 0, i64* %24, align 8
  %ringbuf_output21 = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, i8*, i64, i64)*)(%"struct map_t.0"* @ringbuf, i8* %lookup_fmtstr_map17, i64 8, i64 0)
  %ringbuf_loss24 = icmp slt i64 %ringbuf_output21, 0
  br i1 %ringbuf_loss24, label %event_loss_counter22, label %counter_merge23

event_loss_counter22:                             ; preds = %lookup_fmtstr_merge19
  %25 = bitcast i32* %key25 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %25)
  store i32 0, i32* %key25, align 4
  %lookup_elem26 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key25)
  %map_lookup_cond30 = icmp ne i8* %lookup_elem26, null
  br i1 %map_lookup_cond30, label %lookup_success27, label %lookup_failure28

counter_merge23:                                  ; preds = %lookup_merge29, %lookup_fmtstr_merge19
  %26 = bitcast i32* %lookup_fmtstr_key31 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %26)
  store i32 0, i32* %lookup_fmtstr_key31, align 4
  %lookup_fmtstr_map32 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.2"*, i32*)*)(%"struct map_t.2"* @fmt_string_args, i32* %lookup_fmtstr_key31)
  %27 = bitcast i32* %lookup_fmtstr_key31 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %27)
  %lookup_fmtstr_cond35 = icmp ne i8* %lookup_fmtstr_map32, null
  br i1 %lookup_fmtstr_cond35, label %lookup_fmtstr_merge34, label %lookup_fmtstr_failure33

lookup_success27:                                 ; preds = %event_loss_counter22
  %28 = bitcast i8* %lookup_elem26 to i64*
  %29 = atomicrmw add i64* %28, i64 1 seq_cst
  br label %lookup_merge29

lookup_failure28:                                 ; preds = %event_loss_counter22
  br label %lookup_merge29

lookup_merge29:                                   ; preds = %lookup_failure28, %lookup_success27
  %30 = bitcast i32* %key25 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %30)
  br label %counter_merge23

lookup_fmtstr_failure33:                          ; preds = %counter_merge23
  ret i64 0

lookup_fmtstr_merge34:                            ; preds = %counter_merge23
  call void @llvm.memset.p0i8.i64(i8* align 1 %lookup_fmtstr_map32, i8 0, i64 8, i1 false)
  %31 = bitcast i8* %lookup_fmtstr_map32 to %printf_t.5*
  %32 = getelementptr %printf_t.5, %printf_t.5* %31, i32 0, i32 0
  store i64 0, i64* %32, align 8
  %ringbuf_output36 = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, i8*, i64, i64)*)(%"struct map_t.0"* @ringbuf, i8* %lookup_fmtstr_map32, i64 8, i64 0)
  %ringbuf_loss39 = icmp slt i64 %ringbuf_output36, 0
  br i1 %ringbuf_loss39, label %event_loss_counter37, label %counter_merge38

event_loss_counter37:                             ; preds = %lookup_fmtstr_merge34
  %33 = bitcast i32* %key40 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %33)
  store i32 0, i32* %key40, align 4
  %lookup_elem41 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key40)
  %map_lookup_cond45 = icmp ne i8* %lookup_elem41, null
  br i1 %map_lookup_cond45, label %lookup_success42, label %lookup_failure43

counter_merge38:                                  ; preds = %lookup_merge44, %lookup_fmtstr_merge34
  %34 = bitcast i32* %lookup_fmtstr_key46 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %34)
  store i32 0, i32* %lookup_fmtstr_key46, align 4
  %lookup_fmtstr_map47 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.2"*, i32*)*)(%"struct map_t.2"* @fmt_string_args, i32* %lookup_fmtstr_key46)
  %35 = bitcast i32* %lookup_fmtstr_key46 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %35)
  %lookup_fmtstr_cond50 = icmp ne i8* %lookup_fmtstr_map47, null
  br i1 %lookup_fmtstr_cond50, label %lookup_fmtstr_merge49, label %lookup_fmtstr_failure48

lookup_success42:                                 ; preds = %event_loss_counter37
  %36 = bitcast i8* %lookup_elem41 to i64*
  %37 = atomicrmw add i64* %36, i64 1 seq_cst
  br label %lookup_merge44

lookup_failure43:                                 ; preds = %event_loss_counter37
  br label %lookup_merge44

lookup_merge44:                                   ; preds = %lookup_failure43, %lookup_success42
  %38 = bitcast i32* %key40 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %38)
  br label %counter_merge38

lookup_fmtstr_failure48:                          ; preds = %counter_merge38
  ret i64 0

lookup_fmtstr_merge49:                            ; preds = %counter_merge38
  call void @llvm.memset.p0i8.i64(i8* align 1 %lookup_fmtstr_map47, i8 0, i64 8, i1 false)
  %39 = bitcast i8* %lookup_fmtstr_map47 to %printf_t.6*
  %40 = getelementptr %printf_t.6, %printf_t.6* %39, i32 0, i32 0
  store i64 0, i64* %40, align 8
  %ringbuf_output51 = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, i8*, i64, i64)*)(%"struct map_t.0"* @ringbuf, i8* %lookup_fmtstr_map47, i64 8, i64 0)
  %ringbuf_loss54 = icmp slt i64 %ringbuf_output51, 0
  br i1 %ringbuf_loss54, label %event_loss_counter52, label %counter_merge53

event_loss_counter52:                             ; preds = %lookup_fmtstr_merge49
  %41 = bitcast i32* %key55 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %41)
  store i32 0, i32* %key55, align 4
  %lookup_elem56 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key55)
  %map_lookup_cond60 = icmp ne i8* %lookup_elem56, null
  br i1 %map_lookup_cond60, label %lookup_success57, label %lookup_failure58

counter_merge53:                                  ; preds = %lookup_merge59, %lookup_fmtstr_merge49
  ret i64 0

lookup_success57:                                 ; preds = %event_loss_counter52
  %42 = bitcast i8* %lookup_elem56 to i64*
  %43 = atomicrmw add i64* %42, i64 1 seq_cst
  br label %lookup_merge59

lookup_failure58:                                 ; preds = %event_loss_counter52
  br label %lookup_merge59

lookup_merge59:                                   ; preds = %lookup_failure58, %lookup_success57
  %44 = bitcast i32* %key55 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %44)
  br label %counter_merge53
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

!llvm.dbg.cu = !{!62}
!llvm.module.flags = !{!65}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_i", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 131072, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 4096, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!20 = !DIGlobalVariableExpression(var: !21, expr: !DIExpression())
!21 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !22, isLocal: false, isDefinition: true)
!22 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !23)
!23 = !{!24, !29}
!24 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !25, size: 64)
!25 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !26, size: 64)
!26 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !27)
!27 = !{!28}
!28 = !DISubrange(count: 27, lowerBound: 0)
!29 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !30, size: 64, offset: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 262144, lowerBound: 0)
!34 = !DIGlobalVariableExpression(var: !35, expr: !DIExpression())
!35 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!36 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !37)
!37 = !{!38, !43, !44, !19}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !39, size: 64)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 2, lowerBound: 0)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !45, size: 64, offset: 128)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!47 = !DIGlobalVariableExpression(var: !48, expr: !DIExpression())
!48 = distinct !DIGlobalVariable(name: "fmt_string_args", linkageName: "global", scope: !2, file: !2, type: !49, isLocal: false, isDefinition: true)
!49 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !50)
!50 = !{!51, !43, !44, !56}
!51 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !52, size: 64)
!52 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !53, size: 64)
!53 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !54)
!54 = !{!55}
!55 = !DISubrange(count: 6, lowerBound: 0)
!56 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !57, size: 64, offset: 192)
!57 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !58, size: 64)
!58 = !DICompositeType(tag: DW_TAG_array_type, baseType: !59, size: 64, elements: !60)
!59 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!60 = !{!61}
!61 = !DISubrange(count: 8, lowerBound: 0)
!62 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !63, globals: !64)
!63 = !{}
!64 = !{!0, !20, !34, !47}
!65 = !{i32 2, !"Debug Info Version", i32 3}
!66 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !67, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !62, retainedNodes: !70)
!67 = !DISubroutineType(types: !68)
!68 = !{!18, !69}
!69 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!70 = !{!71}
!71 = !DILocalVariable(name: "ctx", arg: 1, scope: !66, file: !2, type: !69)
