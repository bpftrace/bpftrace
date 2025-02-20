; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_bar = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !35
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !49

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !62 {
entry:
  %key15 = alloca i32, align 4
  %helper_error_t10 = alloca %helper_error_t, align 8
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %lookup_elem_val = alloca [2 x [2 x [4 x i8]]], align 1
  %"@bar_key1" = alloca i64, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %"@bar_val" = alloca [2 x [2 x [4 x i8]]], align 1
  %"@bar_key" = alloca i64, align 8
  %1 = call ptr @llvm.preserve.static.offset(ptr %0)
  %2 = getelementptr i64, ptr %1, i64 14
  %arg0 = load volatile i64, ptr %2, align 8
  %3 = inttoptr i64 %arg0 to ptr
  %4 = call ptr @llvm.preserve.static.offset(ptr %3)
  %5 = getelementptr i8, ptr %4, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_key")
  store i64 42, ptr %"@bar_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_val")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"@bar_val", i32 16, ptr %5)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_bar, ptr %"@bar_key", ptr %"@bar_val", i64 0)
  %6 = trunc i64 %update_elem to i32
  %7 = icmp sge i32 %6, 0
  br i1 %7, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %8 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %8, align 8
  %9 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %9, align 8
  %10 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %6, ptr %10, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %entry
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_key1")
  store i64 42, ptr %"@bar_key1", align 8
  %lookup_elem2 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_bar, ptr %"@bar_key1")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond6 = icmp ne ptr %lookup_elem2, null
  br i1 %map_lookup_cond6, label %lookup_success3, label %lookup_failure4

event_loss_counter:                               ; preds = %helper_failure
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %helper_failure
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t)
  br label %helper_merge

lookup_success:                                   ; preds = %event_loss_counter
  %11 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

lookup_success3:                                  ; preds = %helper_merge
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %lookup_elem_val, ptr align 1 %lookup_elem2, i64 16, i1 false)
  br label %lookup_merge5

lookup_failure4:                                  ; preds = %helper_merge
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_elem_val, i8 0, i64 16, i1 false)
  br label %lookup_merge5

lookup_merge5:                                    ; preds = %lookup_failure4, %lookup_success3
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_key1")
  %12 = getelementptr [2 x [2 x [4 x i8]]], ptr %lookup_elem_val, i32 0, i64 0
  %13 = getelementptr [2 x [4 x i8]], ptr %12, i32 0, i64 1
  %14 = getelementptr [4 x i8], ptr %13, i32 0, i64 0
  %15 = load volatile i32, ptr %14, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key")
  store i64 0, ptr %"@_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_val")
  %16 = sext i32 %15 to i64
  store i64 %16, ptr %"@_val", align 8
  %update_elem7 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_, ptr %"@_key", ptr %"@_val", i64 0)
  %17 = trunc i64 %update_elem7 to i32
  %18 = icmp sge i32 %17, 0
  br i1 %18, label %helper_merge9, label %helper_failure8

helper_failure8:                                  ; preds = %lookup_merge5
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t10)
  %19 = getelementptr %helper_error_t, ptr %helper_error_t10, i64 0, i32 0
  store i64 30006, ptr %19, align 8
  %20 = getelementptr %helper_error_t, ptr %helper_error_t10, i64 0, i32 1
  store i64 1, ptr %20, align 8
  %21 = getelementptr %helper_error_t, ptr %helper_error_t10, i64 0, i32 2
  store i32 %17, ptr %21, align 4
  %ringbuf_output11 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t10, i64 20, i64 0)
  %ringbuf_loss14 = icmp slt i64 %ringbuf_output11, 0
  br i1 %ringbuf_loss14, label %event_loss_counter12, label %counter_merge13

helper_merge9:                                    ; preds = %counter_merge13, %lookup_merge5
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key")
  ret i64 0

event_loss_counter12:                             ; preds = %helper_failure8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key15)
  store i32 0, ptr %key15, align 4
  %lookup_elem16 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key15)
  %map_lookup_cond20 = icmp ne ptr %lookup_elem16, null
  br i1 %map_lookup_cond20, label %lookup_success17, label %lookup_failure18

counter_merge13:                                  ; preds = %lookup_merge19, %helper_failure8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t10)
  br label %helper_merge9

lookup_success17:                                 ; preds = %event_loss_counter12
  %22 = atomicrmw add ptr %lookup_elem16, i64 1 seq_cst, align 8
  br label %lookup_merge19

lookup_failure18:                                 ; preds = %event_loss_counter12
  br label %lookup_merge19

lookup_merge19:                                   ; preds = %lookup_failure18, %lookup_success17
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key15)
  br label %counter_merge13
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #4

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #4 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!59}
!llvm.module.flags = !{!61}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !12, !15}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !13, size: 64, offset: 128)
!13 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !14, size: 64)
!14 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!15 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !13, size: 64, offset: 192)
!16 = !DIGlobalVariableExpression(var: !17, expr: !DIExpression())
!17 = distinct !DIGlobalVariable(name: "AT_bar", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !19)
!19 = !{!5, !20, !12, !25}
!20 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !21, size: 64, offset: 64)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 131072, elements: !23)
!23 = !{!24}
!24 = !DISubrange(count: 4096, lowerBound: 0)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !26, size: 64, offset: 192)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !28, size: 128, elements: !33)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !29, size: 64, elements: !33)
!29 = !DICompositeType(tag: DW_TAG_array_type, baseType: !30, size: 32, elements: !31)
!30 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!31 = !{!32}
!32 = !DISubrange(count: 4, lowerBound: 0)
!33 = !{!34}
!34 = !DISubrange(count: 2, lowerBound: 0)
!35 = !DIGlobalVariableExpression(var: !36, expr: !DIExpression())
!36 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !37, isLocal: false, isDefinition: true)
!37 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !38)
!38 = !{!39, !44}
!39 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !40, size: 64)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 27, lowerBound: 0)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !45, size: 64, offset: 64)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !47)
!47 = !{!48}
!48 = !DISubrange(count: 262144, lowerBound: 0)
!49 = !DIGlobalVariableExpression(var: !50, expr: !DIExpression())
!50 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !51, isLocal: false, isDefinition: true)
!51 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !52)
!52 = !{!53, !11, !56, !15}
!53 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !54, size: 64)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !33)
!56 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !57, size: 64, offset: 128)
!57 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !58, size: 64)
!58 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!59 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !60)
!60 = !{!0, !16, !35, !49}
!61 = !{i32 2, !"Debug Info Version", i32 3}
!62 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !63, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !59, retainedNodes: !66)
!63 = !DISubroutineType(types: !64)
!64 = !{!14, !65}
!65 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !30, size: 64)
!66 = !{!67}
!67 = !DILocalVariable(name: "ctx", arg: 1, scope: !62, file: !2, type: !65)
