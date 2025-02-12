; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr }
%"struct map_t.3" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_bar = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_foo = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !21
@AT_x = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !30
@ringbuf = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !35
@event_loss_counter = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !49

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !64 {
entry:
  %key36 = alloca i32, align 4
  %helper_error_t31 = alloca %helper_error_t, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %lookup_elem_val26 = alloca [16 x i8], align 1
  %"@foo_key21" = alloca i64, align 8
  %key15 = alloca i32, align 4
  %helper_error_t10 = alloca %helper_error_t, align 8
  %"@bar_key" = alloca i64, align 8
  %lookup_elem_val = alloca [16 x i8], align 1
  %"@foo_key1" = alloca i64, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %"@foo_val" = alloca [16 x i8], align 1
  %"@foo_key" = alloca i64, align 8
  %1 = call ptr @llvm.preserve.static.offset(ptr %0)
  %2 = getelementptr i64, ptr %1, i64 14
  %arg0 = load volatile i64, ptr %2, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_key")
  store i64 0, ptr %"@foo_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_val")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"@foo_val", i32 16, i64 %arg0)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_foo, ptr %"@foo_key", ptr %"@foo_val", i64 0)
  %3 = trunc i64 %update_elem to i32
  %4 = icmp sge i32 %3, 0
  br i1 %4, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %5 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %5, align 8
  %6 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %6, align 8
  %7 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %3, ptr %7, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %entry
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_key1")
  store i64 0, ptr %"@foo_key1", align 8
  %lookup_elem2 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_foo, ptr %"@foo_key1")
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
  %8 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
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
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_key1")
  %9 = getelementptr [16 x i8], ptr %lookup_elem_val, i32 0, i64 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_key")
  store i64 0, ptr %"@bar_key", align 8
  %update_elem7 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_bar, ptr %"@bar_key", ptr %9, i64 0)
  %10 = trunc i64 %update_elem7 to i32
  %11 = icmp sge i32 %10, 0
  br i1 %11, label %helper_merge9, label %helper_failure8

helper_failure8:                                  ; preds = %lookup_merge5
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t10)
  %12 = getelementptr %helper_error_t, ptr %helper_error_t10, i64 0, i32 0
  store i64 30006, ptr %12, align 8
  %13 = getelementptr %helper_error_t, ptr %helper_error_t10, i64 0, i32 1
  store i64 1, ptr %13, align 8
  %14 = getelementptr %helper_error_t, ptr %helper_error_t10, i64 0, i32 2
  store i32 %10, ptr %14, align 4
  %ringbuf_output11 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t10, i64 20, i64 0)
  %ringbuf_loss14 = icmp slt i64 %ringbuf_output11, 0
  br i1 %ringbuf_loss14, label %event_loss_counter12, label %counter_merge13

helper_merge9:                                    ; preds = %counter_merge13, %lookup_merge5
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_key21")
  store i64 0, ptr %"@foo_key21", align 8
  %lookup_elem22 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_foo, ptr %"@foo_key21")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val26)
  %map_lookup_cond27 = icmp ne ptr %lookup_elem22, null
  br i1 %map_lookup_cond27, label %lookup_success23, label %lookup_failure24

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
  %15 = atomicrmw add ptr %lookup_elem16, i64 1 seq_cst, align 8
  br label %lookup_merge19

lookup_failure18:                                 ; preds = %event_loss_counter12
  br label %lookup_merge19

lookup_merge19:                                   ; preds = %lookup_failure18, %lookup_success17
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key15)
  br label %counter_merge13

lookup_success23:                                 ; preds = %helper_merge9
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %lookup_elem_val26, ptr align 1 %lookup_elem22, i64 16, i1 false)
  br label %lookup_merge25

lookup_failure24:                                 ; preds = %helper_merge9
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_elem_val26, i8 0, i64 16, i1 false)
  br label %lookup_merge25

lookup_merge25:                                   ; preds = %lookup_failure24, %lookup_success23
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_key21")
  %16 = getelementptr [16 x i8], ptr %lookup_elem_val26, i32 0, i64 4
  %17 = getelementptr [8 x i8], ptr %16, i32 0, i64 0
  %18 = load volatile i32, ptr %17, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val26)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_val")
  %19 = sext i32 %18 to i64
  store i64 %19, ptr %"@x_val", align 8
  %update_elem28 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %"@x_val", i64 0)
  %20 = trunc i64 %update_elem28 to i32
  %21 = icmp sge i32 %20, 0
  br i1 %21, label %helper_merge30, label %helper_failure29

helper_failure29:                                 ; preds = %lookup_merge25
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t31)
  %22 = getelementptr %helper_error_t, ptr %helper_error_t31, i64 0, i32 0
  store i64 30006, ptr %22, align 8
  %23 = getelementptr %helper_error_t, ptr %helper_error_t31, i64 0, i32 1
  store i64 2, ptr %23, align 8
  %24 = getelementptr %helper_error_t, ptr %helper_error_t31, i64 0, i32 2
  store i32 %20, ptr %24, align 4
  %ringbuf_output32 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t31, i64 20, i64 0)
  %ringbuf_loss35 = icmp slt i64 %ringbuf_output32, 0
  br i1 %ringbuf_loss35, label %event_loss_counter33, label %counter_merge34

helper_merge30:                                   ; preds = %counter_merge34, %lookup_merge25
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  ret i64 0

event_loss_counter33:                             ; preds = %helper_failure29
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key36)
  store i32 0, ptr %key36, align 4
  %lookup_elem37 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key36)
  %map_lookup_cond41 = icmp ne ptr %lookup_elem37, null
  br i1 %map_lookup_cond41, label %lookup_success38, label %lookup_failure39

counter_merge34:                                  ; preds = %lookup_merge40, %helper_failure29
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t31)
  br label %helper_merge30

lookup_success38:                                 ; preds = %event_loss_counter33
  %25 = atomicrmw add ptr %lookup_elem37, i64 1 seq_cst, align 8
  br label %lookup_merge40

lookup_failure39:                                 ; preds = %event_loss_counter33
  br label %lookup_merge40

lookup_merge40:                                   ; preds = %lookup_failure39, %lookup_success38
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key36)
  br label %counter_merge34
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

!llvm.dbg.cu = !{!61}
!llvm.module.flags = !{!63}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_bar", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!15 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !16, size: 64, offset: 192)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !17, size: 64)
!17 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 64, elements: !19)
!18 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DISubrange(count: 8, lowerBound: 0)
!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())
!22 = distinct !DIGlobalVariable(name: "AT_foo", linkageName: "global", scope: !2, file: !2, type: !23, isLocal: false, isDefinition: true)
!23 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !24)
!24 = !{!5, !11, !12, !25}
!25 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !26, size: 64, offset: 192)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 128, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 16, lowerBound: 0)
!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())
!31 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !32, isLocal: false, isDefinition: true)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !33)
!33 = !{!5, !11, !12, !34}
!34 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !13, size: 64, offset: 192)
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
!52 = !{!53, !11, !58, !34}
!53 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !54, size: 64)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !56)
!56 = !{!57}
!57 = !DISubrange(count: 2, lowerBound: 0)
!58 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !59, size: 64, offset: 128)
!59 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !60, size: 64)
!60 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!61 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !62)
!62 = !{!0, !21, !30, !35, !49}
!63 = !{i32 2, !"Debug Info Version", i32 3}
!64 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !65, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !61, retainedNodes: !68)
!65 = !DISubroutineType(types: !66)
!66 = !{!14, !67}
!67 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!68 = !{!69}
!69 = !DILocalVariable(name: "ctx", arg: 1, scope: !64, file: !2, type: !67)
