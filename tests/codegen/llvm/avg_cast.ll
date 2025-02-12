; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>
%avg_stas_val = type { i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !26
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !40
@num_cpus = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !52

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !57 {
entry:
  %"$res" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$res")
  store i64 0, ptr %"$res", align 8
  %ret = alloca i64, align 8
  %key14 = alloca i32, align 4
  %helper_error_t9 = alloca %helper_error_t, align 8
  %val_2 = alloca i64, align 8
  %val_1 = alloca i64, align 8
  %i = alloca i32, align 4
  %"@x_key5" = alloca i64, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %avg_struct = alloca %avg_stas_val, align 8
  %"@x_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key")
  %lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %1 = getelementptr %avg_stas_val, ptr %lookup_elem, i64 0, i32 0
  %2 = load i64, ptr %1, align 8
  %3 = getelementptr %avg_stas_val, ptr %lookup_elem, i64 0, i32 1
  %4 = load i64, ptr %3, align 8
  %5 = getelementptr %avg_stas_val, ptr %lookup_elem, i64 0, i32 0
  %6 = add i64 %2, 2
  store i64 %6, ptr %5, align 8
  %7 = getelementptr %avg_stas_val, ptr %lookup_elem, i64 0, i32 1
  %8 = add i64 1, %4
  store i64 %8, ptr %7, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %avg_struct)
  %9 = getelementptr %avg_stas_val, ptr %avg_struct, i64 0, i32 0
  store i64 2, ptr %9, align 8
  %10 = getelementptr %avg_stas_val, ptr %avg_struct, i64 0, i32 1
  store i64 1, ptr %10, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %avg_struct, i64 0)
  %11 = trunc i64 %update_elem to i32
  %12 = icmp sge i32 %11, 0
  br i1 %12, label %helper_merge, label %helper_failure

lookup_merge:                                     ; preds = %helper_merge, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key5")
  store i64 0, ptr %"@x_key5", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %val_1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %val_2)
  store i32 0, ptr %i, align 4
  store i64 0, ptr %val_1, align 8
  store i64 0, ptr %val_2, align 8
  br label %while_cond

helper_failure:                                   ; preds = %lookup_failure
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %13 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %13, align 8
  %14 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %14, align 8
  %15 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %11, ptr %15, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %lookup_failure
  call void @llvm.lifetime.end.p0(i64 -1, ptr %avg_struct)
  br label %lookup_merge

event_loss_counter:                               ; preds = %helper_failure
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem1 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond = icmp ne ptr %lookup_elem1, null
  br i1 %map_lookup_cond, label %lookup_success2, label %lookup_failure3

counter_merge:                                    ; preds = %lookup_merge4, %helper_failure
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t)
  br label %helper_merge

lookup_success2:                                  ; preds = %event_loss_counter
  %16 = atomicrmw add ptr %lookup_elem1, i64 1 seq_cst, align 8
  br label %lookup_merge4

lookup_failure3:                                  ; preds = %event_loss_counter
  br label %lookup_merge4

lookup_merge4:                                    ; preds = %lookup_failure3, %lookup_success2
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

while_cond:                                       ; preds = %lookup_success6, %lookup_merge
  %17 = load i32, ptr @num_cpus, align 4
  %18 = load i32, ptr %i, align 4
  %num_cpu.cmp = icmp ult i32 %18, %17
  br i1 %num_cpu.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %19 = load i32, ptr %i, align 4
  %lookup_percpu_elem = call ptr inttoptr (i64 195 to ptr)(ptr @AT_x, ptr %"@x_key5", i32 %19)
  %map_lookup_cond8 = icmp ne ptr %lookup_percpu_elem, null
  br i1 %map_lookup_cond8, label %lookup_success6, label %lookup_failure7

while_end:                                        ; preds = %error_failure, %counter_merge12, %while_cond
  call void @llvm.lifetime.end.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ret)
  %20 = load i64, ptr %val_1, align 8
  %is_negative_cond = icmp slt i64 %20, 0
  br i1 %is_negative_cond, label %is_negative, label %is_positive

lookup_success6:                                  ; preds = %while_body
  %21 = getelementptr %avg_stas_val, ptr %lookup_percpu_elem, i64 0, i32 0
  %22 = load i64, ptr %21, align 8
  %23 = getelementptr %avg_stas_val, ptr %lookup_percpu_elem, i64 0, i32 1
  %24 = load i64, ptr %23, align 8
  %25 = load i64, ptr %val_1, align 8
  %26 = add i64 %22, %25
  store i64 %26, ptr %val_1, align 8
  %27 = load i64, ptr %val_2, align 8
  %28 = add i64 %24, %27
  store i64 %28, ptr %val_2, align 8
  %29 = load i32, ptr %i, align 4
  %30 = add i32 %29, 1
  store i32 %30, ptr %i, align 4
  br label %while_cond

lookup_failure7:                                  ; preds = %while_body
  %31 = load i32, ptr %i, align 4
  %error_lookup_cond = icmp eq i32 %31, 0
  br i1 %error_lookup_cond, label %error_success, label %error_failure

error_success:                                    ; preds = %lookup_failure7
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t9)
  %32 = getelementptr %helper_error_t, ptr %helper_error_t9, i64 0, i32 0
  store i64 30006, ptr %32, align 8
  %33 = getelementptr %helper_error_t, ptr %helper_error_t9, i64 0, i32 1
  store i64 1, ptr %33, align 8
  %34 = getelementptr %helper_error_t, ptr %helper_error_t9, i64 0, i32 2
  store i32 0, ptr %34, align 4
  %ringbuf_output10 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t9, i64 20, i64 0)
  %ringbuf_loss13 = icmp slt i64 %ringbuf_output10, 0
  br i1 %ringbuf_loss13, label %event_loss_counter11, label %counter_merge12

error_failure:                                    ; preds = %lookup_failure7
  %35 = load i32, ptr %i, align 4
  br label %while_end

event_loss_counter11:                             ; preds = %error_success
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key14)
  store i32 0, ptr %key14, align 4
  %lookup_elem15 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key14)
  %map_lookup_cond19 = icmp ne ptr %lookup_elem15, null
  br i1 %map_lookup_cond19, label %lookup_success16, label %lookup_failure17

counter_merge12:                                  ; preds = %lookup_merge18, %error_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t9)
  br label %while_end

lookup_success16:                                 ; preds = %event_loss_counter11
  %36 = atomicrmw add ptr %lookup_elem15, i64 1 seq_cst, align 8
  br label %lookup_merge18

lookup_failure17:                                 ; preds = %event_loss_counter11
  br label %lookup_merge18

lookup_merge18:                                   ; preds = %lookup_failure17, %lookup_success16
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key14)
  br label %counter_merge12

is_negative:                                      ; preds = %while_end
  %37 = load i64, ptr %val_1, align 8
  %38 = xor i64 %37, -1
  %39 = add i64 %38, 1
  %40 = load i64, ptr %val_2, align 8
  %41 = udiv i64 %39, %40
  %42 = sub i64 0, %41
  store i64 %42, ptr %ret, align 8
  br label %is_negative_merge_block

is_positive:                                      ; preds = %while_end
  %43 = load i64, ptr %val_2, align 8
  %44 = load i64, ptr %val_1, align 8
  %45 = udiv i64 %44, %43
  store i64 %45, ptr %ret, align 8
  br label %is_negative_merge_block

is_negative_merge_block:                          ; preds = %is_positive, %is_negative
  %46 = load i64, ptr %ret, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %ret)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %val_1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %val_2)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key5")
  store i64 %46, ptr %"$res", align 8
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!54}
!llvm.module.flags = !{!56}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 160, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 5, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 1, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !20, size: 64, offset: 192)
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!21 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !22)
!22 = !{!23, !24}
!23 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !18, size: 64)
!24 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !25, size: 64, offset: 64)
!25 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!26 = !DIGlobalVariableExpression(var: !27, expr: !DIExpression())
!27 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !28, isLocal: false, isDefinition: true)
!28 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !29)
!29 = !{!30, !35}
!30 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !31, size: 64)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !33)
!33 = !{!34}
!34 = !DISubrange(count: 27, lowerBound: 0)
!35 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !36, size: 64, offset: 64)
!36 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !37, size: 64)
!37 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !38)
!38 = !{!39}
!39 = !DISubrange(count: 262144, lowerBound: 0)
!40 = !DIGlobalVariableExpression(var: !41, expr: !DIExpression())
!41 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !42, isLocal: false, isDefinition: true)
!42 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !43)
!43 = !{!44, !11, !49, !51}
!44 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !45, size: 64)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !47)
!47 = !{!48}
!48 = !DISubrange(count: 2, lowerBound: 0)
!49 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !50, size: 64, offset: 128)
!50 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !25, size: 64)
!51 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!52 = !DIGlobalVariableExpression(var: !53, expr: !DIExpression())
!53 = distinct !DIGlobalVariable(name: "num_cpus", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!54 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !55)
!55 = !{!0, !26, !40, !52}
!56 = !{i32 2, !"Debug Info Version", i32 3}
!57 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !58, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !54, retainedNodes: !62)
!58 = !DISubroutineType(types: !59)
!59 = !{!18, !60}
!60 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !61, size: 64)
!61 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!62 = !{!63}
!63 = !DILocalVariable(name: "ctx", arg: 1, scope: !57, file: !2, type: !60)
