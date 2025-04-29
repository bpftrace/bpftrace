; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%int64_int64__tuple_t = type { i64, i64 }
%"(int64,int64)_count_t__tuple_t" = type { %int64_int64__tuple_t, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !31
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !45
@num_cpus = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !62

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !68 {
entry:
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %tuple = alloca %int64_int64__tuple_t, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %tuple)
  call void @llvm.memset.p0.i64(ptr align 1 %tuple, i8 0, i64 16, i1 false)
  %1 = getelementptr %int64_int64__tuple_t, ptr %tuple, i32 0, i32 0
  store i64 1, ptr %1, align 8
  %2 = getelementptr %int64_int64__tuple_t, ptr %tuple, i32 0, i32 1
  store i64 2, ptr %2, align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %tuple)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %3 = load i64, ptr %lookup_elem, align 8
  %4 = add i64 %3, 1
  store i64 %4, ptr %lookup_elem, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %initial_value)
  store i64 1, ptr %initial_value, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %tuple, ptr %initial_value, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %initial_value)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %tuple)
  %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr @AT_x, ptr @map_for_each_cb, ptr null, i64 0)
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nounwind
define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) #0 section ".text" !dbg !74 {
  %"$res" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$res")
  store i64 0, ptr %"$res", align 8
  %"$kv" = alloca %"(int64,int64)_count_t__tuple_t", align 8
  %val_2 = alloca i64, align 8
  %val_1 = alloca i64, align 8
  %i = alloca i32, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %val_1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %val_2)
  store i32 0, ptr %i, align 4
  store i64 0, ptr %val_1, align 8
  store i64 0, ptr %val_2, align 8
  br label %while_cond

while_cond:                                       ; preds = %lookup_success, %4
  %5 = load i32, ptr @num_cpus, align 4
  %6 = load i32, ptr %i, align 4
  %num_cpu.cmp = icmp ult i32 %6, %5
  br i1 %num_cpu.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %7 = load i32, ptr %i, align 4
  %lookup_percpu_elem = call ptr inttoptr (i64 195 to ptr)(ptr @AT_x, ptr %1, i32 %7)
  %map_lookup_cond = icmp ne ptr %lookup_percpu_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

while_end:                                        ; preds = %error_failure, %error_success, %while_cond
  call void @llvm.lifetime.end.p0(i64 -1, ptr %i)
  %8 = load i64, ptr %val_1, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %val_1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %val_2)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$kv")
  call void @llvm.memset.p0.i64(ptr align 1 %"$kv", i8 0, i64 24, i1 false)
  %9 = getelementptr %"(int64,int64)_count_t__tuple_t", ptr %"$kv", i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %9, ptr align 1 %1, i64 16, i1 false)
  %10 = getelementptr %"(int64,int64)_count_t__tuple_t", ptr %"$kv", i32 0, i32 1
  store i64 %8, ptr %10, align 8
  %11 = getelementptr %"(int64,int64)_count_t__tuple_t", ptr %"$kv", i32 0, i32 1
  %12 = load i64, ptr %11, align 8
  store i64 %12, ptr %"$res", align 8
  ret i64 0

lookup_success:                                   ; preds = %while_body
  %13 = load i64, ptr %val_1, align 8
  %14 = load i64, ptr %lookup_percpu_elem, align 8
  %15 = add i64 %14, %13
  store i64 %15, ptr %val_1, align 8
  %16 = load i32, ptr %i, align 4
  %17 = add i32 %16, 1
  store i32 %17, ptr %i, align 4
  br label %while_cond

lookup_failure:                                   ; preds = %while_body
  %18 = load i32, ptr %i, align 4
  %error_lookup_cond = icmp eq i32 %18, 0
  br i1 %error_lookup_cond, label %error_success, label %error_failure

error_success:                                    ; preds = %lookup_failure
  br label %while_end

error_failure:                                    ; preds = %lookup_failure
  %19 = load i32, ptr %i, align 4
  br label %while_end
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!64}
!llvm.module.flags = !{!66, !67}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !10)
!10 = !{!11, !17, !22, !29}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 160, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 5, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !18, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 131072, elements: !20)
!20 = !{!21}
!21 = !DISubrange(count: 4096, lowerBound: 0)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !23, size: 64, offset: 128)
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !25)
!25 = !{!26, !28}
!26 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!28 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !27, size: 64, offset: 64)
!29 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !30, size: 64, offset: 192)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!31 = !DIGlobalVariableExpression(var: !32, expr: !DIExpression())
!32 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !33, isLocal: false, isDefinition: true)
!33 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !34)
!34 = !{!35, !40}
!35 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !36, size: 64)
!36 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !37, size: 64)
!37 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !38)
!38 = !{!39}
!39 = !DISubrange(count: 27, lowerBound: 0)
!40 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !41, size: 64, offset: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 262144, lowerBound: 0)
!45 = !DIGlobalVariableExpression(var: !46, expr: !DIExpression())
!46 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !47, isLocal: false, isDefinition: true)
!47 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !48)
!48 = !{!49, !54, !59, !29}
!49 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !50, size: 64)
!50 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !51, size: 64)
!51 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 64, elements: !52)
!52 = !{!53}
!53 = !DISubrange(count: 2, lowerBound: 0)
!54 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !55, size: 64, offset: 64)
!55 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !56, size: 64)
!56 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !57)
!57 = !{!58}
!58 = !DISubrange(count: 1, lowerBound: 0)
!59 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !60, size: 64, offset: 128)
!60 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !61, size: 64)
!61 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!62 = !DIGlobalVariableExpression(var: !63, expr: !DIExpression())
!63 = distinct !DIGlobalVariable(name: "num_cpus", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!64 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !65)
!65 = !{!0, !7, !31, !45, !62}
!66 = !{i32 2, !"Debug Info Version", i32 3}
!67 = !{i32 7, !"uwtable", i32 0}
!68 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !69, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !64, retainedNodes: !72)
!69 = !DISubroutineType(types: !70)
!70 = !{!27, !71}
!71 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!72 = !{!73}
!73 = !DILocalVariable(name: "ctx", arg: 1, scope: !68, file: !2, type: !71)
!74 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !75, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !64, retainedNodes: !77)
!75 = !DISubroutineType(types: !76)
!76 = !{!27, !71, !71, !71, !71}
!77 = !{!78, !79, !80, !81}
!78 = !DILocalVariable(name: "map", arg: 1, scope: !74, file: !2, type: !71)
!79 = !DILocalVariable(name: "key", arg: 2, scope: !74, file: !2, type: !71)
!80 = !DILocalVariable(name: "value", arg: 3, scope: !74, file: !2, type: !71)
!81 = !DILocalVariable(name: "ctx", arg: 4, scope: !74, file: !2, type: !71)
