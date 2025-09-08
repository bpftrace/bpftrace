; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.0" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_ = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_internal_repr_t.0" zeroinitializer, section ".maps", !dbg !22
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !36
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !40
@__bt__get_str_buf = dso_local externally_initialized global [1 x [1 x [1024 x i8]]] zeroinitializer, section ".data.get_str_buf", !dbg !42

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @tracepoint_file_filename_1(ptr %0) #0 section "s_tracepoint_file_filename_1" !dbg !53 {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %strcmp.result = alloca i64, align 8
  %__builtin_comm = alloca [16 x i8], align 1
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #4
  %1 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [1 x [1024 x i8]]], ptr @__bt__get_str_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %2, i32 1024, ptr null)
  %3 = call ptr @llvm.preserve.static.offset(ptr %0)
  %4 = getelementptr i8, ptr %3, i64 8
  %5 = load volatile ptr, ptr %4, align 8
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to ptr)(ptr %2, i32 1024, ptr %5)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %__builtin_comm)
  call void @llvm.memset.p0.i64(ptr align 1 %__builtin_comm, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to ptr)(ptr %__builtin_comm, i64 16)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %strcmp.result)
  store i64 0, ptr %strcmp.result, align 8
  %6 = getelementptr i8, ptr %2, i32 0
  %7 = load i8, ptr %6, align 1
  %8 = getelementptr i8, ptr %__builtin_comm, i32 0
  %9 = load i8, ptr %8, align 1
  %strcmp.cmp = icmp ne i8 %7, %9
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

pred_false:                                       ; preds = %strcmp.false
  ret i64 1

pred_true:                                        ; preds = %strcmp.false
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key")
  store i64 0, ptr %"@_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_val")
  store i64 1, ptr %"@_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_, ptr %"@_key", ptr %"@_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key")
  ret i64 1

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop53, %strcmp.loop49, %strcmp.loop45, %strcmp.loop41, %strcmp.loop37, %strcmp.loop33, %strcmp.loop29, %strcmp.loop25, %strcmp.loop21, %strcmp.loop17, %strcmp.loop13, %strcmp.loop9, %strcmp.loop5, %strcmp.loop1, %strcmp.loop, %entry
  %10 = load i64, ptr %strcmp.result, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %strcmp.result)
  %11 = trunc i64 %10 to i1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %__builtin_comm)
  %predcond = icmp eq i1 %11, false
  br i1 %predcond, label %pred_false, label %pred_true

strcmp.done:                                      ; preds = %strcmp.loop57, %strcmp.loop_null_cmp58, %strcmp.loop_null_cmp54, %strcmp.loop_null_cmp50, %strcmp.loop_null_cmp46, %strcmp.loop_null_cmp42, %strcmp.loop_null_cmp38, %strcmp.loop_null_cmp34, %strcmp.loop_null_cmp30, %strcmp.loop_null_cmp26, %strcmp.loop_null_cmp22, %strcmp.loop_null_cmp18, %strcmp.loop_null_cmp14, %strcmp.loop_null_cmp10, %strcmp.loop_null_cmp6, %strcmp.loop_null_cmp2, %strcmp.loop_null_cmp
  store i64 1, ptr %strcmp.result, align 8
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %12 = getelementptr i8, ptr %2, i32 1
  %13 = load i8, ptr %12, align 1
  %14 = getelementptr i8, ptr %__builtin_comm, i32 1
  %15 = load i8, ptr %14, align 1
  %strcmp.cmp3 = icmp ne i8 %13, %15
  br i1 %strcmp.cmp3, label %strcmp.false, label %strcmp.loop_null_cmp2

strcmp.loop_null_cmp:                             ; preds = %entry
  %strcmp.cmp_null = icmp eq i8 %7, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop1:                                     ; preds = %strcmp.loop_null_cmp2
  %16 = getelementptr i8, ptr %2, i32 2
  %17 = load i8, ptr %16, align 1
  %18 = getelementptr i8, ptr %__builtin_comm, i32 2
  %19 = load i8, ptr %18, align 1
  %strcmp.cmp7 = icmp ne i8 %17, %19
  br i1 %strcmp.cmp7, label %strcmp.false, label %strcmp.loop_null_cmp6

strcmp.loop_null_cmp2:                            ; preds = %strcmp.loop
  %strcmp.cmp_null4 = icmp eq i8 %13, 0
  br i1 %strcmp.cmp_null4, label %strcmp.done, label %strcmp.loop1

strcmp.loop5:                                     ; preds = %strcmp.loop_null_cmp6
  %20 = getelementptr i8, ptr %2, i32 3
  %21 = load i8, ptr %20, align 1
  %22 = getelementptr i8, ptr %__builtin_comm, i32 3
  %23 = load i8, ptr %22, align 1
  %strcmp.cmp11 = icmp ne i8 %21, %23
  br i1 %strcmp.cmp11, label %strcmp.false, label %strcmp.loop_null_cmp10

strcmp.loop_null_cmp6:                            ; preds = %strcmp.loop1
  %strcmp.cmp_null8 = icmp eq i8 %17, 0
  br i1 %strcmp.cmp_null8, label %strcmp.done, label %strcmp.loop5

strcmp.loop9:                                     ; preds = %strcmp.loop_null_cmp10
  %24 = getelementptr i8, ptr %2, i32 4
  %25 = load i8, ptr %24, align 1
  %26 = getelementptr i8, ptr %__builtin_comm, i32 4
  %27 = load i8, ptr %26, align 1
  %strcmp.cmp15 = icmp ne i8 %25, %27
  br i1 %strcmp.cmp15, label %strcmp.false, label %strcmp.loop_null_cmp14

strcmp.loop_null_cmp10:                           ; preds = %strcmp.loop5
  %strcmp.cmp_null12 = icmp eq i8 %21, 0
  br i1 %strcmp.cmp_null12, label %strcmp.done, label %strcmp.loop9

strcmp.loop13:                                    ; preds = %strcmp.loop_null_cmp14
  %28 = getelementptr i8, ptr %2, i32 5
  %29 = load i8, ptr %28, align 1
  %30 = getelementptr i8, ptr %__builtin_comm, i32 5
  %31 = load i8, ptr %30, align 1
  %strcmp.cmp19 = icmp ne i8 %29, %31
  br i1 %strcmp.cmp19, label %strcmp.false, label %strcmp.loop_null_cmp18

strcmp.loop_null_cmp14:                           ; preds = %strcmp.loop9
  %strcmp.cmp_null16 = icmp eq i8 %25, 0
  br i1 %strcmp.cmp_null16, label %strcmp.done, label %strcmp.loop13

strcmp.loop17:                                    ; preds = %strcmp.loop_null_cmp18
  %32 = getelementptr i8, ptr %2, i32 6
  %33 = load i8, ptr %32, align 1
  %34 = getelementptr i8, ptr %__builtin_comm, i32 6
  %35 = load i8, ptr %34, align 1
  %strcmp.cmp23 = icmp ne i8 %33, %35
  br i1 %strcmp.cmp23, label %strcmp.false, label %strcmp.loop_null_cmp22

strcmp.loop_null_cmp18:                           ; preds = %strcmp.loop13
  %strcmp.cmp_null20 = icmp eq i8 %29, 0
  br i1 %strcmp.cmp_null20, label %strcmp.done, label %strcmp.loop17

strcmp.loop21:                                    ; preds = %strcmp.loop_null_cmp22
  %36 = getelementptr i8, ptr %2, i32 7
  %37 = load i8, ptr %36, align 1
  %38 = getelementptr i8, ptr %__builtin_comm, i32 7
  %39 = load i8, ptr %38, align 1
  %strcmp.cmp27 = icmp ne i8 %37, %39
  br i1 %strcmp.cmp27, label %strcmp.false, label %strcmp.loop_null_cmp26

strcmp.loop_null_cmp22:                           ; preds = %strcmp.loop17
  %strcmp.cmp_null24 = icmp eq i8 %33, 0
  br i1 %strcmp.cmp_null24, label %strcmp.done, label %strcmp.loop21

strcmp.loop25:                                    ; preds = %strcmp.loop_null_cmp26
  %40 = getelementptr i8, ptr %2, i32 8
  %41 = load i8, ptr %40, align 1
  %42 = getelementptr i8, ptr %__builtin_comm, i32 8
  %43 = load i8, ptr %42, align 1
  %strcmp.cmp31 = icmp ne i8 %41, %43
  br i1 %strcmp.cmp31, label %strcmp.false, label %strcmp.loop_null_cmp30

strcmp.loop_null_cmp26:                           ; preds = %strcmp.loop21
  %strcmp.cmp_null28 = icmp eq i8 %37, 0
  br i1 %strcmp.cmp_null28, label %strcmp.done, label %strcmp.loop25

strcmp.loop29:                                    ; preds = %strcmp.loop_null_cmp30
  %44 = getelementptr i8, ptr %2, i32 9
  %45 = load i8, ptr %44, align 1
  %46 = getelementptr i8, ptr %__builtin_comm, i32 9
  %47 = load i8, ptr %46, align 1
  %strcmp.cmp35 = icmp ne i8 %45, %47
  br i1 %strcmp.cmp35, label %strcmp.false, label %strcmp.loop_null_cmp34

strcmp.loop_null_cmp30:                           ; preds = %strcmp.loop25
  %strcmp.cmp_null32 = icmp eq i8 %41, 0
  br i1 %strcmp.cmp_null32, label %strcmp.done, label %strcmp.loop29

strcmp.loop33:                                    ; preds = %strcmp.loop_null_cmp34
  %48 = getelementptr i8, ptr %2, i32 10
  %49 = load i8, ptr %48, align 1
  %50 = getelementptr i8, ptr %__builtin_comm, i32 10
  %51 = load i8, ptr %50, align 1
  %strcmp.cmp39 = icmp ne i8 %49, %51
  br i1 %strcmp.cmp39, label %strcmp.false, label %strcmp.loop_null_cmp38

strcmp.loop_null_cmp34:                           ; preds = %strcmp.loop29
  %strcmp.cmp_null36 = icmp eq i8 %45, 0
  br i1 %strcmp.cmp_null36, label %strcmp.done, label %strcmp.loop33

strcmp.loop37:                                    ; preds = %strcmp.loop_null_cmp38
  %52 = getelementptr i8, ptr %2, i32 11
  %53 = load i8, ptr %52, align 1
  %54 = getelementptr i8, ptr %__builtin_comm, i32 11
  %55 = load i8, ptr %54, align 1
  %strcmp.cmp43 = icmp ne i8 %53, %55
  br i1 %strcmp.cmp43, label %strcmp.false, label %strcmp.loop_null_cmp42

strcmp.loop_null_cmp38:                           ; preds = %strcmp.loop33
  %strcmp.cmp_null40 = icmp eq i8 %49, 0
  br i1 %strcmp.cmp_null40, label %strcmp.done, label %strcmp.loop37

strcmp.loop41:                                    ; preds = %strcmp.loop_null_cmp42
  %56 = getelementptr i8, ptr %2, i32 12
  %57 = load i8, ptr %56, align 1
  %58 = getelementptr i8, ptr %__builtin_comm, i32 12
  %59 = load i8, ptr %58, align 1
  %strcmp.cmp47 = icmp ne i8 %57, %59
  br i1 %strcmp.cmp47, label %strcmp.false, label %strcmp.loop_null_cmp46

strcmp.loop_null_cmp42:                           ; preds = %strcmp.loop37
  %strcmp.cmp_null44 = icmp eq i8 %53, 0
  br i1 %strcmp.cmp_null44, label %strcmp.done, label %strcmp.loop41

strcmp.loop45:                                    ; preds = %strcmp.loop_null_cmp46
  %60 = getelementptr i8, ptr %2, i32 13
  %61 = load i8, ptr %60, align 1
  %62 = getelementptr i8, ptr %__builtin_comm, i32 13
  %63 = load i8, ptr %62, align 1
  %strcmp.cmp51 = icmp ne i8 %61, %63
  br i1 %strcmp.cmp51, label %strcmp.false, label %strcmp.loop_null_cmp50

strcmp.loop_null_cmp46:                           ; preds = %strcmp.loop41
  %strcmp.cmp_null48 = icmp eq i8 %57, 0
  br i1 %strcmp.cmp_null48, label %strcmp.done, label %strcmp.loop45

strcmp.loop49:                                    ; preds = %strcmp.loop_null_cmp50
  %64 = getelementptr i8, ptr %2, i32 14
  %65 = load i8, ptr %64, align 1
  %66 = getelementptr i8, ptr %__builtin_comm, i32 14
  %67 = load i8, ptr %66, align 1
  %strcmp.cmp55 = icmp ne i8 %65, %67
  br i1 %strcmp.cmp55, label %strcmp.false, label %strcmp.loop_null_cmp54

strcmp.loop_null_cmp50:                           ; preds = %strcmp.loop45
  %strcmp.cmp_null52 = icmp eq i8 %61, 0
  br i1 %strcmp.cmp_null52, label %strcmp.done, label %strcmp.loop49

strcmp.loop53:                                    ; preds = %strcmp.loop_null_cmp54
  %68 = getelementptr i8, ptr %2, i32 15
  %69 = load i8, ptr %68, align 1
  %70 = getelementptr i8, ptr %__builtin_comm, i32 15
  %71 = load i8, ptr %70, align 1
  %strcmp.cmp59 = icmp ne i8 %69, %71
  br i1 %strcmp.cmp59, label %strcmp.false, label %strcmp.loop_null_cmp58

strcmp.loop_null_cmp54:                           ; preds = %strcmp.loop49
  %strcmp.cmp_null56 = icmp eq i8 %65, 0
  br i1 %strcmp.cmp_null56, label %strcmp.done, label %strcmp.loop53

strcmp.loop57:                                    ; preds = %strcmp.loop_null_cmp58
  br label %strcmp.done

strcmp.loop_null_cmp58:                           ; preds = %strcmp.loop53
  %strcmp.cmp_null60 = icmp eq i8 %69, 0
  br i1 %strcmp.cmp_null60, label %strcmp.done, label %strcmp.loop57
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #3

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #4 = { memory(none) }

!llvm.dbg.cu = !{!49}
!llvm.module.flags = !{!51, !52}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !10)
!10 = !{!11, !17, !18, !21}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 1, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !19, size: 64, offset: 128)
!19 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !20, size: 64)
!20 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !19, size: 64, offset: 192)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !25)
!25 = !{!26, !31}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 27, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !32, size: 64, offset: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 262144, lowerBound: 0)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_array_type, baseType: !39, size: 64, elements: !15)
!39 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 64, elements: !15)
!40 = !DIGlobalVariableExpression(var: !41, expr: !DIExpression())
!41 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!42 = !DIGlobalVariableExpression(var: !43, expr: !DIExpression())
!43 = distinct !DIGlobalVariable(name: "__bt__get_str_buf", linkageName: "global", scope: !2, file: !2, type: !44, isLocal: false, isDefinition: true)
!44 = !DICompositeType(tag: DW_TAG_array_type, baseType: !45, size: 8192, elements: !15)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !46, size: 8192, elements: !15)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 8192, elements: !47)
!47 = !{!48}
!48 = !DISubrange(count: 1024, lowerBound: 0)
!49 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !50)
!50 = !{!0, !7, !22, !36, !40, !42}
!51 = !{i32 2, !"Debug Info Version", i32 3}
!52 = !{i32 7, !"uwtable", i32 0}
!53 = distinct !DISubprogram(name: "tracepoint_file_filename_1", linkageName: "tracepoint_file_filename_1", scope: !2, file: !2, type: !54, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !49, retainedNodes: !57)
!54 = !DISubroutineType(types: !55)
!55 = !{!20, !56}
!56 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!57 = !{!58}
!58 = !DILocalVariable(name: "ctx", arg: 1, scope: !53, file: !2, type: !56)
