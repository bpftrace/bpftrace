; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@str_buffer = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !51

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @tracepoint_file_filename_1(ptr %0) section "s_tracepoint_file_filename_1" !dbg !56 {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %strcmp.result = alloca i1, align 1
  %comm = alloca [16 x i8], align 1
  %lookup_str_key = alloca i32, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_str_key)
  store i32 0, ptr %lookup_str_key, align 4
  %lookup_str_map = call ptr inttoptr (i64 1 to ptr)(ptr @str_buffer, ptr %lookup_str_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_str_key)
  %lookup_str_cond = icmp ne ptr %lookup_str_map, null
  br i1 %lookup_str_cond, label %lookup_str_merge, label %lookup_str_failure

pred_false:                                       ; preds = %strcmp.false
  ret i64 1

pred_true:                                        ; preds = %strcmp.false
  call void @llvm.lifetime.end.p0(i64 -1, ptr %comm)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key")
  store i64 0, ptr %"@_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_val")
  store i64 1, ptr %"@_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_, ptr %"@_key", ptr %"@_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key")
  ret i64 1

lookup_str_failure:                               ; preds = %entry
  ret i64 0

lookup_str_merge:                                 ; preds = %entry
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_str_map, i8 0, i64 64, i1 false)
  %1 = ptrtoint ptr %0 to i64
  %2 = add i64 %1, 8
  %3 = inttoptr i64 %2 to ptr
  %4 = load volatile i64, ptr %3, align 8
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to ptr)(ptr %lookup_str_map, i32 64, i64 %4)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %comm)
  call void @llvm.memset.p0.i64(ptr align 1 %comm, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to ptr)(ptr %comm, i64 16)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %strcmp.result)
  store i1 false, ptr %strcmp.result, align 1
  %5 = getelementptr i8, ptr %lookup_str_map, i32 0
  %6 = load i8, ptr %5, align 1
  %7 = getelementptr i8, ptr %comm, i32 0
  %8 = load i8, ptr %7, align 1
  %strcmp.cmp = icmp ne i8 %6, %8
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop53, %strcmp.loop49, %strcmp.loop45, %strcmp.loop41, %strcmp.loop37, %strcmp.loop33, %strcmp.loop29, %strcmp.loop25, %strcmp.loop21, %strcmp.loop17, %strcmp.loop13, %strcmp.loop9, %strcmp.loop5, %strcmp.loop1, %strcmp.loop, %lookup_str_merge
  %9 = load i1, ptr %strcmp.result, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %strcmp.result)
  %10 = zext i1 %9 to i64
  %predcond = icmp eq i64 %10, 0
  br i1 %predcond, label %pred_false, label %pred_true

strcmp.done:                                      ; preds = %strcmp.loop57, %strcmp.loop_null_cmp58, %strcmp.loop_null_cmp54, %strcmp.loop_null_cmp50, %strcmp.loop_null_cmp46, %strcmp.loop_null_cmp42, %strcmp.loop_null_cmp38, %strcmp.loop_null_cmp34, %strcmp.loop_null_cmp30, %strcmp.loop_null_cmp26, %strcmp.loop_null_cmp22, %strcmp.loop_null_cmp18, %strcmp.loop_null_cmp14, %strcmp.loop_null_cmp10, %strcmp.loop_null_cmp6, %strcmp.loop_null_cmp2, %strcmp.loop_null_cmp
  store i1 true, ptr %strcmp.result, align 1
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %11 = getelementptr i8, ptr %lookup_str_map, i32 1
  %12 = load i8, ptr %11, align 1
  %13 = getelementptr i8, ptr %comm, i32 1
  %14 = load i8, ptr %13, align 1
  %strcmp.cmp3 = icmp ne i8 %12, %14
  br i1 %strcmp.cmp3, label %strcmp.false, label %strcmp.loop_null_cmp2

strcmp.loop_null_cmp:                             ; preds = %lookup_str_merge
  %strcmp.cmp_null = icmp eq i8 %6, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop1:                                     ; preds = %strcmp.loop_null_cmp2
  %15 = getelementptr i8, ptr %lookup_str_map, i32 2
  %16 = load i8, ptr %15, align 1
  %17 = getelementptr i8, ptr %comm, i32 2
  %18 = load i8, ptr %17, align 1
  %strcmp.cmp7 = icmp ne i8 %16, %18
  br i1 %strcmp.cmp7, label %strcmp.false, label %strcmp.loop_null_cmp6

strcmp.loop_null_cmp2:                            ; preds = %strcmp.loop
  %strcmp.cmp_null4 = icmp eq i8 %12, 0
  br i1 %strcmp.cmp_null4, label %strcmp.done, label %strcmp.loop1

strcmp.loop5:                                     ; preds = %strcmp.loop_null_cmp6
  %19 = getelementptr i8, ptr %lookup_str_map, i32 3
  %20 = load i8, ptr %19, align 1
  %21 = getelementptr i8, ptr %comm, i32 3
  %22 = load i8, ptr %21, align 1
  %strcmp.cmp11 = icmp ne i8 %20, %22
  br i1 %strcmp.cmp11, label %strcmp.false, label %strcmp.loop_null_cmp10

strcmp.loop_null_cmp6:                            ; preds = %strcmp.loop1
  %strcmp.cmp_null8 = icmp eq i8 %16, 0
  br i1 %strcmp.cmp_null8, label %strcmp.done, label %strcmp.loop5

strcmp.loop9:                                     ; preds = %strcmp.loop_null_cmp10
  %23 = getelementptr i8, ptr %lookup_str_map, i32 4
  %24 = load i8, ptr %23, align 1
  %25 = getelementptr i8, ptr %comm, i32 4
  %26 = load i8, ptr %25, align 1
  %strcmp.cmp15 = icmp ne i8 %24, %26
  br i1 %strcmp.cmp15, label %strcmp.false, label %strcmp.loop_null_cmp14

strcmp.loop_null_cmp10:                           ; preds = %strcmp.loop5
  %strcmp.cmp_null12 = icmp eq i8 %20, 0
  br i1 %strcmp.cmp_null12, label %strcmp.done, label %strcmp.loop9

strcmp.loop13:                                    ; preds = %strcmp.loop_null_cmp14
  %27 = getelementptr i8, ptr %lookup_str_map, i32 5
  %28 = load i8, ptr %27, align 1
  %29 = getelementptr i8, ptr %comm, i32 5
  %30 = load i8, ptr %29, align 1
  %strcmp.cmp19 = icmp ne i8 %28, %30
  br i1 %strcmp.cmp19, label %strcmp.false, label %strcmp.loop_null_cmp18

strcmp.loop_null_cmp14:                           ; preds = %strcmp.loop9
  %strcmp.cmp_null16 = icmp eq i8 %24, 0
  br i1 %strcmp.cmp_null16, label %strcmp.done, label %strcmp.loop13

strcmp.loop17:                                    ; preds = %strcmp.loop_null_cmp18
  %31 = getelementptr i8, ptr %lookup_str_map, i32 6
  %32 = load i8, ptr %31, align 1
  %33 = getelementptr i8, ptr %comm, i32 6
  %34 = load i8, ptr %33, align 1
  %strcmp.cmp23 = icmp ne i8 %32, %34
  br i1 %strcmp.cmp23, label %strcmp.false, label %strcmp.loop_null_cmp22

strcmp.loop_null_cmp18:                           ; preds = %strcmp.loop13
  %strcmp.cmp_null20 = icmp eq i8 %28, 0
  br i1 %strcmp.cmp_null20, label %strcmp.done, label %strcmp.loop17

strcmp.loop21:                                    ; preds = %strcmp.loop_null_cmp22
  %35 = getelementptr i8, ptr %lookup_str_map, i32 7
  %36 = load i8, ptr %35, align 1
  %37 = getelementptr i8, ptr %comm, i32 7
  %38 = load i8, ptr %37, align 1
  %strcmp.cmp27 = icmp ne i8 %36, %38
  br i1 %strcmp.cmp27, label %strcmp.false, label %strcmp.loop_null_cmp26

strcmp.loop_null_cmp22:                           ; preds = %strcmp.loop17
  %strcmp.cmp_null24 = icmp eq i8 %32, 0
  br i1 %strcmp.cmp_null24, label %strcmp.done, label %strcmp.loop21

strcmp.loop25:                                    ; preds = %strcmp.loop_null_cmp26
  %39 = getelementptr i8, ptr %lookup_str_map, i32 8
  %40 = load i8, ptr %39, align 1
  %41 = getelementptr i8, ptr %comm, i32 8
  %42 = load i8, ptr %41, align 1
  %strcmp.cmp31 = icmp ne i8 %40, %42
  br i1 %strcmp.cmp31, label %strcmp.false, label %strcmp.loop_null_cmp30

strcmp.loop_null_cmp26:                           ; preds = %strcmp.loop21
  %strcmp.cmp_null28 = icmp eq i8 %36, 0
  br i1 %strcmp.cmp_null28, label %strcmp.done, label %strcmp.loop25

strcmp.loop29:                                    ; preds = %strcmp.loop_null_cmp30
  %43 = getelementptr i8, ptr %lookup_str_map, i32 9
  %44 = load i8, ptr %43, align 1
  %45 = getelementptr i8, ptr %comm, i32 9
  %46 = load i8, ptr %45, align 1
  %strcmp.cmp35 = icmp ne i8 %44, %46
  br i1 %strcmp.cmp35, label %strcmp.false, label %strcmp.loop_null_cmp34

strcmp.loop_null_cmp30:                           ; preds = %strcmp.loop25
  %strcmp.cmp_null32 = icmp eq i8 %40, 0
  br i1 %strcmp.cmp_null32, label %strcmp.done, label %strcmp.loop29

strcmp.loop33:                                    ; preds = %strcmp.loop_null_cmp34
  %47 = getelementptr i8, ptr %lookup_str_map, i32 10
  %48 = load i8, ptr %47, align 1
  %49 = getelementptr i8, ptr %comm, i32 10
  %50 = load i8, ptr %49, align 1
  %strcmp.cmp39 = icmp ne i8 %48, %50
  br i1 %strcmp.cmp39, label %strcmp.false, label %strcmp.loop_null_cmp38

strcmp.loop_null_cmp34:                           ; preds = %strcmp.loop29
  %strcmp.cmp_null36 = icmp eq i8 %44, 0
  br i1 %strcmp.cmp_null36, label %strcmp.done, label %strcmp.loop33

strcmp.loop37:                                    ; preds = %strcmp.loop_null_cmp38
  %51 = getelementptr i8, ptr %lookup_str_map, i32 11
  %52 = load i8, ptr %51, align 1
  %53 = getelementptr i8, ptr %comm, i32 11
  %54 = load i8, ptr %53, align 1
  %strcmp.cmp43 = icmp ne i8 %52, %54
  br i1 %strcmp.cmp43, label %strcmp.false, label %strcmp.loop_null_cmp42

strcmp.loop_null_cmp38:                           ; preds = %strcmp.loop33
  %strcmp.cmp_null40 = icmp eq i8 %48, 0
  br i1 %strcmp.cmp_null40, label %strcmp.done, label %strcmp.loop37

strcmp.loop41:                                    ; preds = %strcmp.loop_null_cmp42
  %55 = getelementptr i8, ptr %lookup_str_map, i32 12
  %56 = load i8, ptr %55, align 1
  %57 = getelementptr i8, ptr %comm, i32 12
  %58 = load i8, ptr %57, align 1
  %strcmp.cmp47 = icmp ne i8 %56, %58
  br i1 %strcmp.cmp47, label %strcmp.false, label %strcmp.loop_null_cmp46

strcmp.loop_null_cmp42:                           ; preds = %strcmp.loop37
  %strcmp.cmp_null44 = icmp eq i8 %52, 0
  br i1 %strcmp.cmp_null44, label %strcmp.done, label %strcmp.loop41

strcmp.loop45:                                    ; preds = %strcmp.loop_null_cmp46
  %59 = getelementptr i8, ptr %lookup_str_map, i32 13
  %60 = load i8, ptr %59, align 1
  %61 = getelementptr i8, ptr %comm, i32 13
  %62 = load i8, ptr %61, align 1
  %strcmp.cmp51 = icmp ne i8 %60, %62
  br i1 %strcmp.cmp51, label %strcmp.false, label %strcmp.loop_null_cmp50

strcmp.loop_null_cmp46:                           ; preds = %strcmp.loop41
  %strcmp.cmp_null48 = icmp eq i8 %56, 0
  br i1 %strcmp.cmp_null48, label %strcmp.done, label %strcmp.loop45

strcmp.loop49:                                    ; preds = %strcmp.loop_null_cmp50
  %63 = getelementptr i8, ptr %lookup_str_map, i32 14
  %64 = load i8, ptr %63, align 1
  %65 = getelementptr i8, ptr %comm, i32 14
  %66 = load i8, ptr %65, align 1
  %strcmp.cmp55 = icmp ne i8 %64, %66
  br i1 %strcmp.cmp55, label %strcmp.false, label %strcmp.loop_null_cmp54

strcmp.loop_null_cmp50:                           ; preds = %strcmp.loop45
  %strcmp.cmp_null52 = icmp eq i8 %60, 0
  br i1 %strcmp.cmp_null52, label %strcmp.done, label %strcmp.loop49

strcmp.loop53:                                    ; preds = %strcmp.loop_null_cmp54
  %67 = getelementptr i8, ptr %lookup_str_map, i32 15
  %68 = load i8, ptr %67, align 1
  %69 = getelementptr i8, ptr %comm, i32 15
  %70 = load i8, ptr %69, align 1
  %strcmp.cmp59 = icmp ne i8 %68, %70
  br i1 %strcmp.cmp59, label %strcmp.false, label %strcmp.loop_null_cmp58

strcmp.loop_null_cmp54:                           ; preds = %strcmp.loop49
  %strcmp.cmp_null56 = icmp eq i8 %64, 0
  br i1 %strcmp.cmp_null56, label %strcmp.done, label %strcmp.loop53

strcmp.loop57:                                    ; preds = %strcmp.loop_null_cmp58
  br label %strcmp.done

strcmp.loop_null_cmp58:                           ; preds = %strcmp.loop53
  %strcmp.cmp_null60 = icmp eq i8 %68, 0
  br i1 %strcmp.cmp_null60, label %strcmp.done, label %strcmp.loop57
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!53}
!llvm.module.flags = !{!55}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 2, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 1, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !20, size: 64, offset: 192)
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!21 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !25)
!25 = !{!26, !31}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 27, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !32, size: 64, offset: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 262144, lowerBound: 0)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "str_buffer", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !39)
!39 = !{!40, !11, !16, !45}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 6, lowerBound: 0)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !46, size: 64, offset: 192)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !48, size: 512, elements: !49)
!48 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!49 = !{!50}
!50 = !DISubrange(count: 64, lowerBound: 0)
!51 = !DIGlobalVariableExpression(var: !52, expr: !DIExpression())
!52 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!53 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !54)
!54 = !{!0, !22, !36, !51}
!55 = !{i32 2, !"Debug Info Version", i32 3}
!56 = distinct !DISubprogram(name: "tracepoint_file_filename_1", linkageName: "tracepoint_file_filename_1", scope: !2, file: !2, type: !57, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !53, retainedNodes: !60)
!57 = !DISubroutineType(types: !58)
!58 = !{!21, !59}
!59 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !48, size: 64)
!60 = !{!61}
!61 = !DILocalVariable(name: "ctx", arg: 1, scope: !56, file: !2, type: !59)
