; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%"struct map_t.2" = type { i8*, i8*, i8*, i8* }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@str_buffer = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !53

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @tracepoint_file_filename_1(i8* %0) section "s_tracepoint_file_filename_1" !dbg !66 {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %strcmp.result = alloca i1, align 1
  %comm = alloca [16 x i8], align 1
  %lookup_str_key = alloca i32, align 4
  %1 = bitcast i32* %lookup_str_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i32 0, i32* %lookup_str_key, align 4
  %lookup_str_map = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @str_buffer, i32* %lookup_str_key)
  %2 = bitcast i32* %lookup_str_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %2)
  %lookup_str_cond = icmp ne i8* %lookup_str_map, null
  br i1 %lookup_str_cond, label %lookup_str_merge, label %lookup_str_failure

pred_false:                                       ; preds = %strcmp.false
  ret i64 1

pred_true:                                        ; preds = %strcmp.false
  %3 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i64 0, i64* %"@_key", align 8
  %5 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 1, i64* %"@_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_, i64* %"@_key", i64* %"@_val", i64 0)
  %6 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  ret i64 1

lookup_str_failure:                               ; preds = %entry
  ret i64 0

lookup_str_merge:                                 ; preds = %entry
  call void @llvm.memset.p0i8.i64(i8* align 1 %lookup_str_map, i8 0, i64 64, i1 false)
  %8 = ptrtoint i8* %0 to i64
  %9 = add i64 %8, 8
  %10 = inttoptr i64 %9 to i64*
  %11 = load volatile i64, i64* %10, align 8
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %lookup_str_map, i32 64, i64 %11)
  %12 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  %13 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %13, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 ([16 x i8]*, i64)*)([16 x i8]* %comm, i64 16)
  %14 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i1 false, i1* %strcmp.result, align 1
  %15 = getelementptr i8, i8* %lookup_str_map, i32 0
  %16 = load i8, i8* %15, align 1
  %17 = bitcast [16 x i8]* %comm to i8*
  %18 = getelementptr i8, i8* %17, i32 0
  %19 = load i8, i8* %18, align 1
  %strcmp.cmp = icmp ne i8 %16, %19
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop53, %strcmp.loop49, %strcmp.loop45, %strcmp.loop41, %strcmp.loop37, %strcmp.loop33, %strcmp.loop29, %strcmp.loop25, %strcmp.loop21, %strcmp.loop17, %strcmp.loop13, %strcmp.loop9, %strcmp.loop5, %strcmp.loop1, %strcmp.loop, %lookup_str_merge
  %20 = load i1, i1* %strcmp.result, align 1
  %21 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = zext i1 %20 to i64
  %predcond = icmp eq i64 %22, 0
  br i1 %predcond, label %pred_false, label %pred_true

strcmp.done:                                      ; preds = %strcmp.loop57, %strcmp.loop_null_cmp58, %strcmp.loop_null_cmp54, %strcmp.loop_null_cmp50, %strcmp.loop_null_cmp46, %strcmp.loop_null_cmp42, %strcmp.loop_null_cmp38, %strcmp.loop_null_cmp34, %strcmp.loop_null_cmp30, %strcmp.loop_null_cmp26, %strcmp.loop_null_cmp22, %strcmp.loop_null_cmp18, %strcmp.loop_null_cmp14, %strcmp.loop_null_cmp10, %strcmp.loop_null_cmp6, %strcmp.loop_null_cmp2, %strcmp.loop_null_cmp
  store i1 true, i1* %strcmp.result, align 1
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %23 = getelementptr i8, i8* %lookup_str_map, i32 1
  %24 = load i8, i8* %23, align 1
  %25 = bitcast [16 x i8]* %comm to i8*
  %26 = getelementptr i8, i8* %25, i32 1
  %27 = load i8, i8* %26, align 1
  %strcmp.cmp3 = icmp ne i8 %24, %27
  br i1 %strcmp.cmp3, label %strcmp.false, label %strcmp.loop_null_cmp2

strcmp.loop_null_cmp:                             ; preds = %lookup_str_merge
  %strcmp.cmp_null = icmp eq i8 %16, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop1:                                     ; preds = %strcmp.loop_null_cmp2
  %28 = getelementptr i8, i8* %lookup_str_map, i32 2
  %29 = load i8, i8* %28, align 1
  %30 = bitcast [16 x i8]* %comm to i8*
  %31 = getelementptr i8, i8* %30, i32 2
  %32 = load i8, i8* %31, align 1
  %strcmp.cmp7 = icmp ne i8 %29, %32
  br i1 %strcmp.cmp7, label %strcmp.false, label %strcmp.loop_null_cmp6

strcmp.loop_null_cmp2:                            ; preds = %strcmp.loop
  %strcmp.cmp_null4 = icmp eq i8 %24, 0
  br i1 %strcmp.cmp_null4, label %strcmp.done, label %strcmp.loop1

strcmp.loop5:                                     ; preds = %strcmp.loop_null_cmp6
  %33 = getelementptr i8, i8* %lookup_str_map, i32 3
  %34 = load i8, i8* %33, align 1
  %35 = bitcast [16 x i8]* %comm to i8*
  %36 = getelementptr i8, i8* %35, i32 3
  %37 = load i8, i8* %36, align 1
  %strcmp.cmp11 = icmp ne i8 %34, %37
  br i1 %strcmp.cmp11, label %strcmp.false, label %strcmp.loop_null_cmp10

strcmp.loop_null_cmp6:                            ; preds = %strcmp.loop1
  %strcmp.cmp_null8 = icmp eq i8 %29, 0
  br i1 %strcmp.cmp_null8, label %strcmp.done, label %strcmp.loop5

strcmp.loop9:                                     ; preds = %strcmp.loop_null_cmp10
  %38 = getelementptr i8, i8* %lookup_str_map, i32 4
  %39 = load i8, i8* %38, align 1
  %40 = bitcast [16 x i8]* %comm to i8*
  %41 = getelementptr i8, i8* %40, i32 4
  %42 = load i8, i8* %41, align 1
  %strcmp.cmp15 = icmp ne i8 %39, %42
  br i1 %strcmp.cmp15, label %strcmp.false, label %strcmp.loop_null_cmp14

strcmp.loop_null_cmp10:                           ; preds = %strcmp.loop5
  %strcmp.cmp_null12 = icmp eq i8 %34, 0
  br i1 %strcmp.cmp_null12, label %strcmp.done, label %strcmp.loop9

strcmp.loop13:                                    ; preds = %strcmp.loop_null_cmp14
  %43 = getelementptr i8, i8* %lookup_str_map, i32 5
  %44 = load i8, i8* %43, align 1
  %45 = bitcast [16 x i8]* %comm to i8*
  %46 = getelementptr i8, i8* %45, i32 5
  %47 = load i8, i8* %46, align 1
  %strcmp.cmp19 = icmp ne i8 %44, %47
  br i1 %strcmp.cmp19, label %strcmp.false, label %strcmp.loop_null_cmp18

strcmp.loop_null_cmp14:                           ; preds = %strcmp.loop9
  %strcmp.cmp_null16 = icmp eq i8 %39, 0
  br i1 %strcmp.cmp_null16, label %strcmp.done, label %strcmp.loop13

strcmp.loop17:                                    ; preds = %strcmp.loop_null_cmp18
  %48 = getelementptr i8, i8* %lookup_str_map, i32 6
  %49 = load i8, i8* %48, align 1
  %50 = bitcast [16 x i8]* %comm to i8*
  %51 = getelementptr i8, i8* %50, i32 6
  %52 = load i8, i8* %51, align 1
  %strcmp.cmp23 = icmp ne i8 %49, %52
  br i1 %strcmp.cmp23, label %strcmp.false, label %strcmp.loop_null_cmp22

strcmp.loop_null_cmp18:                           ; preds = %strcmp.loop13
  %strcmp.cmp_null20 = icmp eq i8 %44, 0
  br i1 %strcmp.cmp_null20, label %strcmp.done, label %strcmp.loop17

strcmp.loop21:                                    ; preds = %strcmp.loop_null_cmp22
  %53 = getelementptr i8, i8* %lookup_str_map, i32 7
  %54 = load i8, i8* %53, align 1
  %55 = bitcast [16 x i8]* %comm to i8*
  %56 = getelementptr i8, i8* %55, i32 7
  %57 = load i8, i8* %56, align 1
  %strcmp.cmp27 = icmp ne i8 %54, %57
  br i1 %strcmp.cmp27, label %strcmp.false, label %strcmp.loop_null_cmp26

strcmp.loop_null_cmp22:                           ; preds = %strcmp.loop17
  %strcmp.cmp_null24 = icmp eq i8 %49, 0
  br i1 %strcmp.cmp_null24, label %strcmp.done, label %strcmp.loop21

strcmp.loop25:                                    ; preds = %strcmp.loop_null_cmp26
  %58 = getelementptr i8, i8* %lookup_str_map, i32 8
  %59 = load i8, i8* %58, align 1
  %60 = bitcast [16 x i8]* %comm to i8*
  %61 = getelementptr i8, i8* %60, i32 8
  %62 = load i8, i8* %61, align 1
  %strcmp.cmp31 = icmp ne i8 %59, %62
  br i1 %strcmp.cmp31, label %strcmp.false, label %strcmp.loop_null_cmp30

strcmp.loop_null_cmp26:                           ; preds = %strcmp.loop21
  %strcmp.cmp_null28 = icmp eq i8 %54, 0
  br i1 %strcmp.cmp_null28, label %strcmp.done, label %strcmp.loop25

strcmp.loop29:                                    ; preds = %strcmp.loop_null_cmp30
  %63 = getelementptr i8, i8* %lookup_str_map, i32 9
  %64 = load i8, i8* %63, align 1
  %65 = bitcast [16 x i8]* %comm to i8*
  %66 = getelementptr i8, i8* %65, i32 9
  %67 = load i8, i8* %66, align 1
  %strcmp.cmp35 = icmp ne i8 %64, %67
  br i1 %strcmp.cmp35, label %strcmp.false, label %strcmp.loop_null_cmp34

strcmp.loop_null_cmp30:                           ; preds = %strcmp.loop25
  %strcmp.cmp_null32 = icmp eq i8 %59, 0
  br i1 %strcmp.cmp_null32, label %strcmp.done, label %strcmp.loop29

strcmp.loop33:                                    ; preds = %strcmp.loop_null_cmp34
  %68 = getelementptr i8, i8* %lookup_str_map, i32 10
  %69 = load i8, i8* %68, align 1
  %70 = bitcast [16 x i8]* %comm to i8*
  %71 = getelementptr i8, i8* %70, i32 10
  %72 = load i8, i8* %71, align 1
  %strcmp.cmp39 = icmp ne i8 %69, %72
  br i1 %strcmp.cmp39, label %strcmp.false, label %strcmp.loop_null_cmp38

strcmp.loop_null_cmp34:                           ; preds = %strcmp.loop29
  %strcmp.cmp_null36 = icmp eq i8 %64, 0
  br i1 %strcmp.cmp_null36, label %strcmp.done, label %strcmp.loop33

strcmp.loop37:                                    ; preds = %strcmp.loop_null_cmp38
  %73 = getelementptr i8, i8* %lookup_str_map, i32 11
  %74 = load i8, i8* %73, align 1
  %75 = bitcast [16 x i8]* %comm to i8*
  %76 = getelementptr i8, i8* %75, i32 11
  %77 = load i8, i8* %76, align 1
  %strcmp.cmp43 = icmp ne i8 %74, %77
  br i1 %strcmp.cmp43, label %strcmp.false, label %strcmp.loop_null_cmp42

strcmp.loop_null_cmp38:                           ; preds = %strcmp.loop33
  %strcmp.cmp_null40 = icmp eq i8 %69, 0
  br i1 %strcmp.cmp_null40, label %strcmp.done, label %strcmp.loop37

strcmp.loop41:                                    ; preds = %strcmp.loop_null_cmp42
  %78 = getelementptr i8, i8* %lookup_str_map, i32 12
  %79 = load i8, i8* %78, align 1
  %80 = bitcast [16 x i8]* %comm to i8*
  %81 = getelementptr i8, i8* %80, i32 12
  %82 = load i8, i8* %81, align 1
  %strcmp.cmp47 = icmp ne i8 %79, %82
  br i1 %strcmp.cmp47, label %strcmp.false, label %strcmp.loop_null_cmp46

strcmp.loop_null_cmp42:                           ; preds = %strcmp.loop37
  %strcmp.cmp_null44 = icmp eq i8 %74, 0
  br i1 %strcmp.cmp_null44, label %strcmp.done, label %strcmp.loop41

strcmp.loop45:                                    ; preds = %strcmp.loop_null_cmp46
  %83 = getelementptr i8, i8* %lookup_str_map, i32 13
  %84 = load i8, i8* %83, align 1
  %85 = bitcast [16 x i8]* %comm to i8*
  %86 = getelementptr i8, i8* %85, i32 13
  %87 = load i8, i8* %86, align 1
  %strcmp.cmp51 = icmp ne i8 %84, %87
  br i1 %strcmp.cmp51, label %strcmp.false, label %strcmp.loop_null_cmp50

strcmp.loop_null_cmp46:                           ; preds = %strcmp.loop41
  %strcmp.cmp_null48 = icmp eq i8 %79, 0
  br i1 %strcmp.cmp_null48, label %strcmp.done, label %strcmp.loop45

strcmp.loop49:                                    ; preds = %strcmp.loop_null_cmp50
  %88 = getelementptr i8, i8* %lookup_str_map, i32 14
  %89 = load i8, i8* %88, align 1
  %90 = bitcast [16 x i8]* %comm to i8*
  %91 = getelementptr i8, i8* %90, i32 14
  %92 = load i8, i8* %91, align 1
  %strcmp.cmp55 = icmp ne i8 %89, %92
  br i1 %strcmp.cmp55, label %strcmp.false, label %strcmp.loop_null_cmp54

strcmp.loop_null_cmp50:                           ; preds = %strcmp.loop45
  %strcmp.cmp_null52 = icmp eq i8 %84, 0
  br i1 %strcmp.cmp_null52, label %strcmp.done, label %strcmp.loop49

strcmp.loop53:                                    ; preds = %strcmp.loop_null_cmp54
  %93 = getelementptr i8, i8* %lookup_str_map, i32 15
  %94 = load i8, i8* %93, align 1
  %95 = bitcast [16 x i8]* %comm to i8*
  %96 = getelementptr i8, i8* %95, i32 15
  %97 = load i8, i8* %96, align 1
  %strcmp.cmp59 = icmp ne i8 %94, %97
  br i1 %strcmp.cmp59, label %strcmp.false, label %strcmp.loop_null_cmp58

strcmp.loop_null_cmp54:                           ; preds = %strcmp.loop49
  %strcmp.cmp_null56 = icmp eq i8 %89, 0
  br i1 %strcmp.cmp_null56, label %strcmp.done, label %strcmp.loop53

strcmp.loop57:                                    ; preds = %strcmp.loop_null_cmp58
  br label %strcmp.done

strcmp.loop_null_cmp58:                           ; preds = %strcmp.loop53
  %strcmp.cmp_null60 = icmp eq i8 %94, 0
  br i1 %strcmp.cmp_null60, label %strcmp.done, label %strcmp.loop57
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
!1 = distinct !DIGlobalVariable(name: "AT_", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!35 = distinct !DIGlobalVariable(name: "str_buffer", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!36 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !37)
!37 = !{!38, !43, !44, !47}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !39, size: 64)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 6, lowerBound: 0)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !45, size: 64, offset: 128)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!47 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !48, size: 64, offset: 192)
!48 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !49, size: 64)
!49 = !DICompositeType(tag: DW_TAG_array_type, baseType: !50, size: 512, elements: !51)
!50 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!51 = !{!52}
!52 = !DISubrange(count: 64, lowerBound: 0)
!53 = !DIGlobalVariableExpression(var: !54, expr: !DIExpression())
!54 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !55, isLocal: false, isDefinition: true)
!55 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !56)
!56 = !{!57, !43, !44, !19}
!57 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !58, size: 64)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!59 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !60)
!60 = !{!61}
!61 = !DISubrange(count: 2, lowerBound: 0)
!62 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !63, globals: !64)
!63 = !{}
!64 = !{!0, !20, !34, !53}
!65 = !{i32 2, !"Debug Info Version", i32 3}
!66 = distinct !DISubprogram(name: "tracepoint_file_filename_1", linkageName: "tracepoint_file_filename_1", scope: !2, file: !2, type: !67, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !62, retainedNodes: !70)
!67 = !DISubroutineType(types: !68)
!68 = !{!18, !69}
!69 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!70 = !{!71}
!71 = !DILocalVariable(name: "ctx", arg: 1, scope: !66, file: !2, type: !69)
