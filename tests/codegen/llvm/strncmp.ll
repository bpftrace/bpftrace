; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@ringbuf_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @tracepoint_file_filename_1(i8* %0) section "s_tracepoint_file_filename_1" !dbg !51 {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %strcmp.result = alloca i1, align 1
  %comm = alloca [16 x i8], align 1
  %str = alloca [64 x i8], align 1
  %1 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 64, i1 false)
  %3 = ptrtoint i8* %0 to i64
  %4 = add i64 %3, 8
  %5 = inttoptr i64 %4 to i64*
  %6 = load volatile i64, i64* %5, align 8
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 64, i64 %6)
  %7 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %8 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %8, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 ([16 x i8]*, i64)*)([16 x i8]* %comm, i64 16)
  %9 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i1 false, i1* %strcmp.result, align 1
  %10 = bitcast [64 x i8]* %str to i8*
  %11 = getelementptr i8, i8* %10, i32 0
  %12 = load i8, i8* %11, align 1
  %13 = bitcast [16 x i8]* %comm to i8*
  %14 = getelementptr i8, i8* %13, i32 0
  %15 = load i8, i8* %14, align 1
  %strcmp.cmp = icmp ne i8 %12, %15
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

pred_false:                                       ; preds = %strcmp.false
  ret i64 1

pred_true:                                        ; preds = %strcmp.false
  %16 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  store i64 0, i64* %"@_key", align 8
  %18 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i64 1, i64* %"@_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_, i64* %"@_key", i64* %"@_val", i64 0)
  %19 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  ret i64 1

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop53, %strcmp.loop49, %strcmp.loop45, %strcmp.loop41, %strcmp.loop37, %strcmp.loop33, %strcmp.loop29, %strcmp.loop25, %strcmp.loop21, %strcmp.loop17, %strcmp.loop13, %strcmp.loop9, %strcmp.loop5, %strcmp.loop1, %strcmp.loop, %entry
  %21 = load i1, i1* %strcmp.result, align 1
  %22 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  %23 = zext i1 %21 to i64
  %predcond = icmp eq i64 %23, 0
  br i1 %predcond, label %pred_false, label %pred_true

strcmp.done:                                      ; preds = %strcmp.loop57, %strcmp.loop_null_cmp58, %strcmp.loop_null_cmp54, %strcmp.loop_null_cmp50, %strcmp.loop_null_cmp46, %strcmp.loop_null_cmp42, %strcmp.loop_null_cmp38, %strcmp.loop_null_cmp34, %strcmp.loop_null_cmp30, %strcmp.loop_null_cmp26, %strcmp.loop_null_cmp22, %strcmp.loop_null_cmp18, %strcmp.loop_null_cmp14, %strcmp.loop_null_cmp10, %strcmp.loop_null_cmp6, %strcmp.loop_null_cmp2, %strcmp.loop_null_cmp
  store i1 true, i1* %strcmp.result, align 1
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %24 = bitcast [64 x i8]* %str to i8*
  %25 = getelementptr i8, i8* %24, i32 1
  %26 = load i8, i8* %25, align 1
  %27 = bitcast [16 x i8]* %comm to i8*
  %28 = getelementptr i8, i8* %27, i32 1
  %29 = load i8, i8* %28, align 1
  %strcmp.cmp3 = icmp ne i8 %26, %29
  br i1 %strcmp.cmp3, label %strcmp.false, label %strcmp.loop_null_cmp2

strcmp.loop_null_cmp:                             ; preds = %entry
  %strcmp.cmp_null = icmp eq i8 %12, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop1:                                     ; preds = %strcmp.loop_null_cmp2
  %30 = bitcast [64 x i8]* %str to i8*
  %31 = getelementptr i8, i8* %30, i32 2
  %32 = load i8, i8* %31, align 1
  %33 = bitcast [16 x i8]* %comm to i8*
  %34 = getelementptr i8, i8* %33, i32 2
  %35 = load i8, i8* %34, align 1
  %strcmp.cmp7 = icmp ne i8 %32, %35
  br i1 %strcmp.cmp7, label %strcmp.false, label %strcmp.loop_null_cmp6

strcmp.loop_null_cmp2:                            ; preds = %strcmp.loop
  %strcmp.cmp_null4 = icmp eq i8 %26, 0
  br i1 %strcmp.cmp_null4, label %strcmp.done, label %strcmp.loop1

strcmp.loop5:                                     ; preds = %strcmp.loop_null_cmp6
  %36 = bitcast [64 x i8]* %str to i8*
  %37 = getelementptr i8, i8* %36, i32 3
  %38 = load i8, i8* %37, align 1
  %39 = bitcast [16 x i8]* %comm to i8*
  %40 = getelementptr i8, i8* %39, i32 3
  %41 = load i8, i8* %40, align 1
  %strcmp.cmp11 = icmp ne i8 %38, %41
  br i1 %strcmp.cmp11, label %strcmp.false, label %strcmp.loop_null_cmp10

strcmp.loop_null_cmp6:                            ; preds = %strcmp.loop1
  %strcmp.cmp_null8 = icmp eq i8 %32, 0
  br i1 %strcmp.cmp_null8, label %strcmp.done, label %strcmp.loop5

strcmp.loop9:                                     ; preds = %strcmp.loop_null_cmp10
  %42 = bitcast [64 x i8]* %str to i8*
  %43 = getelementptr i8, i8* %42, i32 4
  %44 = load i8, i8* %43, align 1
  %45 = bitcast [16 x i8]* %comm to i8*
  %46 = getelementptr i8, i8* %45, i32 4
  %47 = load i8, i8* %46, align 1
  %strcmp.cmp15 = icmp ne i8 %44, %47
  br i1 %strcmp.cmp15, label %strcmp.false, label %strcmp.loop_null_cmp14

strcmp.loop_null_cmp10:                           ; preds = %strcmp.loop5
  %strcmp.cmp_null12 = icmp eq i8 %38, 0
  br i1 %strcmp.cmp_null12, label %strcmp.done, label %strcmp.loop9

strcmp.loop13:                                    ; preds = %strcmp.loop_null_cmp14
  %48 = bitcast [64 x i8]* %str to i8*
  %49 = getelementptr i8, i8* %48, i32 5
  %50 = load i8, i8* %49, align 1
  %51 = bitcast [16 x i8]* %comm to i8*
  %52 = getelementptr i8, i8* %51, i32 5
  %53 = load i8, i8* %52, align 1
  %strcmp.cmp19 = icmp ne i8 %50, %53
  br i1 %strcmp.cmp19, label %strcmp.false, label %strcmp.loop_null_cmp18

strcmp.loop_null_cmp14:                           ; preds = %strcmp.loop9
  %strcmp.cmp_null16 = icmp eq i8 %44, 0
  br i1 %strcmp.cmp_null16, label %strcmp.done, label %strcmp.loop13

strcmp.loop17:                                    ; preds = %strcmp.loop_null_cmp18
  %54 = bitcast [64 x i8]* %str to i8*
  %55 = getelementptr i8, i8* %54, i32 6
  %56 = load i8, i8* %55, align 1
  %57 = bitcast [16 x i8]* %comm to i8*
  %58 = getelementptr i8, i8* %57, i32 6
  %59 = load i8, i8* %58, align 1
  %strcmp.cmp23 = icmp ne i8 %56, %59
  br i1 %strcmp.cmp23, label %strcmp.false, label %strcmp.loop_null_cmp22

strcmp.loop_null_cmp18:                           ; preds = %strcmp.loop13
  %strcmp.cmp_null20 = icmp eq i8 %50, 0
  br i1 %strcmp.cmp_null20, label %strcmp.done, label %strcmp.loop17

strcmp.loop21:                                    ; preds = %strcmp.loop_null_cmp22
  %60 = bitcast [64 x i8]* %str to i8*
  %61 = getelementptr i8, i8* %60, i32 7
  %62 = load i8, i8* %61, align 1
  %63 = bitcast [16 x i8]* %comm to i8*
  %64 = getelementptr i8, i8* %63, i32 7
  %65 = load i8, i8* %64, align 1
  %strcmp.cmp27 = icmp ne i8 %62, %65
  br i1 %strcmp.cmp27, label %strcmp.false, label %strcmp.loop_null_cmp26

strcmp.loop_null_cmp22:                           ; preds = %strcmp.loop17
  %strcmp.cmp_null24 = icmp eq i8 %56, 0
  br i1 %strcmp.cmp_null24, label %strcmp.done, label %strcmp.loop21

strcmp.loop25:                                    ; preds = %strcmp.loop_null_cmp26
  %66 = bitcast [64 x i8]* %str to i8*
  %67 = getelementptr i8, i8* %66, i32 8
  %68 = load i8, i8* %67, align 1
  %69 = bitcast [16 x i8]* %comm to i8*
  %70 = getelementptr i8, i8* %69, i32 8
  %71 = load i8, i8* %70, align 1
  %strcmp.cmp31 = icmp ne i8 %68, %71
  br i1 %strcmp.cmp31, label %strcmp.false, label %strcmp.loop_null_cmp30

strcmp.loop_null_cmp26:                           ; preds = %strcmp.loop21
  %strcmp.cmp_null28 = icmp eq i8 %62, 0
  br i1 %strcmp.cmp_null28, label %strcmp.done, label %strcmp.loop25

strcmp.loop29:                                    ; preds = %strcmp.loop_null_cmp30
  %72 = bitcast [64 x i8]* %str to i8*
  %73 = getelementptr i8, i8* %72, i32 9
  %74 = load i8, i8* %73, align 1
  %75 = bitcast [16 x i8]* %comm to i8*
  %76 = getelementptr i8, i8* %75, i32 9
  %77 = load i8, i8* %76, align 1
  %strcmp.cmp35 = icmp ne i8 %74, %77
  br i1 %strcmp.cmp35, label %strcmp.false, label %strcmp.loop_null_cmp34

strcmp.loop_null_cmp30:                           ; preds = %strcmp.loop25
  %strcmp.cmp_null32 = icmp eq i8 %68, 0
  br i1 %strcmp.cmp_null32, label %strcmp.done, label %strcmp.loop29

strcmp.loop33:                                    ; preds = %strcmp.loop_null_cmp34
  %78 = bitcast [64 x i8]* %str to i8*
  %79 = getelementptr i8, i8* %78, i32 10
  %80 = load i8, i8* %79, align 1
  %81 = bitcast [16 x i8]* %comm to i8*
  %82 = getelementptr i8, i8* %81, i32 10
  %83 = load i8, i8* %82, align 1
  %strcmp.cmp39 = icmp ne i8 %80, %83
  br i1 %strcmp.cmp39, label %strcmp.false, label %strcmp.loop_null_cmp38

strcmp.loop_null_cmp34:                           ; preds = %strcmp.loop29
  %strcmp.cmp_null36 = icmp eq i8 %74, 0
  br i1 %strcmp.cmp_null36, label %strcmp.done, label %strcmp.loop33

strcmp.loop37:                                    ; preds = %strcmp.loop_null_cmp38
  %84 = bitcast [64 x i8]* %str to i8*
  %85 = getelementptr i8, i8* %84, i32 11
  %86 = load i8, i8* %85, align 1
  %87 = bitcast [16 x i8]* %comm to i8*
  %88 = getelementptr i8, i8* %87, i32 11
  %89 = load i8, i8* %88, align 1
  %strcmp.cmp43 = icmp ne i8 %86, %89
  br i1 %strcmp.cmp43, label %strcmp.false, label %strcmp.loop_null_cmp42

strcmp.loop_null_cmp38:                           ; preds = %strcmp.loop33
  %strcmp.cmp_null40 = icmp eq i8 %80, 0
  br i1 %strcmp.cmp_null40, label %strcmp.done, label %strcmp.loop37

strcmp.loop41:                                    ; preds = %strcmp.loop_null_cmp42
  %90 = bitcast [64 x i8]* %str to i8*
  %91 = getelementptr i8, i8* %90, i32 12
  %92 = load i8, i8* %91, align 1
  %93 = bitcast [16 x i8]* %comm to i8*
  %94 = getelementptr i8, i8* %93, i32 12
  %95 = load i8, i8* %94, align 1
  %strcmp.cmp47 = icmp ne i8 %92, %95
  br i1 %strcmp.cmp47, label %strcmp.false, label %strcmp.loop_null_cmp46

strcmp.loop_null_cmp42:                           ; preds = %strcmp.loop37
  %strcmp.cmp_null44 = icmp eq i8 %86, 0
  br i1 %strcmp.cmp_null44, label %strcmp.done, label %strcmp.loop41

strcmp.loop45:                                    ; preds = %strcmp.loop_null_cmp46
  %96 = bitcast [64 x i8]* %str to i8*
  %97 = getelementptr i8, i8* %96, i32 13
  %98 = load i8, i8* %97, align 1
  %99 = bitcast [16 x i8]* %comm to i8*
  %100 = getelementptr i8, i8* %99, i32 13
  %101 = load i8, i8* %100, align 1
  %strcmp.cmp51 = icmp ne i8 %98, %101
  br i1 %strcmp.cmp51, label %strcmp.false, label %strcmp.loop_null_cmp50

strcmp.loop_null_cmp46:                           ; preds = %strcmp.loop41
  %strcmp.cmp_null48 = icmp eq i8 %92, 0
  br i1 %strcmp.cmp_null48, label %strcmp.done, label %strcmp.loop45

strcmp.loop49:                                    ; preds = %strcmp.loop_null_cmp50
  %102 = bitcast [64 x i8]* %str to i8*
  %103 = getelementptr i8, i8* %102, i32 14
  %104 = load i8, i8* %103, align 1
  %105 = bitcast [16 x i8]* %comm to i8*
  %106 = getelementptr i8, i8* %105, i32 14
  %107 = load i8, i8* %106, align 1
  %strcmp.cmp55 = icmp ne i8 %104, %107
  br i1 %strcmp.cmp55, label %strcmp.false, label %strcmp.loop_null_cmp54

strcmp.loop_null_cmp50:                           ; preds = %strcmp.loop45
  %strcmp.cmp_null52 = icmp eq i8 %98, 0
  br i1 %strcmp.cmp_null52, label %strcmp.done, label %strcmp.loop49

strcmp.loop53:                                    ; preds = %strcmp.loop_null_cmp54
  %108 = bitcast [64 x i8]* %str to i8*
  %109 = getelementptr i8, i8* %108, i32 15
  %110 = load i8, i8* %109, align 1
  %111 = bitcast [16 x i8]* %comm to i8*
  %112 = getelementptr i8, i8* %111, i32 15
  %113 = load i8, i8* %112, align 1
  %strcmp.cmp59 = icmp ne i8 %110, %113
  br i1 %strcmp.cmp59, label %strcmp.false, label %strcmp.loop_null_cmp58

strcmp.loop_null_cmp54:                           ; preds = %strcmp.loop49
  %strcmp.cmp_null56 = icmp eq i8 %104, 0
  br i1 %strcmp.cmp_null56, label %strcmp.done, label %strcmp.loop53

strcmp.loop57:                                    ; preds = %strcmp.loop_null_cmp58
  br label %strcmp.done

strcmp.loop_null_cmp58:                           ; preds = %strcmp.loop53
  %strcmp.cmp_null60 = icmp eq i8 %110, 0
  br i1 %strcmp.cmp_null60, label %strcmp.done, label %strcmp.loop57
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!47}
!llvm.module.flags = !{!50}

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
!35 = distinct !DIGlobalVariable(name: "ringbuf_loss_counter", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
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
!47 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !48, globals: !49)
!48 = !{}
!49 = !{!0, !20, !34}
!50 = !{i32 2, !"Debug Info Version", i32 3}
!51 = distinct !DISubprogram(name: "tracepoint_file_filename_1", linkageName: "tracepoint_file_filename_1", scope: !2, file: !2, type: !52, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !47, retainedNodes: !56)
!52 = !DISubroutineType(types: !53)
!53 = !{!18, !54}
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!56 = !{!57}
!57 = !DILocalVariable(name: "ctx", arg: 1, scope: !51, file: !2, type: !54)
