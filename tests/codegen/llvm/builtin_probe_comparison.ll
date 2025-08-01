; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29
@"tracepoint:sched:sched_one" = global [27 x i8] c"tracepoint:sched:sched_one\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @tracepoint_sched_sched_one_1(ptr %0) #0 section "s_tracepoint_sched_sched_one_1" !dbg !35 {
entry:
  %strcmp.result = alloca i1, align 1
  %1 = alloca i8, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %1)
  call void @llvm.memset.p0.i64(ptr align 1 %1, i8 0, i64 1, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %strcmp.result)
  store i1 false, ptr %strcmp.result, align 1
  %2 = load i8, ptr @"tracepoint:sched:sched_one", align 1
  %3 = load i8, ptr @"tracepoint:sched:sched_one", align 1
  %strcmp.cmp = icmp ne i8 %2, %3
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

true:                                             ; preds = %strcmp.false
  store i8 1, ptr %1, align 1
  br label %done

false:                                            ; preds = %strcmp.false
  store i8 1, ptr %1, align 1
  br label %done

done:                                             ; preds = %false, %true
  call void @llvm.lifetime.end.p0(i64 -1, ptr %1)
  ret i64 1

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop97, %strcmp.loop93, %strcmp.loop89, %strcmp.loop85, %strcmp.loop81, %strcmp.loop77, %strcmp.loop73, %strcmp.loop69, %strcmp.loop65, %strcmp.loop61, %strcmp.loop57, %strcmp.loop53, %strcmp.loop49, %strcmp.loop45, %strcmp.loop41, %strcmp.loop37, %strcmp.loop33, %strcmp.loop29, %strcmp.loop25, %strcmp.loop21, %strcmp.loop17, %strcmp.loop13, %strcmp.loop9, %strcmp.loop5, %strcmp.loop1, %strcmp.loop, %entry
  %4 = load i1, ptr %strcmp.result, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %strcmp.result)
  %5 = zext i1 %4 to i64
  %cond = icmp ne i64 %5, 0
  br i1 %cond, label %true, label %false

strcmp.done:                                      ; preds = %strcmp.loop101, %strcmp.loop_null_cmp102, %strcmp.loop_null_cmp98, %strcmp.loop_null_cmp94, %strcmp.loop_null_cmp90, %strcmp.loop_null_cmp86, %strcmp.loop_null_cmp82, %strcmp.loop_null_cmp78, %strcmp.loop_null_cmp74, %strcmp.loop_null_cmp70, %strcmp.loop_null_cmp66, %strcmp.loop_null_cmp62, %strcmp.loop_null_cmp58, %strcmp.loop_null_cmp54, %strcmp.loop_null_cmp50, %strcmp.loop_null_cmp46, %strcmp.loop_null_cmp42, %strcmp.loop_null_cmp38, %strcmp.loop_null_cmp34, %strcmp.loop_null_cmp30, %strcmp.loop_null_cmp26, %strcmp.loop_null_cmp22, %strcmp.loop_null_cmp18, %strcmp.loop_null_cmp14, %strcmp.loop_null_cmp10, %strcmp.loop_null_cmp6, %strcmp.loop_null_cmp2, %strcmp.loop_null_cmp
  store i1 true, ptr %strcmp.result, align 1
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %6 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 1), align 1
  %7 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 1), align 1
  %strcmp.cmp3 = icmp ne i8 %6, %7
  br i1 %strcmp.cmp3, label %strcmp.false, label %strcmp.loop_null_cmp2

strcmp.loop_null_cmp:                             ; preds = %entry
  %strcmp.cmp_null = icmp eq i8 %2, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop1:                                     ; preds = %strcmp.loop_null_cmp2
  %8 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 2), align 1
  %9 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 2), align 1
  %strcmp.cmp7 = icmp ne i8 %8, %9
  br i1 %strcmp.cmp7, label %strcmp.false, label %strcmp.loop_null_cmp6

strcmp.loop_null_cmp2:                            ; preds = %strcmp.loop
  %strcmp.cmp_null4 = icmp eq i8 %6, 0
  br i1 %strcmp.cmp_null4, label %strcmp.done, label %strcmp.loop1

strcmp.loop5:                                     ; preds = %strcmp.loop_null_cmp6
  %10 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 3), align 1
  %11 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 3), align 1
  %strcmp.cmp11 = icmp ne i8 %10, %11
  br i1 %strcmp.cmp11, label %strcmp.false, label %strcmp.loop_null_cmp10

strcmp.loop_null_cmp6:                            ; preds = %strcmp.loop1
  %strcmp.cmp_null8 = icmp eq i8 %8, 0
  br i1 %strcmp.cmp_null8, label %strcmp.done, label %strcmp.loop5

strcmp.loop9:                                     ; preds = %strcmp.loop_null_cmp10
  %12 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 4), align 1
  %13 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 4), align 1
  %strcmp.cmp15 = icmp ne i8 %12, %13
  br i1 %strcmp.cmp15, label %strcmp.false, label %strcmp.loop_null_cmp14

strcmp.loop_null_cmp10:                           ; preds = %strcmp.loop5
  %strcmp.cmp_null12 = icmp eq i8 %10, 0
  br i1 %strcmp.cmp_null12, label %strcmp.done, label %strcmp.loop9

strcmp.loop13:                                    ; preds = %strcmp.loop_null_cmp14
  %14 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 5), align 1
  %15 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 5), align 1
  %strcmp.cmp19 = icmp ne i8 %14, %15
  br i1 %strcmp.cmp19, label %strcmp.false, label %strcmp.loop_null_cmp18

strcmp.loop_null_cmp14:                           ; preds = %strcmp.loop9
  %strcmp.cmp_null16 = icmp eq i8 %12, 0
  br i1 %strcmp.cmp_null16, label %strcmp.done, label %strcmp.loop13

strcmp.loop17:                                    ; preds = %strcmp.loop_null_cmp18
  %16 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 6), align 1
  %17 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 6), align 1
  %strcmp.cmp23 = icmp ne i8 %16, %17
  br i1 %strcmp.cmp23, label %strcmp.false, label %strcmp.loop_null_cmp22

strcmp.loop_null_cmp18:                           ; preds = %strcmp.loop13
  %strcmp.cmp_null20 = icmp eq i8 %14, 0
  br i1 %strcmp.cmp_null20, label %strcmp.done, label %strcmp.loop17

strcmp.loop21:                                    ; preds = %strcmp.loop_null_cmp22
  %18 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 7), align 1
  %19 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 7), align 1
  %strcmp.cmp27 = icmp ne i8 %18, %19
  br i1 %strcmp.cmp27, label %strcmp.false, label %strcmp.loop_null_cmp26

strcmp.loop_null_cmp22:                           ; preds = %strcmp.loop17
  %strcmp.cmp_null24 = icmp eq i8 %16, 0
  br i1 %strcmp.cmp_null24, label %strcmp.done, label %strcmp.loop21

strcmp.loop25:                                    ; preds = %strcmp.loop_null_cmp26
  %20 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 8), align 1
  %21 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 8), align 1
  %strcmp.cmp31 = icmp ne i8 %20, %21
  br i1 %strcmp.cmp31, label %strcmp.false, label %strcmp.loop_null_cmp30

strcmp.loop_null_cmp26:                           ; preds = %strcmp.loop21
  %strcmp.cmp_null28 = icmp eq i8 %18, 0
  br i1 %strcmp.cmp_null28, label %strcmp.done, label %strcmp.loop25

strcmp.loop29:                                    ; preds = %strcmp.loop_null_cmp30
  %22 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 9), align 1
  %23 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 9), align 1
  %strcmp.cmp35 = icmp ne i8 %22, %23
  br i1 %strcmp.cmp35, label %strcmp.false, label %strcmp.loop_null_cmp34

strcmp.loop_null_cmp30:                           ; preds = %strcmp.loop25
  %strcmp.cmp_null32 = icmp eq i8 %20, 0
  br i1 %strcmp.cmp_null32, label %strcmp.done, label %strcmp.loop29

strcmp.loop33:                                    ; preds = %strcmp.loop_null_cmp34
  %24 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 10), align 1
  %25 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 10), align 1
  %strcmp.cmp39 = icmp ne i8 %24, %25
  br i1 %strcmp.cmp39, label %strcmp.false, label %strcmp.loop_null_cmp38

strcmp.loop_null_cmp34:                           ; preds = %strcmp.loop29
  %strcmp.cmp_null36 = icmp eq i8 %22, 0
  br i1 %strcmp.cmp_null36, label %strcmp.done, label %strcmp.loop33

strcmp.loop37:                                    ; preds = %strcmp.loop_null_cmp38
  %26 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 11), align 1
  %27 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 11), align 1
  %strcmp.cmp43 = icmp ne i8 %26, %27
  br i1 %strcmp.cmp43, label %strcmp.false, label %strcmp.loop_null_cmp42

strcmp.loop_null_cmp38:                           ; preds = %strcmp.loop33
  %strcmp.cmp_null40 = icmp eq i8 %24, 0
  br i1 %strcmp.cmp_null40, label %strcmp.done, label %strcmp.loop37

strcmp.loop41:                                    ; preds = %strcmp.loop_null_cmp42
  %28 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 12), align 1
  %29 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 12), align 1
  %strcmp.cmp47 = icmp ne i8 %28, %29
  br i1 %strcmp.cmp47, label %strcmp.false, label %strcmp.loop_null_cmp46

strcmp.loop_null_cmp42:                           ; preds = %strcmp.loop37
  %strcmp.cmp_null44 = icmp eq i8 %26, 0
  br i1 %strcmp.cmp_null44, label %strcmp.done, label %strcmp.loop41

strcmp.loop45:                                    ; preds = %strcmp.loop_null_cmp46
  %30 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 13), align 1
  %31 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 13), align 1
  %strcmp.cmp51 = icmp ne i8 %30, %31
  br i1 %strcmp.cmp51, label %strcmp.false, label %strcmp.loop_null_cmp50

strcmp.loop_null_cmp46:                           ; preds = %strcmp.loop41
  %strcmp.cmp_null48 = icmp eq i8 %28, 0
  br i1 %strcmp.cmp_null48, label %strcmp.done, label %strcmp.loop45

strcmp.loop49:                                    ; preds = %strcmp.loop_null_cmp50
  %32 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 14), align 1
  %33 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 14), align 1
  %strcmp.cmp55 = icmp ne i8 %32, %33
  br i1 %strcmp.cmp55, label %strcmp.false, label %strcmp.loop_null_cmp54

strcmp.loop_null_cmp50:                           ; preds = %strcmp.loop45
  %strcmp.cmp_null52 = icmp eq i8 %30, 0
  br i1 %strcmp.cmp_null52, label %strcmp.done, label %strcmp.loop49

strcmp.loop53:                                    ; preds = %strcmp.loop_null_cmp54
  %34 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 15), align 1
  %35 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 15), align 1
  %strcmp.cmp59 = icmp ne i8 %34, %35
  br i1 %strcmp.cmp59, label %strcmp.false, label %strcmp.loop_null_cmp58

strcmp.loop_null_cmp54:                           ; preds = %strcmp.loop49
  %strcmp.cmp_null56 = icmp eq i8 %32, 0
  br i1 %strcmp.cmp_null56, label %strcmp.done, label %strcmp.loop53

strcmp.loop57:                                    ; preds = %strcmp.loop_null_cmp58
  %36 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 16), align 1
  %37 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 16), align 1
  %strcmp.cmp63 = icmp ne i8 %36, %37
  br i1 %strcmp.cmp63, label %strcmp.false, label %strcmp.loop_null_cmp62

strcmp.loop_null_cmp58:                           ; preds = %strcmp.loop53
  %strcmp.cmp_null60 = icmp eq i8 %34, 0
  br i1 %strcmp.cmp_null60, label %strcmp.done, label %strcmp.loop57

strcmp.loop61:                                    ; preds = %strcmp.loop_null_cmp62
  %38 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 17), align 1
  %39 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 17), align 1
  %strcmp.cmp67 = icmp ne i8 %38, %39
  br i1 %strcmp.cmp67, label %strcmp.false, label %strcmp.loop_null_cmp66

strcmp.loop_null_cmp62:                           ; preds = %strcmp.loop57
  %strcmp.cmp_null64 = icmp eq i8 %36, 0
  br i1 %strcmp.cmp_null64, label %strcmp.done, label %strcmp.loop61

strcmp.loop65:                                    ; preds = %strcmp.loop_null_cmp66
  %40 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 18), align 1
  %41 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 18), align 1
  %strcmp.cmp71 = icmp ne i8 %40, %41
  br i1 %strcmp.cmp71, label %strcmp.false, label %strcmp.loop_null_cmp70

strcmp.loop_null_cmp66:                           ; preds = %strcmp.loop61
  %strcmp.cmp_null68 = icmp eq i8 %38, 0
  br i1 %strcmp.cmp_null68, label %strcmp.done, label %strcmp.loop65

strcmp.loop69:                                    ; preds = %strcmp.loop_null_cmp70
  %42 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 19), align 1
  %43 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 19), align 1
  %strcmp.cmp75 = icmp ne i8 %42, %43
  br i1 %strcmp.cmp75, label %strcmp.false, label %strcmp.loop_null_cmp74

strcmp.loop_null_cmp70:                           ; preds = %strcmp.loop65
  %strcmp.cmp_null72 = icmp eq i8 %40, 0
  br i1 %strcmp.cmp_null72, label %strcmp.done, label %strcmp.loop69

strcmp.loop73:                                    ; preds = %strcmp.loop_null_cmp74
  %44 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 20), align 1
  %45 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 20), align 1
  %strcmp.cmp79 = icmp ne i8 %44, %45
  br i1 %strcmp.cmp79, label %strcmp.false, label %strcmp.loop_null_cmp78

strcmp.loop_null_cmp74:                           ; preds = %strcmp.loop69
  %strcmp.cmp_null76 = icmp eq i8 %42, 0
  br i1 %strcmp.cmp_null76, label %strcmp.done, label %strcmp.loop73

strcmp.loop77:                                    ; preds = %strcmp.loop_null_cmp78
  %46 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 21), align 1
  %47 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 21), align 1
  %strcmp.cmp83 = icmp ne i8 %46, %47
  br i1 %strcmp.cmp83, label %strcmp.false, label %strcmp.loop_null_cmp82

strcmp.loop_null_cmp78:                           ; preds = %strcmp.loop73
  %strcmp.cmp_null80 = icmp eq i8 %44, 0
  br i1 %strcmp.cmp_null80, label %strcmp.done, label %strcmp.loop77

strcmp.loop81:                                    ; preds = %strcmp.loop_null_cmp82
  %48 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 22), align 1
  %49 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 22), align 1
  %strcmp.cmp87 = icmp ne i8 %48, %49
  br i1 %strcmp.cmp87, label %strcmp.false, label %strcmp.loop_null_cmp86

strcmp.loop_null_cmp82:                           ; preds = %strcmp.loop77
  %strcmp.cmp_null84 = icmp eq i8 %46, 0
  br i1 %strcmp.cmp_null84, label %strcmp.done, label %strcmp.loop81

strcmp.loop85:                                    ; preds = %strcmp.loop_null_cmp86
  %50 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 23), align 1
  %51 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 23), align 1
  %strcmp.cmp91 = icmp ne i8 %50, %51
  br i1 %strcmp.cmp91, label %strcmp.false, label %strcmp.loop_null_cmp90

strcmp.loop_null_cmp86:                           ; preds = %strcmp.loop81
  %strcmp.cmp_null88 = icmp eq i8 %48, 0
  br i1 %strcmp.cmp_null88, label %strcmp.done, label %strcmp.loop85

strcmp.loop89:                                    ; preds = %strcmp.loop_null_cmp90
  %52 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 24), align 1
  %53 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 24), align 1
  %strcmp.cmp95 = icmp ne i8 %52, %53
  br i1 %strcmp.cmp95, label %strcmp.false, label %strcmp.loop_null_cmp94

strcmp.loop_null_cmp90:                           ; preds = %strcmp.loop85
  %strcmp.cmp_null92 = icmp eq i8 %50, 0
  br i1 %strcmp.cmp_null92, label %strcmp.done, label %strcmp.loop89

strcmp.loop93:                                    ; preds = %strcmp.loop_null_cmp94
  %54 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 25), align 1
  %55 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 25), align 1
  %strcmp.cmp99 = icmp ne i8 %54, %55
  br i1 %strcmp.cmp99, label %strcmp.false, label %strcmp.loop_null_cmp98

strcmp.loop_null_cmp94:                           ; preds = %strcmp.loop89
  %strcmp.cmp_null96 = icmp eq i8 %52, 0
  br i1 %strcmp.cmp_null96, label %strcmp.done, label %strcmp.loop93

strcmp.loop97:                                    ; preds = %strcmp.loop_null_cmp98
  %56 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 26), align 1
  %57 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 26), align 1
  %strcmp.cmp103 = icmp ne i8 %56, %57
  br i1 %strcmp.cmp103, label %strcmp.false, label %strcmp.loop_null_cmp102

strcmp.loop_null_cmp98:                           ; preds = %strcmp.loop93
  %strcmp.cmp_null100 = icmp eq i8 %54, 0
  br i1 %strcmp.cmp_null100, label %strcmp.done, label %strcmp.loop97

strcmp.loop101:                                   ; preds = %strcmp.loop_null_cmp102
  br label %strcmp.done

strcmp.loop_null_cmp102:                          ; preds = %strcmp.loop97
  %strcmp.cmp_null104 = icmp eq i8 %56, 0
  br i1 %strcmp.cmp_null104, label %strcmp.done, label %strcmp.loop101
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!31}
!llvm.module.flags = !{!33, !34}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !10)
!10 = !{!11, !17}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 27, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !18, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !20)
!20 = !{!21}
!21 = !DISubrange(count: 262144, lowerBound: 0)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !25, size: 64, elements: !27)
!25 = !DICompositeType(tag: DW_TAG_array_type, baseType: !26, size: 64, elements: !27)
!26 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!27 = !{!28}
!28 = !DISubrange(count: 1, lowerBound: 0)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!31 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !32)
!32 = !{!0, !7, !22, !29}
!33 = !{i32 2, !"Debug Info Version", i32 3}
!34 = !{i32 7, !"uwtable", i32 0}
!35 = distinct !DISubprogram(name: "tracepoint_sched_sched_one_1", linkageName: "tracepoint_sched_sched_one_1", scope: !2, file: !2, type: !36, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !31, retainedNodes: !39)
!36 = !DISubroutineType(types: !37)
!37 = !{!26, !38}
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!39 = !{!40}
!40 = !DILocalVariable(name: "ctx", arg: 1, scope: !35, file: !2, type: !38)
