; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@event_loss_counter = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@"tracepoint:sched:sched_one" = global [27 x i8] c"tracepoint:sched:sched_one\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @tracepoint_sched_sched_one_1(ptr %0) section "s_tracepoint_sched_sched_one_1" !dbg !39 {
entry:
  %strcmp.result = alloca i1, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %strcmp.result)
  store i1 false, ptr %strcmp.result, align 1
  %1 = load i8, ptr @"tracepoint:sched:sched_one", align 1
  %2 = load i8, ptr @"tracepoint:sched:sched_one", align 1
  %strcmp.cmp = icmp ne i8 %1, %2
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

if_body:                                          ; preds = %strcmp.false
  br label %if_end

if_end:                                           ; preds = %if_body, %strcmp.false
  ret i64 1

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop97, %strcmp.loop93, %strcmp.loop89, %strcmp.loop85, %strcmp.loop81, %strcmp.loop77, %strcmp.loop73, %strcmp.loop69, %strcmp.loop65, %strcmp.loop61, %strcmp.loop57, %strcmp.loop53, %strcmp.loop49, %strcmp.loop45, %strcmp.loop41, %strcmp.loop37, %strcmp.loop33, %strcmp.loop29, %strcmp.loop25, %strcmp.loop21, %strcmp.loop17, %strcmp.loop13, %strcmp.loop9, %strcmp.loop5, %strcmp.loop1, %strcmp.loop, %entry
  %3 = load i1, ptr %strcmp.result, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %strcmp.result)
  %4 = zext i1 %3 to i64
  %true_cond = icmp ne i64 %4, 0
  br i1 %true_cond, label %if_body, label %if_end

strcmp.done:                                      ; preds = %strcmp.loop101, %strcmp.loop_null_cmp102, %strcmp.loop_null_cmp98, %strcmp.loop_null_cmp94, %strcmp.loop_null_cmp90, %strcmp.loop_null_cmp86, %strcmp.loop_null_cmp82, %strcmp.loop_null_cmp78, %strcmp.loop_null_cmp74, %strcmp.loop_null_cmp70, %strcmp.loop_null_cmp66, %strcmp.loop_null_cmp62, %strcmp.loop_null_cmp58, %strcmp.loop_null_cmp54, %strcmp.loop_null_cmp50, %strcmp.loop_null_cmp46, %strcmp.loop_null_cmp42, %strcmp.loop_null_cmp38, %strcmp.loop_null_cmp34, %strcmp.loop_null_cmp30, %strcmp.loop_null_cmp26, %strcmp.loop_null_cmp22, %strcmp.loop_null_cmp18, %strcmp.loop_null_cmp14, %strcmp.loop_null_cmp10, %strcmp.loop_null_cmp6, %strcmp.loop_null_cmp2, %strcmp.loop_null_cmp
  store i1 true, ptr %strcmp.result, align 1
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %5 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 1), align 1
  %6 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 1), align 1
  %strcmp.cmp3 = icmp ne i8 %5, %6
  br i1 %strcmp.cmp3, label %strcmp.false, label %strcmp.loop_null_cmp2

strcmp.loop_null_cmp:                             ; preds = %entry
  %strcmp.cmp_null = icmp eq i8 %1, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop1:                                     ; preds = %strcmp.loop_null_cmp2
  %7 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 2), align 1
  %8 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 2), align 1
  %strcmp.cmp7 = icmp ne i8 %7, %8
  br i1 %strcmp.cmp7, label %strcmp.false, label %strcmp.loop_null_cmp6

strcmp.loop_null_cmp2:                            ; preds = %strcmp.loop
  %strcmp.cmp_null4 = icmp eq i8 %5, 0
  br i1 %strcmp.cmp_null4, label %strcmp.done, label %strcmp.loop1

strcmp.loop5:                                     ; preds = %strcmp.loop_null_cmp6
  %9 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 3), align 1
  %10 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 3), align 1
  %strcmp.cmp11 = icmp ne i8 %9, %10
  br i1 %strcmp.cmp11, label %strcmp.false, label %strcmp.loop_null_cmp10

strcmp.loop_null_cmp6:                            ; preds = %strcmp.loop1
  %strcmp.cmp_null8 = icmp eq i8 %7, 0
  br i1 %strcmp.cmp_null8, label %strcmp.done, label %strcmp.loop5

strcmp.loop9:                                     ; preds = %strcmp.loop_null_cmp10
  %11 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 4), align 1
  %12 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 4), align 1
  %strcmp.cmp15 = icmp ne i8 %11, %12
  br i1 %strcmp.cmp15, label %strcmp.false, label %strcmp.loop_null_cmp14

strcmp.loop_null_cmp10:                           ; preds = %strcmp.loop5
  %strcmp.cmp_null12 = icmp eq i8 %9, 0
  br i1 %strcmp.cmp_null12, label %strcmp.done, label %strcmp.loop9

strcmp.loop13:                                    ; preds = %strcmp.loop_null_cmp14
  %13 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 5), align 1
  %14 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 5), align 1
  %strcmp.cmp19 = icmp ne i8 %13, %14
  br i1 %strcmp.cmp19, label %strcmp.false, label %strcmp.loop_null_cmp18

strcmp.loop_null_cmp14:                           ; preds = %strcmp.loop9
  %strcmp.cmp_null16 = icmp eq i8 %11, 0
  br i1 %strcmp.cmp_null16, label %strcmp.done, label %strcmp.loop13

strcmp.loop17:                                    ; preds = %strcmp.loop_null_cmp18
  %15 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 6), align 1
  %16 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 6), align 1
  %strcmp.cmp23 = icmp ne i8 %15, %16
  br i1 %strcmp.cmp23, label %strcmp.false, label %strcmp.loop_null_cmp22

strcmp.loop_null_cmp18:                           ; preds = %strcmp.loop13
  %strcmp.cmp_null20 = icmp eq i8 %13, 0
  br i1 %strcmp.cmp_null20, label %strcmp.done, label %strcmp.loop17

strcmp.loop21:                                    ; preds = %strcmp.loop_null_cmp22
  %17 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 7), align 1
  %18 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 7), align 1
  %strcmp.cmp27 = icmp ne i8 %17, %18
  br i1 %strcmp.cmp27, label %strcmp.false, label %strcmp.loop_null_cmp26

strcmp.loop_null_cmp22:                           ; preds = %strcmp.loop17
  %strcmp.cmp_null24 = icmp eq i8 %15, 0
  br i1 %strcmp.cmp_null24, label %strcmp.done, label %strcmp.loop21

strcmp.loop25:                                    ; preds = %strcmp.loop_null_cmp26
  %19 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 8), align 1
  %20 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 8), align 1
  %strcmp.cmp31 = icmp ne i8 %19, %20
  br i1 %strcmp.cmp31, label %strcmp.false, label %strcmp.loop_null_cmp30

strcmp.loop_null_cmp26:                           ; preds = %strcmp.loop21
  %strcmp.cmp_null28 = icmp eq i8 %17, 0
  br i1 %strcmp.cmp_null28, label %strcmp.done, label %strcmp.loop25

strcmp.loop29:                                    ; preds = %strcmp.loop_null_cmp30
  %21 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 9), align 1
  %22 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 9), align 1
  %strcmp.cmp35 = icmp ne i8 %21, %22
  br i1 %strcmp.cmp35, label %strcmp.false, label %strcmp.loop_null_cmp34

strcmp.loop_null_cmp30:                           ; preds = %strcmp.loop25
  %strcmp.cmp_null32 = icmp eq i8 %19, 0
  br i1 %strcmp.cmp_null32, label %strcmp.done, label %strcmp.loop29

strcmp.loop33:                                    ; preds = %strcmp.loop_null_cmp34
  %23 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 10), align 1
  %24 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 10), align 1
  %strcmp.cmp39 = icmp ne i8 %23, %24
  br i1 %strcmp.cmp39, label %strcmp.false, label %strcmp.loop_null_cmp38

strcmp.loop_null_cmp34:                           ; preds = %strcmp.loop29
  %strcmp.cmp_null36 = icmp eq i8 %21, 0
  br i1 %strcmp.cmp_null36, label %strcmp.done, label %strcmp.loop33

strcmp.loop37:                                    ; preds = %strcmp.loop_null_cmp38
  %25 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 11), align 1
  %26 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 11), align 1
  %strcmp.cmp43 = icmp ne i8 %25, %26
  br i1 %strcmp.cmp43, label %strcmp.false, label %strcmp.loop_null_cmp42

strcmp.loop_null_cmp38:                           ; preds = %strcmp.loop33
  %strcmp.cmp_null40 = icmp eq i8 %23, 0
  br i1 %strcmp.cmp_null40, label %strcmp.done, label %strcmp.loop37

strcmp.loop41:                                    ; preds = %strcmp.loop_null_cmp42
  %27 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 12), align 1
  %28 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 12), align 1
  %strcmp.cmp47 = icmp ne i8 %27, %28
  br i1 %strcmp.cmp47, label %strcmp.false, label %strcmp.loop_null_cmp46

strcmp.loop_null_cmp42:                           ; preds = %strcmp.loop37
  %strcmp.cmp_null44 = icmp eq i8 %25, 0
  br i1 %strcmp.cmp_null44, label %strcmp.done, label %strcmp.loop41

strcmp.loop45:                                    ; preds = %strcmp.loop_null_cmp46
  %29 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 13), align 1
  %30 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 13), align 1
  %strcmp.cmp51 = icmp ne i8 %29, %30
  br i1 %strcmp.cmp51, label %strcmp.false, label %strcmp.loop_null_cmp50

strcmp.loop_null_cmp46:                           ; preds = %strcmp.loop41
  %strcmp.cmp_null48 = icmp eq i8 %27, 0
  br i1 %strcmp.cmp_null48, label %strcmp.done, label %strcmp.loop45

strcmp.loop49:                                    ; preds = %strcmp.loop_null_cmp50
  %31 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 14), align 1
  %32 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 14), align 1
  %strcmp.cmp55 = icmp ne i8 %31, %32
  br i1 %strcmp.cmp55, label %strcmp.false, label %strcmp.loop_null_cmp54

strcmp.loop_null_cmp50:                           ; preds = %strcmp.loop45
  %strcmp.cmp_null52 = icmp eq i8 %29, 0
  br i1 %strcmp.cmp_null52, label %strcmp.done, label %strcmp.loop49

strcmp.loop53:                                    ; preds = %strcmp.loop_null_cmp54
  %33 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 15), align 1
  %34 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 15), align 1
  %strcmp.cmp59 = icmp ne i8 %33, %34
  br i1 %strcmp.cmp59, label %strcmp.false, label %strcmp.loop_null_cmp58

strcmp.loop_null_cmp54:                           ; preds = %strcmp.loop49
  %strcmp.cmp_null56 = icmp eq i8 %31, 0
  br i1 %strcmp.cmp_null56, label %strcmp.done, label %strcmp.loop53

strcmp.loop57:                                    ; preds = %strcmp.loop_null_cmp58
  %35 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 16), align 1
  %36 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 16), align 1
  %strcmp.cmp63 = icmp ne i8 %35, %36
  br i1 %strcmp.cmp63, label %strcmp.false, label %strcmp.loop_null_cmp62

strcmp.loop_null_cmp58:                           ; preds = %strcmp.loop53
  %strcmp.cmp_null60 = icmp eq i8 %33, 0
  br i1 %strcmp.cmp_null60, label %strcmp.done, label %strcmp.loop57

strcmp.loop61:                                    ; preds = %strcmp.loop_null_cmp62
  %37 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 17), align 1
  %38 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 17), align 1
  %strcmp.cmp67 = icmp ne i8 %37, %38
  br i1 %strcmp.cmp67, label %strcmp.false, label %strcmp.loop_null_cmp66

strcmp.loop_null_cmp62:                           ; preds = %strcmp.loop57
  %strcmp.cmp_null64 = icmp eq i8 %35, 0
  br i1 %strcmp.cmp_null64, label %strcmp.done, label %strcmp.loop61

strcmp.loop65:                                    ; preds = %strcmp.loop_null_cmp66
  %39 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 18), align 1
  %40 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 18), align 1
  %strcmp.cmp71 = icmp ne i8 %39, %40
  br i1 %strcmp.cmp71, label %strcmp.false, label %strcmp.loop_null_cmp70

strcmp.loop_null_cmp66:                           ; preds = %strcmp.loop61
  %strcmp.cmp_null68 = icmp eq i8 %37, 0
  br i1 %strcmp.cmp_null68, label %strcmp.done, label %strcmp.loop65

strcmp.loop69:                                    ; preds = %strcmp.loop_null_cmp70
  %41 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 19), align 1
  %42 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 19), align 1
  %strcmp.cmp75 = icmp ne i8 %41, %42
  br i1 %strcmp.cmp75, label %strcmp.false, label %strcmp.loop_null_cmp74

strcmp.loop_null_cmp70:                           ; preds = %strcmp.loop65
  %strcmp.cmp_null72 = icmp eq i8 %39, 0
  br i1 %strcmp.cmp_null72, label %strcmp.done, label %strcmp.loop69

strcmp.loop73:                                    ; preds = %strcmp.loop_null_cmp74
  %43 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 20), align 1
  %44 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 20), align 1
  %strcmp.cmp79 = icmp ne i8 %43, %44
  br i1 %strcmp.cmp79, label %strcmp.false, label %strcmp.loop_null_cmp78

strcmp.loop_null_cmp74:                           ; preds = %strcmp.loop69
  %strcmp.cmp_null76 = icmp eq i8 %41, 0
  br i1 %strcmp.cmp_null76, label %strcmp.done, label %strcmp.loop73

strcmp.loop77:                                    ; preds = %strcmp.loop_null_cmp78
  %45 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 21), align 1
  %46 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 21), align 1
  %strcmp.cmp83 = icmp ne i8 %45, %46
  br i1 %strcmp.cmp83, label %strcmp.false, label %strcmp.loop_null_cmp82

strcmp.loop_null_cmp78:                           ; preds = %strcmp.loop73
  %strcmp.cmp_null80 = icmp eq i8 %43, 0
  br i1 %strcmp.cmp_null80, label %strcmp.done, label %strcmp.loop77

strcmp.loop81:                                    ; preds = %strcmp.loop_null_cmp82
  %47 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 22), align 1
  %48 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 22), align 1
  %strcmp.cmp87 = icmp ne i8 %47, %48
  br i1 %strcmp.cmp87, label %strcmp.false, label %strcmp.loop_null_cmp86

strcmp.loop_null_cmp82:                           ; preds = %strcmp.loop77
  %strcmp.cmp_null84 = icmp eq i8 %45, 0
  br i1 %strcmp.cmp_null84, label %strcmp.done, label %strcmp.loop81

strcmp.loop85:                                    ; preds = %strcmp.loop_null_cmp86
  %49 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 23), align 1
  %50 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 23), align 1
  %strcmp.cmp91 = icmp ne i8 %49, %50
  br i1 %strcmp.cmp91, label %strcmp.false, label %strcmp.loop_null_cmp90

strcmp.loop_null_cmp86:                           ; preds = %strcmp.loop81
  %strcmp.cmp_null88 = icmp eq i8 %47, 0
  br i1 %strcmp.cmp_null88, label %strcmp.done, label %strcmp.loop85

strcmp.loop89:                                    ; preds = %strcmp.loop_null_cmp90
  %51 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 24), align 1
  %52 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 24), align 1
  %strcmp.cmp95 = icmp ne i8 %51, %52
  br i1 %strcmp.cmp95, label %strcmp.false, label %strcmp.loop_null_cmp94

strcmp.loop_null_cmp90:                           ; preds = %strcmp.loop85
  %strcmp.cmp_null92 = icmp eq i8 %49, 0
  br i1 %strcmp.cmp_null92, label %strcmp.done, label %strcmp.loop89

strcmp.loop93:                                    ; preds = %strcmp.loop_null_cmp94
  %53 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 25), align 1
  %54 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 25), align 1
  %strcmp.cmp99 = icmp ne i8 %53, %54
  br i1 %strcmp.cmp99, label %strcmp.false, label %strcmp.loop_null_cmp98

strcmp.loop_null_cmp94:                           ; preds = %strcmp.loop89
  %strcmp.cmp_null96 = icmp eq i8 %51, 0
  br i1 %strcmp.cmp_null96, label %strcmp.done, label %strcmp.loop93

strcmp.loop97:                                    ; preds = %strcmp.loop_null_cmp98
  %55 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 26), align 1
  %56 = load i8, ptr getelementptr (i8, ptr @"tracepoint:sched:sched_one", i32 26), align 1
  %strcmp.cmp103 = icmp ne i8 %55, %56
  br i1 %strcmp.cmp103, label %strcmp.false, label %strcmp.loop_null_cmp102

strcmp.loop_null_cmp98:                           ; preds = %strcmp.loop93
  %strcmp.cmp_null100 = icmp eq i8 %53, 0
  br i1 %strcmp.cmp_null100, label %strcmp.done, label %strcmp.loop97

strcmp.loop101:                                   ; preds = %strcmp.loop_null_cmp102
  br label %strcmp.done

strcmp.loop_null_cmp102:                          ; preds = %strcmp.loop97
  %strcmp.cmp_null104 = icmp eq i8 %55, 0
  br i1 %strcmp.cmp_null104, label %strcmp.done, label %strcmp.loop101
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!36}
!llvm.module.flags = !{!38}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !4)
!4 = !{!5, !11}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 27, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 262144, lowerBound: 0)
!16 = !DIGlobalVariableExpression(var: !17, expr: !DIExpression())
!17 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !19)
!19 = !{!20, !25, !30, !33}
!20 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !21, size: 64)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !23)
!23 = !{!24}
!24 = !DISubrange(count: 2, lowerBound: 0)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !26, size: 64, offset: 64)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 1, lowerBound: 0)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !31, size: 64, offset: 128)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !34, size: 64, offset: 192)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!36 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !37)
!37 = !{!0, !16}
!38 = !{i32 2, !"Debug Info Version", i32 3}
!39 = distinct !DISubprogram(name: "tracepoint_sched_sched_one_1", linkageName: "tracepoint_sched_sched_one_1", scope: !2, file: !2, type: !40, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !36, retainedNodes: !44)
!40 = !DISubroutineType(types: !41)
!41 = !{!35, !42}
!42 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!43 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!44 = !{!45}
!45 = !DILocalVariable(name: "ctx", arg: 1, scope: !39, file: !2, type: !42)
