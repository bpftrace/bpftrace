; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !30
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !42
@get_str_buf = dso_local externally_initialized global [1 x [1 x [1024 x i8]]] zeroinitializer, section ".data.get_str_buf", !dbg !44

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @tracepoint_file_filename_1(ptr %0) section "s_tracepoint_file_filename_1" !dbg !55 {
entry:
  %key68 = alloca i32, align 4
  %helper_error_t63 = alloca %helper_error_t, align 8
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %strcmp.result = alloca i1, align 1
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %comm = alloca [16 x i8], align 1
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [1 x [1024 x i8]]], ptr @get_str_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %2, i32 1024, ptr null)
  %3 = call ptr @llvm.preserve.static.offset(ptr %0)
  %4 = getelementptr i8, ptr %3, i64 8
  %5 = load volatile i64, ptr %4, align 8
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to ptr)(ptr %2, i32 1024, i64 %5)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %comm)
  call void @llvm.memset.p0.i64(ptr align 1 %comm, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to ptr)(ptr %comm, i64 16)
  %6 = trunc i64 %get_comm to i32
  %7 = icmp sge i32 %6, 0
  br i1 %7, label %helper_merge, label %helper_failure

pred_false:                                       ; preds = %strcmp.false
  ret i64 1

pred_true:                                        ; preds = %strcmp.false
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key")
  store i64 0, ptr %"@_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_val")
  store i64 1, ptr %"@_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_, ptr %"@_key", ptr %"@_val", i64 0)
  %8 = trunc i64 %update_elem to i32
  %9 = icmp sge i32 %8, 0
  br i1 %9, label %helper_merge62, label %helper_failure61

helper_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %10 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %10, align 8
  %11 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %11, align 8
  %12 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %6, ptr %12, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %strcmp.result)
  store i1 false, ptr %strcmp.result, align 1
  %13 = getelementptr i8, ptr %2, i32 0
  %14 = load i8, ptr %13, align 1
  %15 = getelementptr i8, ptr %comm, i32 0
  %16 = load i8, ptr %15, align 1
  %strcmp.cmp = icmp ne i8 %14, %16
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

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
  %17 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop53, %strcmp.loop49, %strcmp.loop45, %strcmp.loop41, %strcmp.loop37, %strcmp.loop33, %strcmp.loop29, %strcmp.loop25, %strcmp.loop21, %strcmp.loop17, %strcmp.loop13, %strcmp.loop9, %strcmp.loop5, %strcmp.loop1, %strcmp.loop, %helper_merge
  %18 = load i1, ptr %strcmp.result, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %strcmp.result)
  %19 = zext i1 %18 to i64
  call void @llvm.lifetime.end.p0(i64 -1, ptr %comm)
  %predcond = icmp eq i64 %19, 0
  br i1 %predcond, label %pred_false, label %pred_true

strcmp.done:                                      ; preds = %strcmp.loop57, %strcmp.loop_null_cmp58, %strcmp.loop_null_cmp54, %strcmp.loop_null_cmp50, %strcmp.loop_null_cmp46, %strcmp.loop_null_cmp42, %strcmp.loop_null_cmp38, %strcmp.loop_null_cmp34, %strcmp.loop_null_cmp30, %strcmp.loop_null_cmp26, %strcmp.loop_null_cmp22, %strcmp.loop_null_cmp18, %strcmp.loop_null_cmp14, %strcmp.loop_null_cmp10, %strcmp.loop_null_cmp6, %strcmp.loop_null_cmp2, %strcmp.loop_null_cmp
  store i1 true, ptr %strcmp.result, align 1
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %20 = getelementptr i8, ptr %2, i32 1
  %21 = load i8, ptr %20, align 1
  %22 = getelementptr i8, ptr %comm, i32 1
  %23 = load i8, ptr %22, align 1
  %strcmp.cmp3 = icmp ne i8 %21, %23
  br i1 %strcmp.cmp3, label %strcmp.false, label %strcmp.loop_null_cmp2

strcmp.loop_null_cmp:                             ; preds = %helper_merge
  %strcmp.cmp_null = icmp eq i8 %14, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop1:                                     ; preds = %strcmp.loop_null_cmp2
  %24 = getelementptr i8, ptr %2, i32 2
  %25 = load i8, ptr %24, align 1
  %26 = getelementptr i8, ptr %comm, i32 2
  %27 = load i8, ptr %26, align 1
  %strcmp.cmp7 = icmp ne i8 %25, %27
  br i1 %strcmp.cmp7, label %strcmp.false, label %strcmp.loop_null_cmp6

strcmp.loop_null_cmp2:                            ; preds = %strcmp.loop
  %strcmp.cmp_null4 = icmp eq i8 %21, 0
  br i1 %strcmp.cmp_null4, label %strcmp.done, label %strcmp.loop1

strcmp.loop5:                                     ; preds = %strcmp.loop_null_cmp6
  %28 = getelementptr i8, ptr %2, i32 3
  %29 = load i8, ptr %28, align 1
  %30 = getelementptr i8, ptr %comm, i32 3
  %31 = load i8, ptr %30, align 1
  %strcmp.cmp11 = icmp ne i8 %29, %31
  br i1 %strcmp.cmp11, label %strcmp.false, label %strcmp.loop_null_cmp10

strcmp.loop_null_cmp6:                            ; preds = %strcmp.loop1
  %strcmp.cmp_null8 = icmp eq i8 %25, 0
  br i1 %strcmp.cmp_null8, label %strcmp.done, label %strcmp.loop5

strcmp.loop9:                                     ; preds = %strcmp.loop_null_cmp10
  %32 = getelementptr i8, ptr %2, i32 4
  %33 = load i8, ptr %32, align 1
  %34 = getelementptr i8, ptr %comm, i32 4
  %35 = load i8, ptr %34, align 1
  %strcmp.cmp15 = icmp ne i8 %33, %35
  br i1 %strcmp.cmp15, label %strcmp.false, label %strcmp.loop_null_cmp14

strcmp.loop_null_cmp10:                           ; preds = %strcmp.loop5
  %strcmp.cmp_null12 = icmp eq i8 %29, 0
  br i1 %strcmp.cmp_null12, label %strcmp.done, label %strcmp.loop9

strcmp.loop13:                                    ; preds = %strcmp.loop_null_cmp14
  %36 = getelementptr i8, ptr %2, i32 5
  %37 = load i8, ptr %36, align 1
  %38 = getelementptr i8, ptr %comm, i32 5
  %39 = load i8, ptr %38, align 1
  %strcmp.cmp19 = icmp ne i8 %37, %39
  br i1 %strcmp.cmp19, label %strcmp.false, label %strcmp.loop_null_cmp18

strcmp.loop_null_cmp14:                           ; preds = %strcmp.loop9
  %strcmp.cmp_null16 = icmp eq i8 %33, 0
  br i1 %strcmp.cmp_null16, label %strcmp.done, label %strcmp.loop13

strcmp.loop17:                                    ; preds = %strcmp.loop_null_cmp18
  %40 = getelementptr i8, ptr %2, i32 6
  %41 = load i8, ptr %40, align 1
  %42 = getelementptr i8, ptr %comm, i32 6
  %43 = load i8, ptr %42, align 1
  %strcmp.cmp23 = icmp ne i8 %41, %43
  br i1 %strcmp.cmp23, label %strcmp.false, label %strcmp.loop_null_cmp22

strcmp.loop_null_cmp18:                           ; preds = %strcmp.loop13
  %strcmp.cmp_null20 = icmp eq i8 %37, 0
  br i1 %strcmp.cmp_null20, label %strcmp.done, label %strcmp.loop17

strcmp.loop21:                                    ; preds = %strcmp.loop_null_cmp22
  %44 = getelementptr i8, ptr %2, i32 7
  %45 = load i8, ptr %44, align 1
  %46 = getelementptr i8, ptr %comm, i32 7
  %47 = load i8, ptr %46, align 1
  %strcmp.cmp27 = icmp ne i8 %45, %47
  br i1 %strcmp.cmp27, label %strcmp.false, label %strcmp.loop_null_cmp26

strcmp.loop_null_cmp22:                           ; preds = %strcmp.loop17
  %strcmp.cmp_null24 = icmp eq i8 %41, 0
  br i1 %strcmp.cmp_null24, label %strcmp.done, label %strcmp.loop21

strcmp.loop25:                                    ; preds = %strcmp.loop_null_cmp26
  %48 = getelementptr i8, ptr %2, i32 8
  %49 = load i8, ptr %48, align 1
  %50 = getelementptr i8, ptr %comm, i32 8
  %51 = load i8, ptr %50, align 1
  %strcmp.cmp31 = icmp ne i8 %49, %51
  br i1 %strcmp.cmp31, label %strcmp.false, label %strcmp.loop_null_cmp30

strcmp.loop_null_cmp26:                           ; preds = %strcmp.loop21
  %strcmp.cmp_null28 = icmp eq i8 %45, 0
  br i1 %strcmp.cmp_null28, label %strcmp.done, label %strcmp.loop25

strcmp.loop29:                                    ; preds = %strcmp.loop_null_cmp30
  %52 = getelementptr i8, ptr %2, i32 9
  %53 = load i8, ptr %52, align 1
  %54 = getelementptr i8, ptr %comm, i32 9
  %55 = load i8, ptr %54, align 1
  %strcmp.cmp35 = icmp ne i8 %53, %55
  br i1 %strcmp.cmp35, label %strcmp.false, label %strcmp.loop_null_cmp34

strcmp.loop_null_cmp30:                           ; preds = %strcmp.loop25
  %strcmp.cmp_null32 = icmp eq i8 %49, 0
  br i1 %strcmp.cmp_null32, label %strcmp.done, label %strcmp.loop29

strcmp.loop33:                                    ; preds = %strcmp.loop_null_cmp34
  %56 = getelementptr i8, ptr %2, i32 10
  %57 = load i8, ptr %56, align 1
  %58 = getelementptr i8, ptr %comm, i32 10
  %59 = load i8, ptr %58, align 1
  %strcmp.cmp39 = icmp ne i8 %57, %59
  br i1 %strcmp.cmp39, label %strcmp.false, label %strcmp.loop_null_cmp38

strcmp.loop_null_cmp34:                           ; preds = %strcmp.loop29
  %strcmp.cmp_null36 = icmp eq i8 %53, 0
  br i1 %strcmp.cmp_null36, label %strcmp.done, label %strcmp.loop33

strcmp.loop37:                                    ; preds = %strcmp.loop_null_cmp38
  %60 = getelementptr i8, ptr %2, i32 11
  %61 = load i8, ptr %60, align 1
  %62 = getelementptr i8, ptr %comm, i32 11
  %63 = load i8, ptr %62, align 1
  %strcmp.cmp43 = icmp ne i8 %61, %63
  br i1 %strcmp.cmp43, label %strcmp.false, label %strcmp.loop_null_cmp42

strcmp.loop_null_cmp38:                           ; preds = %strcmp.loop33
  %strcmp.cmp_null40 = icmp eq i8 %57, 0
  br i1 %strcmp.cmp_null40, label %strcmp.done, label %strcmp.loop37

strcmp.loop41:                                    ; preds = %strcmp.loop_null_cmp42
  %64 = getelementptr i8, ptr %2, i32 12
  %65 = load i8, ptr %64, align 1
  %66 = getelementptr i8, ptr %comm, i32 12
  %67 = load i8, ptr %66, align 1
  %strcmp.cmp47 = icmp ne i8 %65, %67
  br i1 %strcmp.cmp47, label %strcmp.false, label %strcmp.loop_null_cmp46

strcmp.loop_null_cmp42:                           ; preds = %strcmp.loop37
  %strcmp.cmp_null44 = icmp eq i8 %61, 0
  br i1 %strcmp.cmp_null44, label %strcmp.done, label %strcmp.loop41

strcmp.loop45:                                    ; preds = %strcmp.loop_null_cmp46
  %68 = getelementptr i8, ptr %2, i32 13
  %69 = load i8, ptr %68, align 1
  %70 = getelementptr i8, ptr %comm, i32 13
  %71 = load i8, ptr %70, align 1
  %strcmp.cmp51 = icmp ne i8 %69, %71
  br i1 %strcmp.cmp51, label %strcmp.false, label %strcmp.loop_null_cmp50

strcmp.loop_null_cmp46:                           ; preds = %strcmp.loop41
  %strcmp.cmp_null48 = icmp eq i8 %65, 0
  br i1 %strcmp.cmp_null48, label %strcmp.done, label %strcmp.loop45

strcmp.loop49:                                    ; preds = %strcmp.loop_null_cmp50
  %72 = getelementptr i8, ptr %2, i32 14
  %73 = load i8, ptr %72, align 1
  %74 = getelementptr i8, ptr %comm, i32 14
  %75 = load i8, ptr %74, align 1
  %strcmp.cmp55 = icmp ne i8 %73, %75
  br i1 %strcmp.cmp55, label %strcmp.false, label %strcmp.loop_null_cmp54

strcmp.loop_null_cmp50:                           ; preds = %strcmp.loop45
  %strcmp.cmp_null52 = icmp eq i8 %69, 0
  br i1 %strcmp.cmp_null52, label %strcmp.done, label %strcmp.loop49

strcmp.loop53:                                    ; preds = %strcmp.loop_null_cmp54
  %76 = getelementptr i8, ptr %2, i32 15
  %77 = load i8, ptr %76, align 1
  %78 = getelementptr i8, ptr %comm, i32 15
  %79 = load i8, ptr %78, align 1
  %strcmp.cmp59 = icmp ne i8 %77, %79
  br i1 %strcmp.cmp59, label %strcmp.false, label %strcmp.loop_null_cmp58

strcmp.loop_null_cmp54:                           ; preds = %strcmp.loop49
  %strcmp.cmp_null56 = icmp eq i8 %73, 0
  br i1 %strcmp.cmp_null56, label %strcmp.done, label %strcmp.loop53

strcmp.loop57:                                    ; preds = %strcmp.loop_null_cmp58
  br label %strcmp.done

strcmp.loop_null_cmp58:                           ; preds = %strcmp.loop53
  %strcmp.cmp_null60 = icmp eq i8 %77, 0
  br i1 %strcmp.cmp_null60, label %strcmp.done, label %strcmp.loop57

helper_failure61:                                 ; preds = %pred_true
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t63)
  %80 = getelementptr %helper_error_t, ptr %helper_error_t63, i64 0, i32 0
  store i64 30006, ptr %80, align 8
  %81 = getelementptr %helper_error_t, ptr %helper_error_t63, i64 0, i32 1
  store i64 1, ptr %81, align 8
  %82 = getelementptr %helper_error_t, ptr %helper_error_t63, i64 0, i32 2
  store i32 %8, ptr %82, align 4
  %ringbuf_output64 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t63, i64 20, i64 0)
  %ringbuf_loss67 = icmp slt i64 %ringbuf_output64, 0
  br i1 %ringbuf_loss67, label %event_loss_counter65, label %counter_merge66

helper_merge62:                                   ; preds = %counter_merge66, %pred_true
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key")
  ret i64 1

event_loss_counter65:                             ; preds = %helper_failure61
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key68)
  store i32 0, ptr %key68, align 4
  %lookup_elem69 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key68)
  %map_lookup_cond73 = icmp ne ptr %lookup_elem69, null
  br i1 %map_lookup_cond73, label %lookup_success70, label %lookup_failure71

counter_merge66:                                  ; preds = %lookup_merge72, %helper_failure61
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t63)
  br label %helper_merge62

lookup_success70:                                 ; preds = %event_loss_counter65
  %83 = atomicrmw add ptr %lookup_elem69, i64 1 seq_cst, align 8
  br label %lookup_merge72

lookup_failure71:                                 ; preds = %event_loss_counter65
  br label %lookup_merge72

lookup_merge72:                                   ; preds = %lookup_failure71, %lookup_success70
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key68)
  br label %counter_merge66
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

!llvm.dbg.cu = !{!52}
!llvm.module.flags = !{!54}

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
!17 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !19)
!19 = !{!20, !25}
!20 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !21, size: 64)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !23)
!23 = !{!24}
!24 = !DISubrange(count: 27, lowerBound: 0)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !26, size: 64, offset: 64)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 262144, lowerBound: 0)
!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())
!31 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !32, isLocal: false, isDefinition: true)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !33)
!33 = !{!34, !11, !39, !15}
!34 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !35, size: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 2, lowerBound: 0)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !40, size: 64, offset: 128)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!42 = !DIGlobalVariableExpression(var: !43, expr: !DIExpression())
!43 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !14, isLocal: false, isDefinition: true)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "get_str_buf", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !47, size: 8192, elements: !9)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !48, size: 8192, elements: !9)
!48 = !DICompositeType(tag: DW_TAG_array_type, baseType: !49, size: 8192, elements: !50)
!49 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!50 = !{!51}
!51 = !DISubrange(count: 1024, lowerBound: 0)
!52 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !53)
!53 = !{!0, !16, !30, !42, !44}
!54 = !{i32 2, !"Debug Info Version", i32 3}
!55 = distinct !DISubprogram(name: "tracepoint_file_filename_1", linkageName: "tracepoint_file_filename_1", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !52, retainedNodes: !59)
!56 = !DISubroutineType(types: !57)
!57 = !{!14, !58}
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !49, size: 64)
!59 = !{!60}
!60 = !DILocalVariable(name: "ctx", arg: 1, scope: !55, file: !2, type: !58)
