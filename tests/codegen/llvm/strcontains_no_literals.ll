; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr }
%ctx_t = type { ptr, ptr, ptr, i64, i64 }
%ctx_t.0 = type { ptr, ptr, ptr, ptr, i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29
@__bt__var_buf = dso_local externally_initialized global [1 x [4 x [1024 x i8]]] zeroinitializer, section ".data.var_buf", !dbg !31
@__bt__get_str_buf = dso_local externally_initialized global [1 x [2 x [1024 x i8]]] zeroinitializer, section ".data.get_str_buf", !dbg !38

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_foo_1(ptr %0) #0 section "s_kprobe_foo_1" !dbg !48 {
entry:
  %ctx = alloca %ctx_t, align 8
  %array_access = alloca i8, align 1
  %"||_result" = alloca i1, align 1
  %"$$strcontains_$found" = alloca i8, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strcontains_$found")
  store i8 0, ptr %"$$strcontains_$found", align 1
  %get_cpu_id9 = call i64 inttoptr (i64 8 to ptr)() #3
  %1 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded10 = and i64 %get_cpu_id9, %1
  %2 = getelementptr [1 x [4 x [1024 x i8]]], ptr @__bt__var_buf, i64 0, i64 %cpu.id.bounded10, i64 1, i64 0
  %probe_read_kernel11 = call i64 inttoptr (i64 113 to ptr)(ptr %2, i32 1024, ptr null)
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)() #3
  %3 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %3
  %4 = getelementptr [1 x [4 x [1024 x i8]]], ptr @__bt__var_buf, i64 0, i64 %cpu.id.bounded2, i64 0, i64 0
  %probe_read_kernel3 = call i64 inttoptr (i64 113 to ptr)(ptr %4, i32 1024, ptr null)
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #3
  %5 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %5
  %6 = getelementptr [1 x [2 x [1024 x i8]]], ptr @__bt__get_str_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %6, i32 1024, ptr null)
  %7 = call ptr @llvm.preserve.static.offset(ptr %0)
  %8 = getelementptr i8, ptr %7, i64 112
  %arg0 = load volatile i64, ptr %8, align 8
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to ptr)(ptr %6, i32 1024, i64 %arg0)
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to ptr)(ptr %4, i32 1024, ptr %6)
  %get_cpu_id5 = call i64 inttoptr (i64 8 to ptr)() #3
  %9 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded6 = and i64 %get_cpu_id5, %9
  %10 = getelementptr [1 x [2 x [1024 x i8]]], ptr @__bt__get_str_buf, i64 0, i64 %cpu.id.bounded6, i64 1, i64 0
  %probe_read_kernel7 = call i64 inttoptr (i64 113 to ptr)(ptr %10, i32 1024, ptr null)
  %11 = call ptr @llvm.preserve.static.offset(ptr %0)
  %12 = getelementptr i8, ptr %11, i64 104
  %arg1 = load volatile i64, ptr %12, align 8
  %probe_read_kernel_str8 = call i64 inttoptr (i64 115 to ptr)(ptr %10, i32 1024, i64 %arg1)
  %probe_read_kernel12 = call i64 inttoptr (i64 113 to ptr)(ptr %2, i32 1024, ptr %10)
  store i8 0, ptr %"$$strcontains_$found", align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"||_result")
  br i1 false, label %"||_true", label %"||_lhs_false"

left:                                             ; preds = %"||_merge"
  store i8 1, ptr %"$$strcontains_$found", align 1
  br label %done

right:                                            ; preds = %"||_merge"
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ctx)
  %13 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strcontains_$haystack" = getelementptr %ctx_t, ptr %13, i64 0, i32 0
  store ptr %4, ptr %"ctx.$$strcontains_$haystack", align 8
  %14 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strcontains_$needle" = getelementptr %ctx_t, ptr %14, i64 0, i32 1
  store ptr %2, ptr %"ctx.$$strcontains_$needle", align 8
  %15 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strcontains_$found" = getelementptr %ctx_t, ptr %15, i64 0, i32 2
  store ptr %"$$strcontains_$found", ptr %"ctx.$$strcontains_$found", align 8
  %16 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %ctx.start = getelementptr %ctx_t, ptr %16, i64 0, i32 3
  store i64 0, ptr %ctx.start, align 8
  br i1 true, label %is_positive, label %merge

done:                                             ; preds = %merge, %left
  %17 = load i8, ptr %"$$strcontains_$found", align 1
  ret i64 0

"||_lhs_false":                                   ; preds = %entry
  %18 = ptrtoint ptr %2 to i64
  %19 = inttoptr i64 %18 to ptr
  %20 = call ptr @llvm.preserve.static.offset(ptr %19)
  %21 = getelementptr i8, ptr %20, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %array_access)
  %probe_read_kernel13 = call i64 inttoptr (i64 113 to ptr)(ptr %array_access, i32 1, ptr %21)
  %22 = load i8, ptr %array_access, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %array_access)
  %23 = sext i8 %22 to i64
  %24 = icmp eq i64 %23, 0
  %rhs_true_cond = icmp ne i1 %24, false
  br i1 %rhs_true_cond, label %"||_true", label %"||_false"

"||_false":                                       ; preds = %"||_lhs_false"
  store i1 false, ptr %"||_result", align 1
  br label %"||_merge"

"||_true":                                        ; preds = %"||_lhs_false", %entry
  store i1 true, ptr %"||_result", align 1
  br label %"||_merge"

"||_merge":                                       ; preds = %"||_true", %"||_false"
  %25 = load i1, ptr %"||_result", align 1
  %true_cond = icmp ne i1 %25, false
  br i1 %true_cond, label %left, label %right

is_positive:                                      ; preds = %right
  %bpf_loop = call i64 inttoptr (i64 181 to ptr)(i32 1024, ptr @loop_cb, ptr %ctx, i64 0)
  br label %merge

merge:                                            ; preds = %is_positive, %right
  br label %done
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nounwind
define internal i64 @loop_cb(i64 %0, ptr %1) #0 section ".text" !dbg !54 {
for_body:
  %ctx = alloca %ctx_t.0, align 8
  %array_access = alloca i8, align 1
  %"||_result" = alloca i1, align 1
  %2 = call ptr @llvm.preserve.static.offset(ptr %1)
  %start = getelementptr %ctx_t, ptr %2, i64 0, i32 3
  %3 = call ptr @llvm.preserve.static.offset(ptr %1)
  %current = getelementptr %ctx_t, ptr %3, i64 0, i32 4
  %4 = load i64, ptr %start, align 8
  %5 = add i64 %4, %0
  store i64 %5, ptr %current, align 8
  %"ctx.$$strcontains_$haystack" = getelementptr %ctx_t, ptr %1, i64 0, i32 0
  %"$$strcontains_$haystack" = load ptr, ptr %"ctx.$$strcontains_$haystack", align 8
  %"ctx.$$strcontains_$needle" = getelementptr %ctx_t, ptr %1, i64 0, i32 1
  %"$$strcontains_$needle" = load ptr, ptr %"ctx.$$strcontains_$needle", align 8
  %"ctx.$$strcontains_$found" = getelementptr %ctx_t, ptr %1, i64 0, i32 2
  %"$$strcontains_$found" = load ptr, ptr %"ctx.$$strcontains_$found", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"||_result")
  %6 = load i64, ptr %current, align 8
  %7 = icmp ult i64 %6, 0
  %lhs_true_cond = icmp ne i1 %7, false
  br i1 %lhs_true_cond, label %"||_true", label %"||_lhs_false"

for_continue:                                     ; preds = %done11
  ret i64 0

for_break:                                        ; preds = %left9, %left1, %left
  ret i64 1

left:                                             ; preds = %"||_merge"
  br label %for_break

right:                                            ; preds = %"||_merge"
  br label %done

done:                                             ; preds = %right, %unreach
  %8 = load i64, ptr %current, align 8
  %9 = ptrtoint ptr %"$$strcontains_$haystack" to i64
  %10 = mul i64 %8, 1
  %11 = inttoptr i64 %9 to ptr
  %12 = call ptr @llvm.preserve.static.offset(ptr %11)
  %13 = getelementptr i8, ptr %12, i64 %10
  call void @llvm.lifetime.start.p0(i64 -1, ptr %array_access)
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %array_access, i32 1, ptr %13)
  %14 = load i8, ptr %array_access, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %array_access)
  %15 = sext i8 %14 to i64
  %16 = icmp eq i64 %15, 0
  %true_cond4 = icmp ne i1 %16, false
  br i1 %true_cond4, label %left1, label %right2

"||_lhs_false":                                   ; preds = %for_body
  %17 = load i64, ptr %current, align 8
  %18 = icmp uge i64 %17, 1024
  %rhs_true_cond = icmp ne i1 %18, false
  br i1 %rhs_true_cond, label %"||_true", label %"||_false"

"||_false":                                       ; preds = %"||_lhs_false"
  store i1 false, ptr %"||_result", align 1
  br label %"||_merge"

"||_true":                                        ; preds = %"||_lhs_false", %for_body
  store i1 true, ptr %"||_result", align 1
  br label %"||_merge"

"||_merge":                                       ; preds = %"||_true", %"||_false"
  %19 = load i1, ptr %"||_result", align 1
  %true_cond = icmp ne i1 %19, false
  br i1 %true_cond, label %left, label %right

unreach:                                          ; No predecessors!
  br label %done

left1:                                            ; preds = %done
  br label %for_break

right2:                                           ; preds = %done
  br label %done3

done3:                                            ; preds = %right2, %unreach5
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ctx)
  %20 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strcontains_$needle6" = getelementptr %ctx_t.0, ptr %20, i64 0, i32 0
  store ptr %"$$strcontains_$needle", ptr %"ctx.$$strcontains_$needle6", align 8
  %21 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strcontains_$found7" = getelementptr %ctx_t.0, ptr %21, i64 0, i32 1
  store ptr %"$$strcontains_$found", ptr %"ctx.$$strcontains_$found7", align 8
  %22 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$i" = getelementptr %ctx_t.0, ptr %22, i64 0, i32 2
  store ptr %current, ptr %"ctx.$i", align 8
  %23 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strcontains_$haystack8" = getelementptr %ctx_t.0, ptr %23, i64 0, i32 3
  store ptr %"$$strcontains_$haystack", ptr %"ctx.$$strcontains_$haystack8", align 8
  %24 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %ctx.start = getelementptr %ctx_t.0, ptr %24, i64 0, i32 4
  store i64 0, ptr %ctx.start, align 8
  br i1 true, label %is_positive, label %merge

unreach5:                                         ; No predecessors!
  br label %done3

is_positive:                                      ; preds = %done3
  %bpf_loop = call i64 inttoptr (i64 181 to ptr)(i32 1024, ptr @loop_cb.1, ptr %ctx, i64 0)
  br label %merge

merge:                                            ; preds = %is_positive, %done3
  %25 = load i8, ptr %"$$strcontains_$found", align 1
  %true_cond12 = icmp ne i8 %25, 0
  br i1 %true_cond12, label %left9, label %right10

left9:                                            ; preds = %merge
  br label %for_break

right10:                                          ; preds = %merge
  br label %done11

done11:                                           ; preds = %right10, %unreach13
  br label %for_continue

unreach13:                                        ; No predecessors!
  br label %done11
}

; Function Attrs: nounwind
define internal i64 @loop_cb.1(i64 %0, ptr %1) #0 section ".text" !dbg !60 {
for_body:
  %array_access23 = alloca i8, align 1
  %array_access21 = alloca i8, align 1
  %"||_result13" = alloca i1, align 1
  %"$$strcontains_$k" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strcontains_$k")
  store i64 0, ptr %"$$strcontains_$k", align 8
  %array_access = alloca i8, align 1
  %"||_result" = alloca i1, align 1
  %2 = call ptr @llvm.preserve.static.offset(ptr %1)
  %start = getelementptr %ctx_t.0, ptr %2, i64 0, i32 4
  %3 = call ptr @llvm.preserve.static.offset(ptr %1)
  %current = getelementptr %ctx_t.0, ptr %3, i64 0, i32 5
  %4 = load i64, ptr %start, align 8
  %5 = add i64 %4, %0
  store i64 %5, ptr %current, align 8
  %"ctx.$$strcontains_$needle" = getelementptr %ctx_t.0, ptr %1, i64 0, i32 0
  %"$$strcontains_$needle" = load ptr, ptr %"ctx.$$strcontains_$needle", align 8
  %"ctx.$$strcontains_$found" = getelementptr %ctx_t.0, ptr %1, i64 0, i32 1
  %"$$strcontains_$found" = load ptr, ptr %"ctx.$$strcontains_$found", align 8
  %"ctx.$i" = getelementptr %ctx_t.0, ptr %1, i64 0, i32 2
  %"$i" = load ptr, ptr %"ctx.$i", align 8
  %"ctx.$$strcontains_$haystack" = getelementptr %ctx_t.0, ptr %1, i64 0, i32 3
  %"$$strcontains_$haystack" = load ptr, ptr %"ctx.$$strcontains_$haystack", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"||_result")
  %6 = load i64, ptr %current, align 8
  %7 = icmp ult i64 %6, 0
  %lhs_true_cond = icmp ne i1 %7, false
  br i1 %lhs_true_cond, label %"||_true", label %"||_lhs_false"

for_continue:                                     ; preds = %done20
  ret i64 0

for_break:                                        ; preds = %left18, %left6, %left1, %left
  ret i64 1

left:                                             ; preds = %"||_merge"
  br label %for_break

right:                                            ; preds = %"||_merge"
  br label %done

done:                                             ; preds = %right, %unreach
  %8 = load i64, ptr %current, align 8
  %9 = ptrtoint ptr %"$$strcontains_$needle" to i64
  %10 = mul i64 %8, 1
  %11 = inttoptr i64 %9 to ptr
  %12 = call ptr @llvm.preserve.static.offset(ptr %11)
  %13 = getelementptr i8, ptr %12, i64 %10
  call void @llvm.lifetime.start.p0(i64 -1, ptr %array_access)
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %array_access, i32 1, ptr %13)
  %14 = load i8, ptr %array_access, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %array_access)
  %15 = sext i8 %14 to i64
  %16 = icmp eq i64 %15, 0
  %true_cond4 = icmp ne i1 %16, false
  br i1 %true_cond4, label %left1, label %right2

"||_lhs_false":                                   ; preds = %for_body
  %17 = load i64, ptr %current, align 8
  %18 = icmp uge i64 %17, 1024
  %rhs_true_cond = icmp ne i1 %18, false
  br i1 %rhs_true_cond, label %"||_true", label %"||_false"

"||_false":                                       ; preds = %"||_lhs_false"
  store i1 false, ptr %"||_result", align 1
  br label %"||_merge"

"||_true":                                        ; preds = %"||_lhs_false", %for_body
  store i1 true, ptr %"||_result", align 1
  br label %"||_merge"

"||_merge":                                       ; preds = %"||_true", %"||_false"
  %19 = load i1, ptr %"||_result", align 1
  %true_cond = icmp ne i1 %19, false
  br i1 %true_cond, label %left, label %right

unreach:                                          ; No predecessors!
  br label %done

left1:                                            ; preds = %done
  store i8 1, ptr %"$$strcontains_$found", align 1
  br label %for_break

right2:                                           ; preds = %done
  br label %done3

done3:                                            ; preds = %right2, %unreach5
  %20 = load i64, ptr %"$i", align 8
  %21 = load i64, ptr %current, align 8
  %22 = add i64 %20, %21
  store i64 %22, ptr %"$$strcontains_$k", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"||_result13")
  %23 = load i64, ptr %"$$strcontains_$k", align 8
  %24 = icmp ult i64 %23, 0
  %lhs_true_cond14 = icmp ne i1 %24, false
  br i1 %lhs_true_cond14, label %"||_true11", label %"||_lhs_false9"

unreach5:                                         ; No predecessors!
  br label %done3

left6:                                            ; preds = %"||_merge12"
  br label %for_break

right7:                                           ; preds = %"||_merge12"
  br label %done8

done8:                                            ; preds = %right7, %unreach17
  %25 = load i64, ptr %"$$strcontains_$k", align 8
  %26 = ptrtoint ptr %"$$strcontains_$haystack" to i64
  %27 = mul i64 %25, 1
  %28 = inttoptr i64 %26 to ptr
  %29 = call ptr @llvm.preserve.static.offset(ptr %28)
  %30 = getelementptr i8, ptr %29, i64 %27
  call void @llvm.lifetime.start.p0(i64 -1, ptr %array_access21)
  %probe_read_kernel22 = call i64 inttoptr (i64 113 to ptr)(ptr %array_access21, i32 1, ptr %30)
  %31 = load i8, ptr %array_access21, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %array_access21)
  %32 = load i64, ptr %current, align 8
  %33 = ptrtoint ptr %"$$strcontains_$needle" to i64
  %34 = mul i64 %32, 1
  %35 = inttoptr i64 %33 to ptr
  %36 = call ptr @llvm.preserve.static.offset(ptr %35)
  %37 = getelementptr i8, ptr %36, i64 %34
  call void @llvm.lifetime.start.p0(i64 -1, ptr %array_access23)
  %probe_read_kernel24 = call i64 inttoptr (i64 113 to ptr)(ptr %array_access23, i32 1, ptr %37)
  %38 = load i8, ptr %array_access23, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %array_access23)
  %39 = icmp ne i8 %31, %38
  %true_cond25 = icmp ne i1 %39, false
  br i1 %true_cond25, label %left18, label %right19

"||_lhs_false9":                                  ; preds = %done3
  %40 = load i64, ptr %"$$strcontains_$k", align 8
  %41 = icmp uge i64 %40, 1024
  %rhs_true_cond15 = icmp ne i1 %41, false
  br i1 %rhs_true_cond15, label %"||_true11", label %"||_false10"

"||_false10":                                     ; preds = %"||_lhs_false9"
  store i1 false, ptr %"||_result13", align 1
  br label %"||_merge12"

"||_true11":                                      ; preds = %"||_lhs_false9", %done3
  store i1 true, ptr %"||_result13", align 1
  br label %"||_merge12"

"||_merge12":                                     ; preds = %"||_true11", %"||_false10"
  %42 = load i1, ptr %"||_result13", align 1
  %true_cond16 = icmp ne i1 %42, false
  br i1 %true_cond16, label %left6, label %right7

unreach17:                                        ; No predecessors!
  br label %done8

left18:                                           ; preds = %done8
  br label %for_break

right19:                                          ; preds = %done8
  br label %done20

done20:                                           ; preds = %right19, %unreach26
  br label %for_continue

unreach26:                                        ; No predecessors!
  br label %done20
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { memory(none) }

!llvm.dbg.cu = !{!44}
!llvm.module.flags = !{!46, !47}

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
!31 = !DIGlobalVariableExpression(var: !32, expr: !DIExpression())
!32 = distinct !DIGlobalVariable(name: "__bt__var_buf", linkageName: "global", scope: !2, file: !2, type: !33, isLocal: false, isDefinition: true)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !34, size: 32768, elements: !27)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !35, size: 32768, elements: !5)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 8192, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 1024, lowerBound: 0)
!38 = !DIGlobalVariableExpression(var: !39, expr: !DIExpression())
!39 = distinct !DIGlobalVariable(name: "__bt__get_str_buf", linkageName: "global", scope: !2, file: !2, type: !40, isLocal: false, isDefinition: true)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !41, size: 16384, elements: !27)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !35, size: 16384, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 2, lowerBound: 0)
!44 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !45)
!45 = !{!0, !7, !22, !29, !31, !38}
!46 = !{i32 2, !"Debug Info Version", i32 3}
!47 = !{i32 7, !"uwtable", i32 0}
!48 = distinct !DISubprogram(name: "kprobe_foo_1", linkageName: "kprobe_foo_1", scope: !2, file: !2, type: !49, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !44, retainedNodes: !52)
!49 = !DISubroutineType(types: !50)
!50 = !{!26, !51}
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!52 = !{!53}
!53 = !DILocalVariable(name: "ctx", arg: 1, scope: !48, file: !2, type: !51)
!54 = distinct !DISubprogram(name: "loop_cb", linkageName: "loop_cb", scope: !2, file: !2, type: !55, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !44, retainedNodes: !57)
!55 = !DISubroutineType(types: !56)
!56 = !{!26, !26, !51}
!57 = !{!58, !59}
!58 = !DILocalVariable(name: "index", arg: 1, scope: !54, file: !2, type: !26)
!59 = !DILocalVariable(name: "ctx", arg: 2, scope: !54, file: !2, type: !51)
!60 = distinct !DISubprogram(name: "loop_cb_1", linkageName: "loop_cb_1", scope: !2, file: !2, type: !55, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !44, retainedNodes: !61)
!61 = !{!62, !63}
!62 = !DILocalVariable(name: "index", arg: 1, scope: !60, file: !2, type: !26)
!63 = !DILocalVariable(name: "ctx", arg: 2, scope: !60, file: !2, type: !51)
