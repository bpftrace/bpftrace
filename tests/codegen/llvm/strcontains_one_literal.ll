; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr }
%ctx_t = type { ptr, ptr, ptr, ptr, ptr, i64, i64 }
%ctx_t.0 = type { ptr, ptr, ptr, ptr, ptr, i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29
@__bt__var_buf = dso_local externally_initialized global [1 x [2 x [1024 x i8]]] zeroinitializer, section ".data.var_buf", !dbg !31
@__bt__get_str_buf = dso_local externally_initialized global [1 x [1 x [1024 x i8]]] zeroinitializer, section ".data.get_str_buf", !dbg !40
@test = global [5 x i8] c"test\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_foo_1(ptr %0) #0 section "s_kprobe_foo_1" !dbg !48 {
entry:
  %ctx = alloca %ctx_t, align 8
  %"$$strstr_4_$found" = alloca i1, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strstr_4_$found")
  store i1 false, ptr %"$$strstr_4_$found", align 1
  %array_access = alloca i8, align 1
  %"$$strstr_4_$needle_size" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strstr_4_$needle_size")
  store i64 0, ptr %"$$strstr_4_$needle_size", align 8
  %"$$strstr_4_$haystack_size" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strstr_4_$haystack_size")
  store i64 0, ptr %"$$strstr_4_$haystack_size", align 8
  %"$$strstr_4_$index" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strstr_4_$index")
  store i64 0, ptr %"$$strstr_4_$index", align 8
  %"$$strstr_3_$needle" = alloca [5 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strstr_3_$needle")
  call void @llvm.memset.p0.i64(ptr align 1 %"$$strstr_3_$needle", i8 0, i64 5, i1 false)
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)() #6
  %1 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %1
  %2 = getelementptr [1 x [2 x [1024 x i8]]], ptr @__bt__var_buf, i64 0, i64 %cpu.id.bounded2, i64 0, i64 0
  %probe_read_kernel3 = call i64 inttoptr (i64 113 to ptr)(ptr %2, i32 1024, ptr null)
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #6
  %3 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %3
  %4 = getelementptr [1 x [1 x [1024 x i8]]], ptr @__bt__get_str_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %4, i32 1024, ptr null)
  %5 = call ptr @llvm.preserve.static.offset(ptr %0)
  %6 = getelementptr i8, ptr %5, i64 112
  %arg0 = load volatile i64, ptr %6, align 8
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to ptr)(ptr %4, i32 1024, i64 %arg0)
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to ptr)(ptr %2, i32 1024, ptr %4)
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %"$$strstr_3_$needle", ptr align 1 @test, i64 5, i1 false)
  store i64 -1, ptr %"$$strstr_4_$index", align 8
  store i64 1024, ptr %"$$strstr_4_$haystack_size", align 8
  store i64 5, ptr %"$$strstr_4_$needle_size", align 8
  %7 = load i64, ptr %"$$strstr_4_$needle_size", align 8
  %8 = icmp eq i64 %7, 0
  %true_cond = icmp ne i1 %8, false
  br i1 %true_cond, label %left, label %right

left:                                             ; preds = %entry
  store i64 0, ptr %"$$strstr_4_$index", align 8
  br label %done

right:                                            ; preds = %entry
  %9 = ptrtoint ptr %"$$strstr_3_$needle" to i64
  %10 = inttoptr i64 %9 to ptr
  %11 = call ptr @llvm.preserve.static.offset(ptr %10)
  %12 = getelementptr i8, ptr %11, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %array_access)
  %probe_read_kernel8 = call i64 inttoptr (i64 113 to ptr)(ptr %array_access, i32 1, ptr %12)
  %13 = load i8, ptr %array_access, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %array_access)
  %14 = sext i8 %13 to i64
  %15 = icmp eq i64 %14, 0
  %true_cond9 = icmp ne i1 %15, false
  br i1 %true_cond9, label %left5, label %right6

done:                                             ; preds = %done7, %left
  %16 = load i64, ptr %"$$strstr_4_$index", align 8
  %17 = icmp sge i64 %16, 0
  ret i64 0

left5:                                            ; preds = %right
  store i64 0, ptr %"$$strstr_4_$index", align 8
  br label %done7

right6:                                           ; preds = %right
  %18 = load i64, ptr %"$$strstr_4_$haystack_size", align 8
  %__bpf_strnstr = call i64 @__bpf_strnstr(ptr %2, ptr %"$$strstr_3_$needle", i64 %18, ptr %"$$strstr_4_$index"), !dbg !54
  %19 = icmp sge i64 %__bpf_strnstr, 0
  %true_cond13 = icmp ne i1 %19, false
  br i1 %true_cond13, label %left10, label %right11

done7:                                            ; preds = %done12, %left5
  br label %done

left10:                                           ; preds = %right6
  br label %done12

right11:                                          ; preds = %right6
  store i1 false, ptr %"$$strstr_4_$found", align 1
  %20 = load i64, ptr %"$$strstr_4_$haystack_size", align 8
  %21 = sub i64 %20, 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ctx)
  %22 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strstr_2_$haystack" = getelementptr %ctx_t, ptr %22, i64 0, i32 0
  store ptr %2, ptr %"ctx.$$strstr_2_$haystack", align 8
  %23 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strstr_4_$needle_size" = getelementptr %ctx_t, ptr %23, i64 0, i32 1
  store ptr %"$$strstr_4_$needle_size", ptr %"ctx.$$strstr_4_$needle_size", align 8
  %24 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strstr_3_$needle" = getelementptr %ctx_t, ptr %24, i64 0, i32 2
  store ptr %"$$strstr_3_$needle", ptr %"ctx.$$strstr_3_$needle", align 8
  %25 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strstr_4_$index" = getelementptr %ctx_t, ptr %25, i64 0, i32 3
  store ptr %"$$strstr_4_$index", ptr %"ctx.$$strstr_4_$index", align 8
  %26 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strstr_4_$found" = getelementptr %ctx_t, ptr %26, i64 0, i32 4
  store ptr %"$$strstr_4_$found", ptr %"ctx.$$strstr_4_$found", align 8
  %27 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %ctx.start = getelementptr %ctx_t, ptr %27, i64 0, i32 5
  store i64 0, ptr %ctx.start, align 8
  %28 = trunc i64 %21 to i32
  %is_positive_cond = icmp sgt i32 %28, 0
  br i1 %is_positive_cond, label %is_positive, label %merge

done12:                                           ; preds = %merge, %left10
  br label %done7

is_positive:                                      ; preds = %right11
  %bpf_loop = call i64 inttoptr (i64 181 to ptr)(i32 %28, ptr @loop_cb, ptr %ctx, i64 0)
  br label %merge

merge:                                            ; preds = %is_positive, %right11
  br label %done12
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #3

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #4

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: alwaysinline nounwind
declare dso_local i64 @__bpf_strnstr(ptr noundef %0, ptr noundef %1, i64 noundef %2, ptr noundef %3) #5

; Function Attrs: nounwind
define internal i64 @loop_cb(i64 %0, ptr %1) #0 section ".text" !dbg !55 {
for_body:
  %ctx = alloca %ctx_t.0, align 8
  %array_access = alloca i8, align 1
  %2 = call ptr @llvm.preserve.static.offset(ptr %1)
  %start = getelementptr %ctx_t, ptr %2, i64 0, i32 5
  %3 = call ptr @llvm.preserve.static.offset(ptr %1)
  %current = getelementptr %ctx_t, ptr %3, i64 0, i32 6
  %4 = load i64, ptr %start, align 8
  %5 = add i64 %4, %0
  store i64 %5, ptr %current, align 8
  %"ctx.$$strstr_2_$haystack" = getelementptr %ctx_t, ptr %1, i64 0, i32 0
  %"$$strstr_2_$haystack" = load ptr, ptr %"ctx.$$strstr_2_$haystack", align 8
  %"ctx.$$strstr_4_$needle_size" = getelementptr %ctx_t, ptr %1, i64 0, i32 1
  %"$$strstr_4_$needle_size" = load ptr, ptr %"ctx.$$strstr_4_$needle_size", align 8
  %"ctx.$$strstr_3_$needle" = getelementptr %ctx_t, ptr %1, i64 0, i32 2
  %"$$strstr_3_$needle" = load ptr, ptr %"ctx.$$strstr_3_$needle", align 8
  %"ctx.$$strstr_4_$index" = getelementptr %ctx_t, ptr %1, i64 0, i32 3
  %"$$strstr_4_$index" = load ptr, ptr %"ctx.$$strstr_4_$index", align 8
  %"ctx.$$strstr_4_$found" = getelementptr %ctx_t, ptr %1, i64 0, i32 4
  %"$$strstr_4_$found" = load ptr, ptr %"ctx.$$strstr_4_$found", align 8
  %6 = load i64, ptr %current, align 8
  %7 = icmp uge i64 %6, 1024
  %true_cond = icmp ne i1 %7, false
  br i1 %true_cond, label %left, label %right

for_continue:                                     ; preds = %done12
  ret i64 0

for_break:                                        ; preds = %left10, %left1, %left
  ret i64 1

left:                                             ; preds = %for_body
  br label %for_break

right:                                            ; preds = %for_body
  br label %done

done:                                             ; preds = %right, %unreach
  %8 = load i64, ptr %current, align 8
  %9 = ptrtoint ptr %"$$strstr_2_$haystack" to i64
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

unreach:                                          ; No predecessors!
  br label %done

left1:                                            ; preds = %done
  br label %for_break

right2:                                           ; preds = %done
  br label %done3

done3:                                            ; preds = %right2, %unreach5
  %17 = load i64, ptr %"$$strstr_4_$needle_size", align 8
  %18 = sub i64 %17, 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ctx)
  %19 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strstr_3_$needle6" = getelementptr %ctx_t.0, ptr %19, i64 0, i32 0
  store ptr %"$$strstr_3_$needle", ptr %"ctx.$$strstr_3_$needle6", align 8
  %20 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strstr_4_$index7" = getelementptr %ctx_t.0, ptr %20, i64 0, i32 1
  store ptr %"$$strstr_4_$index", ptr %"ctx.$$strstr_4_$index7", align 8
  %21 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$i" = getelementptr %ctx_t.0, ptr %21, i64 0, i32 2
  store ptr %current, ptr %"ctx.$i", align 8
  %22 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strstr_4_$found8" = getelementptr %ctx_t.0, ptr %22, i64 0, i32 3
  store ptr %"$$strstr_4_$found", ptr %"ctx.$$strstr_4_$found8", align 8
  %23 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$$strstr_2_$haystack9" = getelementptr %ctx_t.0, ptr %23, i64 0, i32 4
  store ptr %"$$strstr_2_$haystack", ptr %"ctx.$$strstr_2_$haystack9", align 8
  %24 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %ctx.start = getelementptr %ctx_t.0, ptr %24, i64 0, i32 5
  store i64 0, ptr %ctx.start, align 8
  %25 = trunc i64 %18 to i32
  %is_positive_cond = icmp sgt i32 %25, 0
  br i1 %is_positive_cond, label %is_positive, label %merge

unreach5:                                         ; No predecessors!
  br label %done3

is_positive:                                      ; preds = %done3
  %bpf_loop = call i64 inttoptr (i64 181 to ptr)(i32 %25, ptr @loop_cb.1, ptr %ctx, i64 0)
  br label %merge

merge:                                            ; preds = %is_positive, %done3
  %26 = load i1, ptr %"$$strstr_4_$found", align 1
  %true_cond13 = icmp ne i1 %26, false
  br i1 %true_cond13, label %left10, label %right11

left10:                                           ; preds = %merge
  br label %for_break

right11:                                          ; preds = %merge
  br label %done12

done12:                                           ; preds = %right11, %unreach14
  br label %for_continue

unreach14:                                        ; No predecessors!
  br label %done12
}

; Function Attrs: nounwind
define internal i64 @loop_cb.1(i64 %0, ptr %1) #0 section ".text" !dbg !61 {
for_body:
  %array_access16 = alloca i8, align 1
  %array_access14 = alloca i8, align 1
  %"$$strstr_4_$k" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$strstr_4_$k")
  store i64 0, ptr %"$$strstr_4_$k", align 8
  %array_access = alloca i8, align 1
  %2 = call ptr @llvm.preserve.static.offset(ptr %1)
  %start = getelementptr %ctx_t.0, ptr %2, i64 0, i32 5
  %3 = call ptr @llvm.preserve.static.offset(ptr %1)
  %current = getelementptr %ctx_t.0, ptr %3, i64 0, i32 6
  %4 = load i64, ptr %start, align 8
  %5 = add i64 %4, %0
  store i64 %5, ptr %current, align 8
  %"ctx.$$strstr_3_$needle" = getelementptr %ctx_t.0, ptr %1, i64 0, i32 0
  %"$$strstr_3_$needle" = load ptr, ptr %"ctx.$$strstr_3_$needle", align 8
  %"ctx.$$strstr_4_$index" = getelementptr %ctx_t.0, ptr %1, i64 0, i32 1
  %"$$strstr_4_$index" = load ptr, ptr %"ctx.$$strstr_4_$index", align 8
  %"ctx.$i" = getelementptr %ctx_t.0, ptr %1, i64 0, i32 2
  %"$i" = load ptr, ptr %"ctx.$i", align 8
  %"ctx.$$strstr_4_$found" = getelementptr %ctx_t.0, ptr %1, i64 0, i32 3
  %"$$strstr_4_$found" = load ptr, ptr %"ctx.$$strstr_4_$found", align 8
  %"ctx.$$strstr_2_$haystack" = getelementptr %ctx_t.0, ptr %1, i64 0, i32 4
  %"$$strstr_2_$haystack" = load ptr, ptr %"ctx.$$strstr_2_$haystack", align 8
  %6 = load i64, ptr %current, align 8
  %7 = icmp uge i64 %6, 5
  %true_cond = icmp ne i1 %7, false
  br i1 %true_cond, label %left, label %right

for_continue:                                     ; preds = %done13
  ret i64 0

for_break:                                        ; preds = %left11, %left6, %left1, %left
  ret i64 1

left:                                             ; preds = %for_body
  br label %for_break

right:                                            ; preds = %for_body
  br label %done

done:                                             ; preds = %right, %unreach
  %8 = load i64, ptr %current, align 8
  %9 = ptrtoint ptr %"$$strstr_3_$needle" to i64
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

unreach:                                          ; No predecessors!
  br label %done

left1:                                            ; preds = %done
  %17 = load i64, ptr %"$i", align 8
  store i64 %17, ptr %"$$strstr_4_$index", align 8
  store i1 true, ptr %"$$strstr_4_$found", align 1
  br label %for_break

right2:                                           ; preds = %done
  br label %done3

done3:                                            ; preds = %right2, %unreach5
  %18 = load i64, ptr %"$i", align 8
  %19 = load i64, ptr %current, align 8
  %20 = add i64 %18, %19
  store i64 %20, ptr %"$$strstr_4_$k", align 8
  %21 = load i64, ptr %"$$strstr_4_$k", align 8
  %22 = icmp uge i64 %21, 1024
  %true_cond9 = icmp ne i1 %22, false
  br i1 %true_cond9, label %left6, label %right7

unreach5:                                         ; No predecessors!
  br label %done3

left6:                                            ; preds = %done3
  br label %for_break

right7:                                           ; preds = %done3
  br label %done8

done8:                                            ; preds = %right7, %unreach10
  %23 = load i64, ptr %"$$strstr_4_$k", align 8
  %24 = ptrtoint ptr %"$$strstr_2_$haystack" to i64
  %25 = mul i64 %23, 1
  %26 = inttoptr i64 %24 to ptr
  %27 = call ptr @llvm.preserve.static.offset(ptr %26)
  %28 = getelementptr i8, ptr %27, i64 %25
  call void @llvm.lifetime.start.p0(i64 -1, ptr %array_access14)
  %probe_read_kernel15 = call i64 inttoptr (i64 113 to ptr)(ptr %array_access14, i32 1, ptr %28)
  %29 = load i8, ptr %array_access14, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %array_access14)
  %30 = load i64, ptr %current, align 8
  %31 = ptrtoint ptr %"$$strstr_3_$needle" to i64
  %32 = mul i64 %30, 1
  %33 = inttoptr i64 %31 to ptr
  %34 = call ptr @llvm.preserve.static.offset(ptr %33)
  %35 = getelementptr i8, ptr %34, i64 %32
  call void @llvm.lifetime.start.p0(i64 -1, ptr %array_access16)
  %probe_read_kernel17 = call i64 inttoptr (i64 113 to ptr)(ptr %array_access16, i32 1, ptr %35)
  %36 = load i8, ptr %array_access16, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %array_access16)
  %37 = icmp ne i8 %29, %36
  %true_cond18 = icmp ne i1 %37, false
  br i1 %true_cond18, label %left11, label %right12

unreach10:                                        ; No predecessors!
  br label %done8

left11:                                           ; preds = %done8
  br label %for_break

right12:                                          ; preds = %done8
  br label %done13

done13:                                           ; preds = %right12, %unreach19
  br label %for_continue

unreach19:                                        ; No predecessors!
  br label %done13
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #4 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #5 = { alwaysinline nounwind }
attributes #6 = { memory(none) }

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
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !34, size: 16384, elements: !27)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !35, size: 16384, elements: !38)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 8192, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 1024, lowerBound: 0)
!38 = !{!39}
!39 = !DISubrange(count: 2, lowerBound: 0)
!40 = !DIGlobalVariableExpression(var: !41, expr: !DIExpression())
!41 = distinct !DIGlobalVariable(name: "__bt__get_str_buf", linkageName: "global", scope: !2, file: !2, type: !42, isLocal: false, isDefinition: true)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !43, size: 8192, elements: !27)
!43 = !DICompositeType(tag: DW_TAG_array_type, baseType: !35, size: 8192, elements: !27)
!44 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !45)
!45 = !{!0, !7, !22, !29, !31, !40}
!46 = !{i32 2, !"Debug Info Version", i32 3}
!47 = !{i32 7, !"uwtable", i32 0}
!48 = distinct !DISubprogram(name: "kprobe_foo_1", linkageName: "kprobe_foo_1", scope: !2, file: !2, type: !49, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !44, retainedNodes: !52)
!49 = !DISubroutineType(types: !50)
!50 = !{!26, !51}
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!52 = !{!53}
!53 = !DILocalVariable(name: "ctx", arg: 1, scope: !48, file: !2, type: !51)
!54 = !DILocation(line: 104, column: 13, scope: !48)
!55 = distinct !DISubprogram(name: "loop_cb", linkageName: "loop_cb", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !44, retainedNodes: !58)
!56 = !DISubroutineType(types: !57)
!57 = !{!26, !26, !51}
!58 = !{!59, !60}
!59 = !DILocalVariable(name: "index", arg: 1, scope: !55, file: !2, type: !26)
!60 = !DILocalVariable(name: "ctx", arg: 2, scope: !55, file: !2, type: !51)
!61 = distinct !DISubprogram(name: "loop_cb_1", linkageName: "loop_cb_1", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !44, retainedNodes: !62)
!62 = !{!63, !64}
!63 = !DILocalVariable(name: "index", arg: 1, scope: !61, file: !2, type: !26)
!64 = !DILocalVariable(name: "ctx", arg: 2, scope: !61, file: !2, type: !51)
