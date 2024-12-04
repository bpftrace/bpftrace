; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%print_int_8_t = type <{ i64, i64, [8 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_test = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !50 {
entry:
  %"@test_val" = alloca i64, align 8
  %"@test_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@test_key")
  store i64 1, ptr %"@test_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@test_val")
  store i64 1, ptr %"@test_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_test, ptr %"@test_key", ptr %"@test_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@test_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@test_key")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

define i64 @tracepoint_btf_tag_2(ptr %0) section "s_tracepoint_btf_tag_2" !dbg !57 {
entry:
  %key224 = alloca i32, align 4
  %print_int_8_t219 = alloca %print_int_8_t, align 8
  %lookup_elem_val216 = alloca i64, align 8
  %"@test_key211" = alloca i64, align 8
  %key = alloca i32, align 4
  %print_int_8_t = alloca %print_int_8_t, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@test_key202" = alloca i64, align 8
  %"@test_val" = alloca i64, align 8
  %"@test_key" = alloca i64, align 8
  %strcontains.result = alloca i1, align 1
  %comm = alloca [16 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %comm)
  call void @llvm.memset.p0.i64(ptr align 1 %comm, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to ptr)(ptr %comm, i64 16)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %strcontains.result)
  store i1 true, ptr %strcontains.result, align 1
  %1 = getelementptr i8, ptr %comm, i32 0
  %2 = load i8, ptr %1, align 1
  %3 = getelementptr i8, ptr %comm, i32 0
  %4 = load i8, ptr %3, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char

if_body:                                          ; preds = %strcontains.true
  %5 = call ptr @llvm.preserve.static.offset(ptr %0)
  %6 = getelementptr i8, ptr %5, i64 8
  %7 = load volatile i64, ptr %6, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@test_key")
  store i64 %7, ptr %"@test_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@test_val")
  store i64 1, ptr %"@test_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_test, ptr %"@test_key", ptr %"@test_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@test_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@test_key")
  br label %if_end

if_end:                                           ; preds = %if_body, %strcontains.true
  call void @llvm.lifetime.end.p0(i64 -1, ptr %comm)
  %8 = call ptr @llvm.preserve.static.offset(ptr %0)
  %9 = getelementptr i8, ptr %8, i64 8
  %10 = load volatile i64, ptr %9, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@test_key202")
  store i64 1, ptr %"@test_key202", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_test, ptr %"@test_key202")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

strcontains.true:                                 ; preds = %strcontains.false, %strcontains.secondloop193, %strcontains.secondloop190, %strcontains.secondloop187, %strcontains.secondloop184, %strcontains.firstloop166, %strcontains.secondloop176, %strcontains.secondloop173, %strcontains.secondloop170, %strcontains.secondloop167, %strcontains.firstloop149, %strcontains.secondloop159, %strcontains.secondloop156, %strcontains.secondloop153, %strcontains.secondloop150, %strcontains.firstloop132, %strcontains.secondloop142, %strcontains.secondloop139, %strcontains.secondloop136, %strcontains.secondloop133, %strcontains.firstloop115, %strcontains.secondloop125, %strcontains.secondloop122, %strcontains.secondloop119, %strcontains.secondloop116, %strcontains.firstloop98, %strcontains.secondloop108, %strcontains.secondloop105, %strcontains.secondloop102, %strcontains.secondloop99, %strcontains.firstloop81, %strcontains.secondloop91, %strcontains.secondloop88, %strcontains.secondloop85, %strcontains.secondloop82, %strcontains.firstloop64, %strcontains.secondloop74, %strcontains.secondloop71, %strcontains.secondloop68, %strcontains.secondloop65, %strcontains.firstloop47, %strcontains.secondloop57, %strcontains.secondloop54, %strcontains.secondloop51, %strcontains.secondloop48, %strcontains.firstloop30, %strcontains.secondloop40, %strcontains.secondloop37, %strcontains.secondloop34, %strcontains.secondloop31, %strcontains.firstloop13, %strcontains.secondloop23, %strcontains.secondloop20, %strcontains.secondloop17, %strcontains.secondloop14, %strcontains.firstloop, %strcontains.secondloop7, %strcontains.secondloop4, %strcontains.secondloop1, %strcontains.secondloop, %entry
  %11 = load i1, ptr %strcontains.result, align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %strcontains.result)
  %12 = zext i1 %11 to i64
  %true_cond = icmp ne i64 %12, 0
  br i1 %true_cond, label %if_body, label %if_end

strcontains.false:                                ; preds = %strcontains.firstloop183, %strcontains.secondloop196, %strcontains.secondloop179, %strcontains.secondloop162, %strcontains.secondloop145, %strcontains.secondloop128, %strcontains.secondloop111, %strcontains.secondloop94, %strcontains.secondloop77, %strcontains.secondloop60, %strcontains.secondloop43, %strcontains.secondloop26, %strcontains.secondloop10
  store i1 false, ptr %strcontains.result, align 1
  br label %strcontains.true

strcontains.firstloop:                            ; preds = %strcontains.secondloop10, %strcontains.cmp_char11, %strcontains.cmp_char8, %strcontains.cmp_char5, %strcontains.cmp_char2, %strcontains.cmp_char
  %13 = getelementptr i8, ptr %comm, i32 1
  %14 = load i8, ptr %13, align 1
  %15 = getelementptr i8, ptr %comm, i32 1
  %16 = load i8, ptr %15, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char15

strcontains.secondloop:                           ; preds = %strcontains.cmp_char
  %17 = getelementptr i8, ptr %comm, i32 1
  %18 = load i8, ptr %17, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char2

strcontains.cmp_char:                             ; preds = %entry
  %strcontains.cmp = icmp ne i8 %4, 116
  br i1 %strcontains.cmp, label %strcontains.firstloop, label %strcontains.secondloop

strcontains.secondloop1:                          ; preds = %strcontains.cmp_char2
  %19 = getelementptr i8, ptr %comm, i32 2
  %20 = load i8, ptr %19, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char5

strcontains.cmp_char2:                            ; preds = %strcontains.secondloop
  %strcontains.cmp3 = icmp ne i8 %18, 101
  br i1 %strcontains.cmp3, label %strcontains.firstloop, label %strcontains.secondloop1

strcontains.secondloop4:                          ; preds = %strcontains.cmp_char5
  %21 = getelementptr i8, ptr %comm, i32 3
  %22 = load i8, ptr %21, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char8

strcontains.cmp_char5:                            ; preds = %strcontains.secondloop1
  %strcontains.cmp6 = icmp ne i8 %20, 115
  br i1 %strcontains.cmp6, label %strcontains.firstloop, label %strcontains.secondloop4

strcontains.secondloop7:                          ; preds = %strcontains.cmp_char8
  %23 = getelementptr i8, ptr %comm, i32 4
  %24 = load i8, ptr %23, align 1
  br i1 true, label %strcontains.true, label %strcontains.cmp_char11

strcontains.cmp_char8:                            ; preds = %strcontains.secondloop4
  %strcontains.cmp9 = icmp ne i8 %22, 116
  br i1 %strcontains.cmp9, label %strcontains.firstloop, label %strcontains.secondloop7

strcontains.secondloop10:                         ; preds = %strcontains.cmp_char11
  %strcontains.cmp_null = icmp eq i8 %2, 0
  br i1 %strcontains.cmp_null, label %strcontains.false, label %strcontains.firstloop

strcontains.cmp_char11:                           ; preds = %strcontains.secondloop7
  %strcontains.cmp12 = icmp ne i8 %24, 0
  br i1 %strcontains.cmp12, label %strcontains.firstloop, label %strcontains.secondloop10

strcontains.firstloop13:                          ; preds = %strcontains.secondloop26, %strcontains.cmp_char27, %strcontains.cmp_char24, %strcontains.cmp_char21, %strcontains.cmp_char18, %strcontains.cmp_char15
  %25 = getelementptr i8, ptr %comm, i32 2
  %26 = load i8, ptr %25, align 1
  %27 = getelementptr i8, ptr %comm, i32 2
  %28 = load i8, ptr %27, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char32

strcontains.secondloop14:                         ; preds = %strcontains.cmp_char15
  %29 = getelementptr i8, ptr %comm, i32 2
  %30 = load i8, ptr %29, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char18

strcontains.cmp_char15:                           ; preds = %strcontains.firstloop
  %strcontains.cmp16 = icmp ne i8 %16, 116
  br i1 %strcontains.cmp16, label %strcontains.firstloop13, label %strcontains.secondloop14

strcontains.secondloop17:                         ; preds = %strcontains.cmp_char18
  %31 = getelementptr i8, ptr %comm, i32 3
  %32 = load i8, ptr %31, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char21

strcontains.cmp_char18:                           ; preds = %strcontains.secondloop14
  %strcontains.cmp19 = icmp ne i8 %30, 101
  br i1 %strcontains.cmp19, label %strcontains.firstloop13, label %strcontains.secondloop17

strcontains.secondloop20:                         ; preds = %strcontains.cmp_char21
  %33 = getelementptr i8, ptr %comm, i32 4
  %34 = load i8, ptr %33, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char24

strcontains.cmp_char21:                           ; preds = %strcontains.secondloop17
  %strcontains.cmp22 = icmp ne i8 %32, 115
  br i1 %strcontains.cmp22, label %strcontains.firstloop13, label %strcontains.secondloop20

strcontains.secondloop23:                         ; preds = %strcontains.cmp_char24
  %35 = getelementptr i8, ptr %comm, i32 5
  %36 = load i8, ptr %35, align 1
  br i1 true, label %strcontains.true, label %strcontains.cmp_char27

strcontains.cmp_char24:                           ; preds = %strcontains.secondloop20
  %strcontains.cmp25 = icmp ne i8 %34, 116
  br i1 %strcontains.cmp25, label %strcontains.firstloop13, label %strcontains.secondloop23

strcontains.secondloop26:                         ; preds = %strcontains.cmp_char27
  %strcontains.cmp_null29 = icmp eq i8 %14, 0
  br i1 %strcontains.cmp_null29, label %strcontains.false, label %strcontains.firstloop13

strcontains.cmp_char27:                           ; preds = %strcontains.secondloop23
  %strcontains.cmp28 = icmp ne i8 %36, 0
  br i1 %strcontains.cmp28, label %strcontains.firstloop13, label %strcontains.secondloop26

strcontains.firstloop30:                          ; preds = %strcontains.secondloop43, %strcontains.cmp_char44, %strcontains.cmp_char41, %strcontains.cmp_char38, %strcontains.cmp_char35, %strcontains.cmp_char32
  %37 = getelementptr i8, ptr %comm, i32 3
  %38 = load i8, ptr %37, align 1
  %39 = getelementptr i8, ptr %comm, i32 3
  %40 = load i8, ptr %39, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char49

strcontains.secondloop31:                         ; preds = %strcontains.cmp_char32
  %41 = getelementptr i8, ptr %comm, i32 3
  %42 = load i8, ptr %41, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char35

strcontains.cmp_char32:                           ; preds = %strcontains.firstloop13
  %strcontains.cmp33 = icmp ne i8 %28, 116
  br i1 %strcontains.cmp33, label %strcontains.firstloop30, label %strcontains.secondloop31

strcontains.secondloop34:                         ; preds = %strcontains.cmp_char35
  %43 = getelementptr i8, ptr %comm, i32 4
  %44 = load i8, ptr %43, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char38

strcontains.cmp_char35:                           ; preds = %strcontains.secondloop31
  %strcontains.cmp36 = icmp ne i8 %42, 101
  br i1 %strcontains.cmp36, label %strcontains.firstloop30, label %strcontains.secondloop34

strcontains.secondloop37:                         ; preds = %strcontains.cmp_char38
  %45 = getelementptr i8, ptr %comm, i32 5
  %46 = load i8, ptr %45, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char41

strcontains.cmp_char38:                           ; preds = %strcontains.secondloop34
  %strcontains.cmp39 = icmp ne i8 %44, 115
  br i1 %strcontains.cmp39, label %strcontains.firstloop30, label %strcontains.secondloop37

strcontains.secondloop40:                         ; preds = %strcontains.cmp_char41
  %47 = getelementptr i8, ptr %comm, i32 6
  %48 = load i8, ptr %47, align 1
  br i1 true, label %strcontains.true, label %strcontains.cmp_char44

strcontains.cmp_char41:                           ; preds = %strcontains.secondloop37
  %strcontains.cmp42 = icmp ne i8 %46, 116
  br i1 %strcontains.cmp42, label %strcontains.firstloop30, label %strcontains.secondloop40

strcontains.secondloop43:                         ; preds = %strcontains.cmp_char44
  %strcontains.cmp_null46 = icmp eq i8 %26, 0
  br i1 %strcontains.cmp_null46, label %strcontains.false, label %strcontains.firstloop30

strcontains.cmp_char44:                           ; preds = %strcontains.secondloop40
  %strcontains.cmp45 = icmp ne i8 %48, 0
  br i1 %strcontains.cmp45, label %strcontains.firstloop30, label %strcontains.secondloop43

strcontains.firstloop47:                          ; preds = %strcontains.secondloop60, %strcontains.cmp_char61, %strcontains.cmp_char58, %strcontains.cmp_char55, %strcontains.cmp_char52, %strcontains.cmp_char49
  %49 = getelementptr i8, ptr %comm, i32 4
  %50 = load i8, ptr %49, align 1
  %51 = getelementptr i8, ptr %comm, i32 4
  %52 = load i8, ptr %51, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char66

strcontains.secondloop48:                         ; preds = %strcontains.cmp_char49
  %53 = getelementptr i8, ptr %comm, i32 4
  %54 = load i8, ptr %53, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char52

strcontains.cmp_char49:                           ; preds = %strcontains.firstloop30
  %strcontains.cmp50 = icmp ne i8 %40, 116
  br i1 %strcontains.cmp50, label %strcontains.firstloop47, label %strcontains.secondloop48

strcontains.secondloop51:                         ; preds = %strcontains.cmp_char52
  %55 = getelementptr i8, ptr %comm, i32 5
  %56 = load i8, ptr %55, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char55

strcontains.cmp_char52:                           ; preds = %strcontains.secondloop48
  %strcontains.cmp53 = icmp ne i8 %54, 101
  br i1 %strcontains.cmp53, label %strcontains.firstloop47, label %strcontains.secondloop51

strcontains.secondloop54:                         ; preds = %strcontains.cmp_char55
  %57 = getelementptr i8, ptr %comm, i32 6
  %58 = load i8, ptr %57, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char58

strcontains.cmp_char55:                           ; preds = %strcontains.secondloop51
  %strcontains.cmp56 = icmp ne i8 %56, 115
  br i1 %strcontains.cmp56, label %strcontains.firstloop47, label %strcontains.secondloop54

strcontains.secondloop57:                         ; preds = %strcontains.cmp_char58
  %59 = getelementptr i8, ptr %comm, i32 7
  %60 = load i8, ptr %59, align 1
  br i1 true, label %strcontains.true, label %strcontains.cmp_char61

strcontains.cmp_char58:                           ; preds = %strcontains.secondloop54
  %strcontains.cmp59 = icmp ne i8 %58, 116
  br i1 %strcontains.cmp59, label %strcontains.firstloop47, label %strcontains.secondloop57

strcontains.secondloop60:                         ; preds = %strcontains.cmp_char61
  %strcontains.cmp_null63 = icmp eq i8 %38, 0
  br i1 %strcontains.cmp_null63, label %strcontains.false, label %strcontains.firstloop47

strcontains.cmp_char61:                           ; preds = %strcontains.secondloop57
  %strcontains.cmp62 = icmp ne i8 %60, 0
  br i1 %strcontains.cmp62, label %strcontains.firstloop47, label %strcontains.secondloop60

strcontains.firstloop64:                          ; preds = %strcontains.secondloop77, %strcontains.cmp_char78, %strcontains.cmp_char75, %strcontains.cmp_char72, %strcontains.cmp_char69, %strcontains.cmp_char66
  %61 = getelementptr i8, ptr %comm, i32 5
  %62 = load i8, ptr %61, align 1
  %63 = getelementptr i8, ptr %comm, i32 5
  %64 = load i8, ptr %63, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char83

strcontains.secondloop65:                         ; preds = %strcontains.cmp_char66
  %65 = getelementptr i8, ptr %comm, i32 5
  %66 = load i8, ptr %65, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char69

strcontains.cmp_char66:                           ; preds = %strcontains.firstloop47
  %strcontains.cmp67 = icmp ne i8 %52, 116
  br i1 %strcontains.cmp67, label %strcontains.firstloop64, label %strcontains.secondloop65

strcontains.secondloop68:                         ; preds = %strcontains.cmp_char69
  %67 = getelementptr i8, ptr %comm, i32 6
  %68 = load i8, ptr %67, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char72

strcontains.cmp_char69:                           ; preds = %strcontains.secondloop65
  %strcontains.cmp70 = icmp ne i8 %66, 101
  br i1 %strcontains.cmp70, label %strcontains.firstloop64, label %strcontains.secondloop68

strcontains.secondloop71:                         ; preds = %strcontains.cmp_char72
  %69 = getelementptr i8, ptr %comm, i32 7
  %70 = load i8, ptr %69, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char75

strcontains.cmp_char72:                           ; preds = %strcontains.secondloop68
  %strcontains.cmp73 = icmp ne i8 %68, 115
  br i1 %strcontains.cmp73, label %strcontains.firstloop64, label %strcontains.secondloop71

strcontains.secondloop74:                         ; preds = %strcontains.cmp_char75
  %71 = getelementptr i8, ptr %comm, i32 8
  %72 = load i8, ptr %71, align 1
  br i1 true, label %strcontains.true, label %strcontains.cmp_char78

strcontains.cmp_char75:                           ; preds = %strcontains.secondloop71
  %strcontains.cmp76 = icmp ne i8 %70, 116
  br i1 %strcontains.cmp76, label %strcontains.firstloop64, label %strcontains.secondloop74

strcontains.secondloop77:                         ; preds = %strcontains.cmp_char78
  %strcontains.cmp_null80 = icmp eq i8 %50, 0
  br i1 %strcontains.cmp_null80, label %strcontains.false, label %strcontains.firstloop64

strcontains.cmp_char78:                           ; preds = %strcontains.secondloop74
  %strcontains.cmp79 = icmp ne i8 %72, 0
  br i1 %strcontains.cmp79, label %strcontains.firstloop64, label %strcontains.secondloop77

strcontains.firstloop81:                          ; preds = %strcontains.secondloop94, %strcontains.cmp_char95, %strcontains.cmp_char92, %strcontains.cmp_char89, %strcontains.cmp_char86, %strcontains.cmp_char83
  %73 = getelementptr i8, ptr %comm, i32 6
  %74 = load i8, ptr %73, align 1
  %75 = getelementptr i8, ptr %comm, i32 6
  %76 = load i8, ptr %75, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char100

strcontains.secondloop82:                         ; preds = %strcontains.cmp_char83
  %77 = getelementptr i8, ptr %comm, i32 6
  %78 = load i8, ptr %77, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char86

strcontains.cmp_char83:                           ; preds = %strcontains.firstloop64
  %strcontains.cmp84 = icmp ne i8 %64, 116
  br i1 %strcontains.cmp84, label %strcontains.firstloop81, label %strcontains.secondloop82

strcontains.secondloop85:                         ; preds = %strcontains.cmp_char86
  %79 = getelementptr i8, ptr %comm, i32 7
  %80 = load i8, ptr %79, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char89

strcontains.cmp_char86:                           ; preds = %strcontains.secondloop82
  %strcontains.cmp87 = icmp ne i8 %78, 101
  br i1 %strcontains.cmp87, label %strcontains.firstloop81, label %strcontains.secondloop85

strcontains.secondloop88:                         ; preds = %strcontains.cmp_char89
  %81 = getelementptr i8, ptr %comm, i32 8
  %82 = load i8, ptr %81, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char92

strcontains.cmp_char89:                           ; preds = %strcontains.secondloop85
  %strcontains.cmp90 = icmp ne i8 %80, 115
  br i1 %strcontains.cmp90, label %strcontains.firstloop81, label %strcontains.secondloop88

strcontains.secondloop91:                         ; preds = %strcontains.cmp_char92
  %83 = getelementptr i8, ptr %comm, i32 9
  %84 = load i8, ptr %83, align 1
  br i1 true, label %strcontains.true, label %strcontains.cmp_char95

strcontains.cmp_char92:                           ; preds = %strcontains.secondloop88
  %strcontains.cmp93 = icmp ne i8 %82, 116
  br i1 %strcontains.cmp93, label %strcontains.firstloop81, label %strcontains.secondloop91

strcontains.secondloop94:                         ; preds = %strcontains.cmp_char95
  %strcontains.cmp_null97 = icmp eq i8 %62, 0
  br i1 %strcontains.cmp_null97, label %strcontains.false, label %strcontains.firstloop81

strcontains.cmp_char95:                           ; preds = %strcontains.secondloop91
  %strcontains.cmp96 = icmp ne i8 %84, 0
  br i1 %strcontains.cmp96, label %strcontains.firstloop81, label %strcontains.secondloop94

strcontains.firstloop98:                          ; preds = %strcontains.secondloop111, %strcontains.cmp_char112, %strcontains.cmp_char109, %strcontains.cmp_char106, %strcontains.cmp_char103, %strcontains.cmp_char100
  %85 = getelementptr i8, ptr %comm, i32 7
  %86 = load i8, ptr %85, align 1
  %87 = getelementptr i8, ptr %comm, i32 7
  %88 = load i8, ptr %87, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char117

strcontains.secondloop99:                         ; preds = %strcontains.cmp_char100
  %89 = getelementptr i8, ptr %comm, i32 7
  %90 = load i8, ptr %89, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char103

strcontains.cmp_char100:                          ; preds = %strcontains.firstloop81
  %strcontains.cmp101 = icmp ne i8 %76, 116
  br i1 %strcontains.cmp101, label %strcontains.firstloop98, label %strcontains.secondloop99

strcontains.secondloop102:                        ; preds = %strcontains.cmp_char103
  %91 = getelementptr i8, ptr %comm, i32 8
  %92 = load i8, ptr %91, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char106

strcontains.cmp_char103:                          ; preds = %strcontains.secondloop99
  %strcontains.cmp104 = icmp ne i8 %90, 101
  br i1 %strcontains.cmp104, label %strcontains.firstloop98, label %strcontains.secondloop102

strcontains.secondloop105:                        ; preds = %strcontains.cmp_char106
  %93 = getelementptr i8, ptr %comm, i32 9
  %94 = load i8, ptr %93, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char109

strcontains.cmp_char106:                          ; preds = %strcontains.secondloop102
  %strcontains.cmp107 = icmp ne i8 %92, 115
  br i1 %strcontains.cmp107, label %strcontains.firstloop98, label %strcontains.secondloop105

strcontains.secondloop108:                        ; preds = %strcontains.cmp_char109
  %95 = getelementptr i8, ptr %comm, i32 10
  %96 = load i8, ptr %95, align 1
  br i1 true, label %strcontains.true, label %strcontains.cmp_char112

strcontains.cmp_char109:                          ; preds = %strcontains.secondloop105
  %strcontains.cmp110 = icmp ne i8 %94, 116
  br i1 %strcontains.cmp110, label %strcontains.firstloop98, label %strcontains.secondloop108

strcontains.secondloop111:                        ; preds = %strcontains.cmp_char112
  %strcontains.cmp_null114 = icmp eq i8 %74, 0
  br i1 %strcontains.cmp_null114, label %strcontains.false, label %strcontains.firstloop98

strcontains.cmp_char112:                          ; preds = %strcontains.secondloop108
  %strcontains.cmp113 = icmp ne i8 %96, 0
  br i1 %strcontains.cmp113, label %strcontains.firstloop98, label %strcontains.secondloop111

strcontains.firstloop115:                         ; preds = %strcontains.secondloop128, %strcontains.cmp_char129, %strcontains.cmp_char126, %strcontains.cmp_char123, %strcontains.cmp_char120, %strcontains.cmp_char117
  %97 = getelementptr i8, ptr %comm, i32 8
  %98 = load i8, ptr %97, align 1
  %99 = getelementptr i8, ptr %comm, i32 8
  %100 = load i8, ptr %99, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char134

strcontains.secondloop116:                        ; preds = %strcontains.cmp_char117
  %101 = getelementptr i8, ptr %comm, i32 8
  %102 = load i8, ptr %101, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char120

strcontains.cmp_char117:                          ; preds = %strcontains.firstloop98
  %strcontains.cmp118 = icmp ne i8 %88, 116
  br i1 %strcontains.cmp118, label %strcontains.firstloop115, label %strcontains.secondloop116

strcontains.secondloop119:                        ; preds = %strcontains.cmp_char120
  %103 = getelementptr i8, ptr %comm, i32 9
  %104 = load i8, ptr %103, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char123

strcontains.cmp_char120:                          ; preds = %strcontains.secondloop116
  %strcontains.cmp121 = icmp ne i8 %102, 101
  br i1 %strcontains.cmp121, label %strcontains.firstloop115, label %strcontains.secondloop119

strcontains.secondloop122:                        ; preds = %strcontains.cmp_char123
  %105 = getelementptr i8, ptr %comm, i32 10
  %106 = load i8, ptr %105, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char126

strcontains.cmp_char123:                          ; preds = %strcontains.secondloop119
  %strcontains.cmp124 = icmp ne i8 %104, 115
  br i1 %strcontains.cmp124, label %strcontains.firstloop115, label %strcontains.secondloop122

strcontains.secondloop125:                        ; preds = %strcontains.cmp_char126
  %107 = getelementptr i8, ptr %comm, i32 11
  %108 = load i8, ptr %107, align 1
  br i1 true, label %strcontains.true, label %strcontains.cmp_char129

strcontains.cmp_char126:                          ; preds = %strcontains.secondloop122
  %strcontains.cmp127 = icmp ne i8 %106, 116
  br i1 %strcontains.cmp127, label %strcontains.firstloop115, label %strcontains.secondloop125

strcontains.secondloop128:                        ; preds = %strcontains.cmp_char129
  %strcontains.cmp_null131 = icmp eq i8 %86, 0
  br i1 %strcontains.cmp_null131, label %strcontains.false, label %strcontains.firstloop115

strcontains.cmp_char129:                          ; preds = %strcontains.secondloop125
  %strcontains.cmp130 = icmp ne i8 %108, 0
  br i1 %strcontains.cmp130, label %strcontains.firstloop115, label %strcontains.secondloop128

strcontains.firstloop132:                         ; preds = %strcontains.secondloop145, %strcontains.cmp_char146, %strcontains.cmp_char143, %strcontains.cmp_char140, %strcontains.cmp_char137, %strcontains.cmp_char134
  %109 = getelementptr i8, ptr %comm, i32 9
  %110 = load i8, ptr %109, align 1
  %111 = getelementptr i8, ptr %comm, i32 9
  %112 = load i8, ptr %111, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char151

strcontains.secondloop133:                        ; preds = %strcontains.cmp_char134
  %113 = getelementptr i8, ptr %comm, i32 9
  %114 = load i8, ptr %113, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char137

strcontains.cmp_char134:                          ; preds = %strcontains.firstloop115
  %strcontains.cmp135 = icmp ne i8 %100, 116
  br i1 %strcontains.cmp135, label %strcontains.firstloop132, label %strcontains.secondloop133

strcontains.secondloop136:                        ; preds = %strcontains.cmp_char137
  %115 = getelementptr i8, ptr %comm, i32 10
  %116 = load i8, ptr %115, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char140

strcontains.cmp_char137:                          ; preds = %strcontains.secondloop133
  %strcontains.cmp138 = icmp ne i8 %114, 101
  br i1 %strcontains.cmp138, label %strcontains.firstloop132, label %strcontains.secondloop136

strcontains.secondloop139:                        ; preds = %strcontains.cmp_char140
  %117 = getelementptr i8, ptr %comm, i32 11
  %118 = load i8, ptr %117, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char143

strcontains.cmp_char140:                          ; preds = %strcontains.secondloop136
  %strcontains.cmp141 = icmp ne i8 %116, 115
  br i1 %strcontains.cmp141, label %strcontains.firstloop132, label %strcontains.secondloop139

strcontains.secondloop142:                        ; preds = %strcontains.cmp_char143
  %119 = getelementptr i8, ptr %comm, i32 12
  %120 = load i8, ptr %119, align 1
  br i1 true, label %strcontains.true, label %strcontains.cmp_char146

strcontains.cmp_char143:                          ; preds = %strcontains.secondloop139
  %strcontains.cmp144 = icmp ne i8 %118, 116
  br i1 %strcontains.cmp144, label %strcontains.firstloop132, label %strcontains.secondloop142

strcontains.secondloop145:                        ; preds = %strcontains.cmp_char146
  %strcontains.cmp_null148 = icmp eq i8 %98, 0
  br i1 %strcontains.cmp_null148, label %strcontains.false, label %strcontains.firstloop132

strcontains.cmp_char146:                          ; preds = %strcontains.secondloop142
  %strcontains.cmp147 = icmp ne i8 %120, 0
  br i1 %strcontains.cmp147, label %strcontains.firstloop132, label %strcontains.secondloop145

strcontains.firstloop149:                         ; preds = %strcontains.secondloop162, %strcontains.cmp_char163, %strcontains.cmp_char160, %strcontains.cmp_char157, %strcontains.cmp_char154, %strcontains.cmp_char151
  %121 = getelementptr i8, ptr %comm, i32 10
  %122 = load i8, ptr %121, align 1
  %123 = getelementptr i8, ptr %comm, i32 10
  %124 = load i8, ptr %123, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char168

strcontains.secondloop150:                        ; preds = %strcontains.cmp_char151
  %125 = getelementptr i8, ptr %comm, i32 10
  %126 = load i8, ptr %125, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char154

strcontains.cmp_char151:                          ; preds = %strcontains.firstloop132
  %strcontains.cmp152 = icmp ne i8 %112, 116
  br i1 %strcontains.cmp152, label %strcontains.firstloop149, label %strcontains.secondloop150

strcontains.secondloop153:                        ; preds = %strcontains.cmp_char154
  %127 = getelementptr i8, ptr %comm, i32 11
  %128 = load i8, ptr %127, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char157

strcontains.cmp_char154:                          ; preds = %strcontains.secondloop150
  %strcontains.cmp155 = icmp ne i8 %126, 101
  br i1 %strcontains.cmp155, label %strcontains.firstloop149, label %strcontains.secondloop153

strcontains.secondloop156:                        ; preds = %strcontains.cmp_char157
  %129 = getelementptr i8, ptr %comm, i32 12
  %130 = load i8, ptr %129, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char160

strcontains.cmp_char157:                          ; preds = %strcontains.secondloop153
  %strcontains.cmp158 = icmp ne i8 %128, 115
  br i1 %strcontains.cmp158, label %strcontains.firstloop149, label %strcontains.secondloop156

strcontains.secondloop159:                        ; preds = %strcontains.cmp_char160
  %131 = getelementptr i8, ptr %comm, i32 13
  %132 = load i8, ptr %131, align 1
  br i1 true, label %strcontains.true, label %strcontains.cmp_char163

strcontains.cmp_char160:                          ; preds = %strcontains.secondloop156
  %strcontains.cmp161 = icmp ne i8 %130, 116
  br i1 %strcontains.cmp161, label %strcontains.firstloop149, label %strcontains.secondloop159

strcontains.secondloop162:                        ; preds = %strcontains.cmp_char163
  %strcontains.cmp_null165 = icmp eq i8 %110, 0
  br i1 %strcontains.cmp_null165, label %strcontains.false, label %strcontains.firstloop149

strcontains.cmp_char163:                          ; preds = %strcontains.secondloop159
  %strcontains.cmp164 = icmp ne i8 %132, 0
  br i1 %strcontains.cmp164, label %strcontains.firstloop149, label %strcontains.secondloop162

strcontains.firstloop166:                         ; preds = %strcontains.secondloop179, %strcontains.cmp_char180, %strcontains.cmp_char177, %strcontains.cmp_char174, %strcontains.cmp_char171, %strcontains.cmp_char168
  %133 = getelementptr i8, ptr %comm, i32 11
  %134 = load i8, ptr %133, align 1
  %135 = getelementptr i8, ptr %comm, i32 11
  %136 = load i8, ptr %135, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char185

strcontains.secondloop167:                        ; preds = %strcontains.cmp_char168
  %137 = getelementptr i8, ptr %comm, i32 11
  %138 = load i8, ptr %137, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char171

strcontains.cmp_char168:                          ; preds = %strcontains.firstloop149
  %strcontains.cmp169 = icmp ne i8 %124, 116
  br i1 %strcontains.cmp169, label %strcontains.firstloop166, label %strcontains.secondloop167

strcontains.secondloop170:                        ; preds = %strcontains.cmp_char171
  %139 = getelementptr i8, ptr %comm, i32 12
  %140 = load i8, ptr %139, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char174

strcontains.cmp_char171:                          ; preds = %strcontains.secondloop167
  %strcontains.cmp172 = icmp ne i8 %138, 101
  br i1 %strcontains.cmp172, label %strcontains.firstloop166, label %strcontains.secondloop170

strcontains.secondloop173:                        ; preds = %strcontains.cmp_char174
  %141 = getelementptr i8, ptr %comm, i32 13
  %142 = load i8, ptr %141, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char177

strcontains.cmp_char174:                          ; preds = %strcontains.secondloop170
  %strcontains.cmp175 = icmp ne i8 %140, 115
  br i1 %strcontains.cmp175, label %strcontains.firstloop166, label %strcontains.secondloop173

strcontains.secondloop176:                        ; preds = %strcontains.cmp_char177
  %143 = getelementptr i8, ptr %comm, i32 14
  %144 = load i8, ptr %143, align 1
  br i1 true, label %strcontains.true, label %strcontains.cmp_char180

strcontains.cmp_char177:                          ; preds = %strcontains.secondloop173
  %strcontains.cmp178 = icmp ne i8 %142, 116
  br i1 %strcontains.cmp178, label %strcontains.firstloop166, label %strcontains.secondloop176

strcontains.secondloop179:                        ; preds = %strcontains.cmp_char180
  %strcontains.cmp_null182 = icmp eq i8 %122, 0
  br i1 %strcontains.cmp_null182, label %strcontains.false, label %strcontains.firstloop166

strcontains.cmp_char180:                          ; preds = %strcontains.secondloop176
  %strcontains.cmp181 = icmp ne i8 %144, 0
  br i1 %strcontains.cmp181, label %strcontains.firstloop166, label %strcontains.secondloop179

strcontains.firstloop183:                         ; preds = %strcontains.secondloop196, %strcontains.cmp_char197, %strcontains.cmp_char194, %strcontains.cmp_char191, %strcontains.cmp_char188, %strcontains.cmp_char185
  br label %strcontains.false

strcontains.secondloop184:                        ; preds = %strcontains.cmp_char185
  %145 = getelementptr i8, ptr %comm, i32 12
  %146 = load i8, ptr %145, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char188

strcontains.cmp_char185:                          ; preds = %strcontains.firstloop166
  %strcontains.cmp186 = icmp ne i8 %136, 116
  br i1 %strcontains.cmp186, label %strcontains.firstloop183, label %strcontains.secondloop184

strcontains.secondloop187:                        ; preds = %strcontains.cmp_char188
  %147 = getelementptr i8, ptr %comm, i32 13
  %148 = load i8, ptr %147, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char191

strcontains.cmp_char188:                          ; preds = %strcontains.secondloop184
  %strcontains.cmp189 = icmp ne i8 %146, 101
  br i1 %strcontains.cmp189, label %strcontains.firstloop183, label %strcontains.secondloop187

strcontains.secondloop190:                        ; preds = %strcontains.cmp_char191
  %149 = getelementptr i8, ptr %comm, i32 14
  %150 = load i8, ptr %149, align 1
  br i1 false, label %strcontains.true, label %strcontains.cmp_char194

strcontains.cmp_char191:                          ; preds = %strcontains.secondloop187
  %strcontains.cmp192 = icmp ne i8 %148, 115
  br i1 %strcontains.cmp192, label %strcontains.firstloop183, label %strcontains.secondloop190

strcontains.secondloop193:                        ; preds = %strcontains.cmp_char194
  %151 = getelementptr i8, ptr %comm, i32 15
  %152 = load i8, ptr %151, align 1
  br i1 true, label %strcontains.true, label %strcontains.cmp_char197

strcontains.cmp_char194:                          ; preds = %strcontains.secondloop190
  %strcontains.cmp195 = icmp ne i8 %150, 116
  br i1 %strcontains.cmp195, label %strcontains.firstloop183, label %strcontains.secondloop193

strcontains.secondloop196:                        ; preds = %strcontains.cmp_char197
  %strcontains.cmp_null199 = icmp eq i8 %134, 0
  br i1 %strcontains.cmp_null199, label %strcontains.false, label %strcontains.firstloop183

strcontains.cmp_char197:                          ; preds = %strcontains.secondloop193
  %strcontains.cmp198 = icmp ne i8 %152, 0
  br i1 %strcontains.cmp198, label %strcontains.firstloop183, label %strcontains.secondloop196

if_body200:                                       ; preds = %lookup_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %print_int_8_t)
  %153 = getelementptr %print_int_8_t, ptr %print_int_8_t, i64 0, i32 0
  store i64 30007, ptr %153, align 8
  %154 = getelementptr %print_int_8_t, ptr %print_int_8_t, i64 0, i32 1
  store i64 0, ptr %154, align 8
  %155 = getelementptr %print_int_8_t, ptr %print_int_8_t, i32 0, i32 2
  call void @llvm.memset.p0.i64(ptr align 1 %155, i8 0, i64 8, i1 false)
  store i64 1, ptr %155, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %print_int_8_t, i64 24, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

if_end201:                                        ; preds = %counter_merge, %lookup_merge
  %156 = call ptr @llvm.preserve.static.offset(ptr %0)
  %157 = getelementptr i8, ptr %156, i64 8
  %158 = load volatile i64, ptr %157, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@test_key211")
  store i64 1, ptr %"@test_key211", align 8
  %lookup_elem212 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_test, ptr %"@test_key211")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val216)
  %map_lookup_cond217 = icmp ne ptr %lookup_elem212, null
  br i1 %map_lookup_cond217, label %lookup_success213, label %lookup_failure214

lookup_success:                                   ; preds = %if_end
  %159 = load i64, ptr %lookup_elem, align 8
  store i64 %159, ptr %lookup_elem_val, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %if_end
  store i64 0, ptr %lookup_elem_val, align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %160 = load i64, ptr %lookup_elem_val, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@test_key202")
  %161 = icmp eq i64 %10, %160
  %true_cond203 = icmp ne i1 %161, false
  br i1 %true_cond203, label %if_body200, label %if_end201

event_loss_counter:                               ; preds = %if_body200
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem204 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond208 = icmp ne ptr %lookup_elem204, null
  br i1 %map_lookup_cond208, label %lookup_success205, label %lookup_failure206

counter_merge:                                    ; preds = %lookup_merge207, %if_body200
  call void @llvm.lifetime.end.p0(i64 -1, ptr %print_int_8_t)
  br label %if_end201

lookup_success205:                                ; preds = %event_loss_counter
  %162 = atomicrmw add ptr %lookup_elem204, i64 1 seq_cst, align 8
  br label %lookup_merge207

lookup_failure206:                                ; preds = %event_loss_counter
  br label %lookup_merge207

lookup_merge207:                                  ; preds = %lookup_failure206, %lookup_success205
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

if_body209:                                       ; preds = %lookup_merge215
  call void @llvm.lifetime.start.p0(i64 -1, ptr %print_int_8_t219)
  %163 = getelementptr %print_int_8_t, ptr %print_int_8_t219, i64 0, i32 0
  store i64 30007, ptr %163, align 8
  %164 = getelementptr %print_int_8_t, ptr %print_int_8_t219, i64 0, i32 1
  store i64 1, ptr %164, align 8
  %165 = getelementptr %print_int_8_t, ptr %print_int_8_t219, i32 0, i32 2
  call void @llvm.memset.p0.i64(ptr align 1 %165, i8 0, i64 8, i1 false)
  store i64 1, ptr %165, align 8
  %ringbuf_output220 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %print_int_8_t219, i64 24, i64 0)
  %ringbuf_loss223 = icmp slt i64 %ringbuf_output220, 0
  br i1 %ringbuf_loss223, label %event_loss_counter221, label %counter_merge222

if_end210:                                        ; preds = %counter_merge222, %lookup_merge215
  ret i64 1

lookup_success213:                                ; preds = %if_end201
  %166 = load i64, ptr %lookup_elem212, align 8
  store i64 %166, ptr %lookup_elem_val216, align 8
  br label %lookup_merge215

lookup_failure214:                                ; preds = %if_end201
  store i64 0, ptr %lookup_elem_val216, align 8
  br label %lookup_merge215

lookup_merge215:                                  ; preds = %lookup_failure214, %lookup_success213
  %167 = load i64, ptr %lookup_elem_val216, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val216)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@test_key211")
  %168 = icmp eq i64 %158, %167
  %true_cond218 = icmp ne i1 %168, false
  br i1 %true_cond218, label %if_body209, label %if_end210

event_loss_counter221:                            ; preds = %if_body209
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key224)
  store i32 0, ptr %key224, align 4
  %lookup_elem225 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key224)
  %map_lookup_cond229 = icmp ne ptr %lookup_elem225, null
  br i1 %map_lookup_cond229, label %lookup_success226, label %lookup_failure227

counter_merge222:                                 ; preds = %lookup_merge228, %if_body209
  call void @llvm.lifetime.end.p0(i64 -1, ptr %print_int_8_t219)
  br label %if_end210

lookup_success226:                                ; preds = %event_loss_counter221
  %169 = atomicrmw add ptr %lookup_elem225, i64 1 seq_cst, align 8
  br label %lookup_merge228

lookup_failure227:                                ; preds = %event_loss_counter221
  br label %lookup_merge228

lookup_merge228:                                  ; preds = %lookup_failure227, %lookup_success226
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key224)
  br label %counter_merge222
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #3

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }

!llvm.dbg.cu = !{!47}
!llvm.module.flags = !{!49}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_test", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!35 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
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
!47 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !48)
!48 = !{!0, !20, !34}
!49 = !{i32 2, !"Debug Info Version", i32 3}
!50 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !51, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !47, retainedNodes: !55)
!51 = !DISubroutineType(types: !52)
!52 = !{!18, !53}
!53 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !54, size: 64)
!54 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!55 = !{!56}
!56 = !DILocalVariable(name: "ctx", arg: 1, scope: !50, file: !2, type: !53)
!57 = distinct !DISubprogram(name: "tracepoint_btf_tag_2", linkageName: "tracepoint_btf_tag_2", scope: !2, file: !2, type: !51, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !47, retainedNodes: !58)
!58 = !{!59}
!59 = !DILocalVariable(name: "ctx", arg: 1, scope: !57, file: !2, type: !53)
