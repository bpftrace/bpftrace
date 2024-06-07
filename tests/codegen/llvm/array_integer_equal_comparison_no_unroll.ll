; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@event_loss_counter = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !40 {
entry:
  %key = alloca i32, align 4
  %perfdata = alloca i64, align 8
  %n = alloca i32, align 4
  %i = alloca i32, align 4
  %arraycmp.result = alloca i1, align 1
  %v2 = alloca i32, align 4
  %v1 = alloca i32, align 4
  %"$b" = alloca i64, align 8
  %1 = bitcast i64* %"$b" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$b", align 8
  %"$a" = alloca i64, align 8
  %2 = bitcast i64* %"$a" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"$a", align 8
  %3 = bitcast i8* %0 to i64*
  %4 = getelementptr i64, i64* %3, i64 14
  %arg0 = load volatile i64, i64* %4, align 8
  %5 = add i64 %arg0, 0
  store i64 %5, i64* %"$a", align 8
  %6 = bitcast i8* %0 to i64*
  %7 = getelementptr i64, i64* %6, i64 14
  %arg01 = load volatile i64, i64* %7, align 8
  %8 = add i64 %arg01, 0
  store i64 %8, i64* %"$b", align 8
  %9 = load i64, i64* %"$a", align 8
  %10 = load i64, i64* %"$b", align 8
  %11 = bitcast i32* %v1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  %12 = bitcast i32* %v2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  %13 = bitcast i1* %arraycmp.result to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i1 true, i1* %arraycmp.result, align 1
  %14 = inttoptr i64 %9 to [4 x i32]*
  %15 = inttoptr i64 %10 to [4 x i32]*
  %16 = bitcast i32* %i to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  %17 = bitcast i32* %n to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  store i32 0, i32* %i, align 4
  store i32 4, i32* %n, align 4
  br label %while_cond

if_body:                                          ; preds = %arraycmp.done
  %18 = bitcast i64* %perfdata to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i64 30000, i64* %perfdata, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t"*, i64*, i64, i64)*)(%"struct map_t"* @ringbuf, i64* %perfdata, i64 8, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

if_end:                                           ; preds = %deadcode, %arraycmp.done
  ret i64 0

while_cond:                                       ; preds = %arraycmp.loop, %entry
  %19 = load i32, i32* %n, align 4
  %20 = load i32, i32* %i, align 4
  %size_check = icmp slt i32 %20, %19
  br i1 %size_check, label %while_body, label %arraycmp.done, !llvm.loop !47

while_body:                                       ; preds = %while_cond
  %21 = load i32, i32* %i, align 4
  %22 = getelementptr [4 x i32], [4 x i32]* %14, i32 0, i32 %21
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i32*, i32, i32*)*)(i32* %v1, i32 4, i32* %22)
  %23 = load i32, i32* %v1, align 4
  %24 = load i32, i32* %i, align 4
  %25 = getelementptr [4 x i32], [4 x i32]* %15, i32 0, i32 %24
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i32*)*)(i32* %v2, i32 4, i32* %25)
  %26 = load i32, i32* %v2, align 4
  %arraycmp.cmp = icmp ne i32 %23, %26
  br i1 %arraycmp.cmp, label %arraycmp.false, label %arraycmp.loop

arraycmp.false:                                   ; preds = %while_body
  store i1 false, i1* %arraycmp.result, align 1
  br label %arraycmp.done

arraycmp.done:                                    ; preds = %arraycmp.false, %while_cond
  %27 = load i1, i1* %arraycmp.result, align 1
  %28 = bitcast i1* %arraycmp.result to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %28)
  %29 = bitcast i32* %v1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %29)
  %30 = bitcast i32* %v2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %30)
  %31 = zext i1 %27 to i64
  %true_cond = icmp ne i64 %31, 0
  br i1 %true_cond, label %if_body, label %if_end

arraycmp.loop:                                    ; preds = %while_body
  %32 = load i32, i32* %i, align 4
  %33 = add i32 %32, 1
  store i32 %33, i32* %i, align 4
  br label %while_cond

event_loss_counter:                               ; preds = %if_body
  %34 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %34)
  store i32 0, i32* %key, align 4
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t.0"*, i32*)*)(%"struct map_t.0"* @event_loss_counter, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %if_body
  %35 = bitcast i64* %perfdata to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %35)
  ret i64 0

lookup_success:                                   ; preds = %event_loss_counter
  %36 = bitcast i8* %lookup_elem to i64*
  %37 = atomicrmw add i64* %36, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %38 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %38)
  br label %counter_merge

deadcode:                                         ; No predecessors!
  br label %if_end
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }

!llvm.dbg.cu = !{!36}
!llvm.module.flags = !{!39}

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
!36 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !37, globals: !38)
!37 = !{}
!38 = !{!0, !16}
!39 = !{i32 2, !"Debug Info Version", i32 3}
!40 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !41, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !36, retainedNodes: !45)
!41 = !DISubroutineType(types: !42)
!42 = !{!35, !43}
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !44, size: 64)
!44 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!45 = !{!46}
!46 = !DILocalVariable(name: "ctx", arg: 1, scope: !40, file: !2, type: !43)
!47 = distinct !{!47, !48}
!48 = !{!"llvm.loop.unroll.disable"}
