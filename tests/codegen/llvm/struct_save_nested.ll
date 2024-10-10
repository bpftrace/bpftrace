; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr }
%"struct map_t.3" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_bar = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_foo = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@AT_x = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34
@ringbuf = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !41
@event_loss_counter = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !55
@write_map_val_buf = dso_local externally_initialized global [1 x [1 x [16 x i8]]] zeroinitializer, section ".data.write_map_val_buf", !dbg !57
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !61
@read_map_val_buf = dso_local externally_initialized global [1 x [2 x [16 x i8]]] zeroinitializer, section ".data.read_map_val_buf", !dbg !63

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !70 {
entry:
  %"@x_key" = alloca i64, align 8
  %"@foo_key5" = alloca i64, align 8
  %"@bar_key" = alloca i64, align 8
  %"@foo_key1" = alloca i64, align 8
  %"@foo_key" = alloca i64, align 8
  %1 = getelementptr i64, ptr %0, i64 14
  %arg0 = load volatile i64, ptr %1, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_key")
  store i64 0, ptr %"@foo_key", align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %2 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %2
  %3 = getelementptr [1 x [1 x [16 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %3, i32 16, i64 %arg0)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_foo, ptr %"@foo_key", ptr %3, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_key1")
  store i64 0, ptr %"@foo_key1", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_foo, ptr %"@foo_key1")
  %get_cpu_id2 = call i64 inttoptr (i64 8 to ptr)()
  %4 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded3 = and i64 %get_cpu_id2, %4
  %5 = getelementptr [1 x [2 x [16 x i8]]], ptr @read_map_val_buf, i64 0, i64 %cpu.id.bounded3, i64 0, i64 0
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %5, ptr align 1 %lookup_elem, i64 16, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.memset.p0.i64(ptr align 1 %5, i8 0, i64 16, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_key1")
  %6 = getelementptr [16 x i8], ptr %5, i32 0, i64 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_key")
  store i64 0, ptr %"@bar_key", align 8
  %update_elem4 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_bar, ptr %"@bar_key", ptr %6, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_key5")
  store i64 0, ptr %"@foo_key5", align 8
  %lookup_elem6 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_foo, ptr %"@foo_key5")
  %get_cpu_id10 = call i64 inttoptr (i64 8 to ptr)()
  %7 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded11 = and i64 %get_cpu_id10, %7
  %8 = getelementptr [1 x [2 x [16 x i8]]], ptr @read_map_val_buf, i64 0, i64 %cpu.id.bounded11, i64 1, i64 0
  %map_lookup_cond12 = icmp ne ptr %lookup_elem6, null
  br i1 %map_lookup_cond12, label %lookup_success7, label %lookup_failure8

lookup_success7:                                  ; preds = %lookup_merge
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %8, ptr align 1 %lookup_elem6, i64 16, i1 false)
  br label %lookup_merge9

lookup_failure8:                                  ; preds = %lookup_merge
  call void @llvm.memset.p0.i64(ptr align 1 %8, i8 0, i64 16, i1 false)
  br label %lookup_merge9

lookup_merge9:                                    ; preds = %lookup_failure8, %lookup_success7
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_key5")
  %9 = getelementptr [16 x i8], ptr %8, i32 0, i64 4
  %10 = getelementptr [8 x i8], ptr %9, i32 0, i64 0
  %11 = load volatile i32, ptr %10, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %get_cpu_id13 = call i64 inttoptr (i64 8 to ptr)()
  %12 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded14 = and i64 %get_cpu_id13, %12
  %13 = getelementptr [1 x [1 x [16 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded14, i64 0, i64 0
  %14 = sext i32 %11 to i64
  store i64 %14, ptr %13, align 8
  %update_elem15 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %13, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!67}
!llvm.module.flags = !{!69}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_bar", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!21 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 64, elements: !23)
!22 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!23 = !{!24}
!24 = !DISubrange(count: 8, lowerBound: 0)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "AT_foo", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !28)
!28 = !{!5, !11, !16, !29}
!29 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !30, size: 64, offset: 192)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 128, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 16, lowerBound: 0)
!34 = !DIGlobalVariableExpression(var: !35, expr: !DIExpression())
!35 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!36 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !37)
!37 = !{!5, !11, !16, !38}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !39, size: 64, offset: 192)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!41 = !DIGlobalVariableExpression(var: !42, expr: !DIExpression())
!42 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !43, isLocal: false, isDefinition: true)
!43 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !44)
!44 = !{!45, !50}
!45 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !46, size: 64)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !48)
!48 = !{!49}
!49 = !DISubrange(count: 27, lowerBound: 0)
!50 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !51, size: 64, offset: 64)
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !53)
!53 = !{!54}
!54 = !DISubrange(count: 262144, lowerBound: 0)
!55 = !DIGlobalVariableExpression(var: !56, expr: !DIExpression())
!56 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!57 = !DIGlobalVariableExpression(var: !58, expr: !DIExpression())
!58 = distinct !DIGlobalVariable(name: "write_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !59, isLocal: false, isDefinition: true)
!59 = !DICompositeType(tag: DW_TAG_array_type, baseType: !60, size: 128, elements: !14)
!60 = !DICompositeType(tag: DW_TAG_array_type, baseType: !31, size: 128, elements: !14)
!61 = !DIGlobalVariableExpression(var: !62, expr: !DIExpression())
!62 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !40, isLocal: false, isDefinition: true)
!63 = !DIGlobalVariableExpression(var: !64, expr: !DIExpression())
!64 = distinct !DIGlobalVariable(name: "read_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !65, isLocal: false, isDefinition: true)
!65 = !DICompositeType(tag: DW_TAG_array_type, baseType: !66, size: 256, elements: !14)
!66 = !DICompositeType(tag: DW_TAG_array_type, baseType: !31, size: 256, elements: !9)
!67 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !68)
!68 = !{!0, !25, !34, !41, !55, !57, !61, !63}
!69 = !{i32 2, !"Debug Info Version", i32 3}
!70 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !71, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !67, retainedNodes: !74)
!71 = !DISubroutineType(types: !72)
!72 = !{!40, !73}
!73 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!74 = !{!75}
!75 = !DILocalVariable(name: "ctx", arg: 1, scope: !70, file: !2, type: !73)
