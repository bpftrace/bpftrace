; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_args" = type { i32, i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"uprobe:/tmp/bpftrace-test-dwarf-data:func_1"(i8* %0) section "s_uprobe:/tmp/bpftrace-test-dwarf-data:func_1_1" {
entry:
  %"@_key" = alloca i64, align 8
  %args = alloca %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_args", align 8
  %1 = bitcast %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_args"* %args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast i8* %0 to i64*
  %3 = getelementptr i64, i64* %2, i64 14
  %arg0 = load volatile i64, i64* %3, align 8
  %4 = trunc i64 %arg0 to i32
  %5 = getelementptr %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_args", %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_args"* %args, i64 0, i32 0
  store i32 %4, i32* %5, align 4
  %6 = bitcast i8* %0 to i64*
  %7 = getelementptr i64, i64* %6, i64 13
  %arg1 = load volatile i64, i64* %7, align 8
  %8 = getelementptr %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_args", %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_args"* %args, i64 0, i32 1
  store i64 %arg1, i64* %8, align 8
  %9 = bitcast i8* %0 to i64*
  %10 = getelementptr i64, i64* %9, i64 12
  %arg2 = load volatile i64, i64* %10, align 8
  %11 = getelementptr %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_args", %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_args"* %args, i64 0, i32 2
  store i64 %arg2, i64* %11, align 8
  %12 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  store i64 0, i64* %"@_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_args"*, i64)*)(i64 %pseudo, i64* %"@_key", %"uprobe:/tmp/bpftrace-test-dwarf-data:func_1_args"* %args, i64 0)
  %13 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
