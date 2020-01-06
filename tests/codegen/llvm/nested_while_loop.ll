; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"interval:s:1"(i8* nocapture readnone) local_unnamed_addr section "s_interval:s:1_1" {
entry:
  %"@_newval" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %1 = bitcast i64* %"@_key" to i8*
  %2 = bitcast i64* %"@_newval" to i8*
  br label %while_body

while_cond.loopexit:                              ; preds = %lookup_merge
  %3 = add nuw nsw i64 %"$i.07", 1
  %exitcond8 = icmp eq i64 %3, 101
  br i1 %exitcond8, label %while_end, label %while_body

while_body:                                       ; preds = %while_cond.loopexit, %entry
  %"$i.07" = phi i64 [ 1, %entry ], [ %3, %while_cond.loopexit ]
  br label %while_body2

while_end:                                        ; preds = %while_cond.loopexit
  ret i64 0

while_body2:                                      ; preds = %lookup_merge, %while_body
  %"$j.06" = phi i64 [ 0, %while_body ], [ %6, %lookup_merge ]
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, i64* %"@_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo, i64* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %while_body2
  %cast = bitcast i8* %lookup_elem to i64*
  %4 = load i64, i64* %cast, align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %while_body2, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %4, %lookup_success ], [ 0, %while_body2 ]
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  %5 = add i64 %lookup_elem_val.0, 1
  store i64 %5, i64* %"@_newval", align 8
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo5, i64* nonnull %"@_key", i64* nonnull %"@_newval", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  %6 = add nuw nsw i64 %"$j.06", 1
  %exitcond = icmp eq i64 %6, 101
  br i1 %exitcond, label %while_cond.loopexit, label %while_body2
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
