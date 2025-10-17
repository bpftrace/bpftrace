#define __KERNEL__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

extern int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it,
                                 struct task_struct *task, u64 addr) __ksym __weak;
extern struct vm_area_struct *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it) __ksym __weak;
extern void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it) __ksym __weak;

unsigned long __bpf_task_map_file_min_addr(unsigned long ino)
{
  // linux >= 6.7
  if (!bpf_iter_task_vma_new || !bpf_iter_task_vma_destroy || !bpf_iter_task_vma_next)
    return 0;

  struct bpf_iter_task_vma vma_it;
  struct vm_area_struct *vma;
  struct task_struct *cur_task = bpf_get_current_task_btf();
  unsigned long off = 0;


  if (bpf_iter_task_vma_new(&vma_it, cur_task, 0)) {
    bpf_iter_task_vma_destroy(&vma_it);
    return 0;
  }

  while ((vma = bpf_iter_task_vma_next(&vma_it))) {
    struct file *file = vma->vm_file;
    if (file) {
      struct inode *inode = file->f_inode;
      // In the VMAs, the first matching inode is the lowest address offset,
      // see /proc/PID/maps.
      if (inode->i_ino == ino) {
        off = vma->vm_start;
        break;
      }
    }
  }

  bpf_iter_task_vma_destroy(&vma_it);
  return off;
}
