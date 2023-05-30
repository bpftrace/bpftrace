struct Foo1
{
  int a;
  char b;
  long c;
};

struct Foo2
{
  int a;
  union
  {
    struct Foo1 f;
    struct
    {
      char g;
    };
  };
};

struct Foo3
{
  struct Foo1 *foo1;
  const volatile struct Foo2 *restrict foo2;
};

struct Foo3 foo3;

struct Foo3 *func_1(int a, struct Foo1 *foo1, struct Foo2 *foo2)
{
  return 0;
}

struct Foo3 *func_2(int a, int *b, struct Foo1 *foo1)
{
  return 0;
}

struct Foo3 *func_3(int a, int *b, struct Foo1 *foo1)
{
  return 0;
}

struct task_struct
{
  int pid;
  int pgid;
  int : 12; // padding
  int a : 8;
  int b : 1;
  int c : 3;
  int d : 20;
};

struct file
{
  int ino;
};

struct vm_area_struct
{
  unsigned long vm_start;
  unsigned long vm_end;
};

struct bpf_iter__task
{
  struct task_struct *task;
};

struct bpf_iter__task_file
{
  struct task_struct *task;
  struct file *file;
};

struct bpf_iter__task_vma
{
  struct task_struct *task;
  struct vm_area_struct *vma;
};

int bpf_iter_task()
{
  return 0;
}

int bpf_iter_task_file()
{
  return 0;
}

int bpf_iter_task_vma()
{
  return 0;
}

int main(void)
{
  struct bpf_iter__task iter_task;
  struct bpf_iter__task_file iter_task_file;
  struct bpf_iter__task_vma iter_task_vma;

  func_1(0, 0, 0);

  bpf_iter_task();
  bpf_iter_task_file();
  bpf_iter_task_vma();
  return 0;
}
