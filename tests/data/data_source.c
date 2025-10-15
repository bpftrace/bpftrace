struct Foo1 {
  int a;
  char b;
  long c;
};

struct Foo2 {
  int a;
  union {
    struct Foo1 f;
    struct {
      char g;
    };
  };
};

struct Foo3 {
  struct Foo1 *foo1;
  const volatile struct Foo2 *restrict foo2;
};

struct Foo3 foo3;

struct Foo4 {
  int pid;
  int pgid;
  unsigned int : 12; // padding
  unsigned int a : 8;
  unsigned int b : 1;
  unsigned int c : 3;
  unsigned int d : 20;
};

enum FooEnum {
  VALUE
};

struct Foo3 *func_1(int a,
                    struct Foo1 *foo1,
                    struct Foo2 *foo2,
                    struct Foo3 *foo3,
                    struct Foo4 *foo4)
{
  return 0;
}

struct Foo3 *func_2(int a, int *b, struct Foo1 *foo1)
{
  return 0;
}

// __attribute__((noinline)) is needed due to a LLDB/GCC compatibility bug
struct Foo3 *__attribute__((noinline)) func_3(int a, int *b, struct Foo1 *foo1)
{
  return 0;
}

struct FirstFieldsAreAnonUnion {
  union {
    int a;
    int b;
  };
  int c;
};

struct FirstFieldsAreAnonUnion first_fields_anon_union;

struct Arrays {
  int int_arr[4];
  char char_arr[8];
  char char_arr2[16];
  void *ptr_arr[2];
  int multi_dim[3][2];
  int zero[0];
  int flexible[];
};
struct Arrays arrays;

struct Arrays *func_arrays(struct Arrays *arr)
{
  return 0;
}

struct ArrayWithCompoundData {
  struct Foo3 *data[2];
};

typedef struct {
  int a;
} AnonStructTypedef;

AnonStructTypedef AnonTypedefArray[8];

struct anon_structs {
  AnonStructTypedef AnonTypedefArray[8];
  struct {
    int a;
    int b;
    struct {
      int c;
      int d;
    } AnonSubArray[2];
  } AnonArray[4];
};

void func_array_with_compound_data(struct ArrayWithCompoundData *arr)
{
}

void func_anon_struct(struct anon_structs *AnonStruct,
                      AnonStructTypedef *AnonTypedef)
{
}

struct task_struct {
  int pid;
  int pgid;
};

struct file {
  int ino;
};

struct vm_area_struct {
  unsigned long vm_start;
  unsigned long vm_end;
};

struct bpf_iter__task {
  struct task_struct *task;
};

struct bpf_iter__task_file {
  struct task_struct *task;
  struct file *file;
};

struct bpf_iter__task_vma {
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

// kfunc definitions
struct bpf_map {};
long bpf_map_sum_elem_count(const struct bpf_map *map)
{
  return 0;
}

long __probestub_event_rt(void *__data, long first_real_arg)
{
  return first_real_arg;
}

struct sock {
  int cookie;
};

void tcp_shutdown(struct sock *sk, int how)
{
}

// kernel percpu variables
__attribute__((section(".data..percpu"))) unsigned long process_counts;

// Make sure all new mocked kernel functions are called in this main (below)
// so they don't get optimzed away
int main(void)
{
  struct bpf_iter__task iter_task;
  struct bpf_iter__task_file iter_task_file;
  struct bpf_iter__task_vma iter_task_vma;
  struct bpf_map bpf_map;
  struct sock sk;
  enum FooEnum e;

  func_1(0, 0, 0, 0, 0);

  bpf_iter_task();
  bpf_iter_task_file();
  bpf_iter_task_vma();
  bpf_map_sum_elem_count(&bpf_map);
  __probestub_event_rt((void *)&bpf_map, 1);
  tcp_shutdown(&sk, 0);
  return 0;
}
