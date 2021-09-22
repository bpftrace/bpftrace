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

int main(void)
{
  func_1(0, 0, 0);
  return 0;
}
