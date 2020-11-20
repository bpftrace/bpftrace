struct Foo
{
  unsigned int a:4,
               b:8,
               c:3,
               d:1,
               e:16;
};

struct Bar
{
  unsigned short a : 4, b : 8, c : 3, d : 1;
  unsigned int e : 9, f : 15, g : 1, h : 2, i : 5;
};

__attribute__((noinline)) unsigned int func(struct Foo *foo)
{
  return foo->b;
}
__attribute__((noinline)) short func2(struct Bar *bar)
{
  return bar->b;
}

int main()
{
  struct Foo foo;
  struct Bar bar;
  foo.a = 1;
  foo.b = 2;
  foo.c = 5;
  foo.d = 0;
  foo.e = 65535;
  func(&foo);
  bar.a = 1;
  bar.b = 217;
  bar.c = 5;
  bar.d = 1;
  bar.e = 500;
  bar.f = 31117;
  bar.g = 1;
  bar.h = 2;
  bar.i = 27;
  func2(&bar);
  return 0;
}
