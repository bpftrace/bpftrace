struct Foo
{
  unsigned int a:4,
               b:8,
               c:3,
               d:1,
               e:16;
};

__attribute__((noinline)) unsigned int func(struct Foo *foo)
{
  return foo->b;
}

int main()
{
  struct Foo foo;
  foo.a = 1;
  foo.b = 2;
  foo.c = 5;
  foo.d = 0;
  foo.e = 65535;
  func(&foo);

  return 0;
}
