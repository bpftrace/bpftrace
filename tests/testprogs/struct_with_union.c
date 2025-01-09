union N {
  int i;
  float f;
};

struct Foo {
  int m;
  union N n;
};

int func(struct Foo *foo)
{
  return foo->m;
}

int main()
{
  struct Foo foo;
  foo.m = 2;
  foo.n.i = 5;
  func(&foo);
  return 0;
}
