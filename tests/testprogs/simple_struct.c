struct Foo
{
  int m;
  int n;
};

int func(struct Foo *foo)
{
  return foo->m;
}

int main()
{
  struct Foo foo;
  foo.m = 2;
  foo.n = 3;
  func(&foo);
  return 0;
}
