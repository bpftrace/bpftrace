struct Foo {
  int m;
  int n;
};

int func(struct Foo *foo)
{
  return foo->m;
}

int n_func(int *n)
{
  return *n;
}

int main()
{
  struct Foo foo;
  foo.m = 2;
  foo.n = 3;
  func(&foo);
  n_func(&foo.n);
  return 0;
}
