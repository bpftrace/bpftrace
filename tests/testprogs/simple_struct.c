struct Foo
{
  int m;
};

int func(struct Foo *foo)
{
  return foo->m;
}

int main()
{
  struct Foo foo;
  foo.m = 2;
  func(&foo);
  return 0;
}
