struct Foo
{
  int a;
  char b[10];
};

int function(struct Foo **f)
{
  return (*f)->a;
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  struct Foo foo1 = { .a = 123, .b = "hello" };
  struct Foo *foo2 = &foo1;
  function(&foo2);

  return 0;
}
