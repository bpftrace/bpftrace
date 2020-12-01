struct A
{
  int x[4];
};

void test_struct(struct A *a __attribute__((unused))) { }

int main(int argc __attribute__((unused)), char ** argv __attribute__((unused)))
{
  struct A a;
  a.x[0] = 1;
  a.x[1] = 2;
  a.x[2] = 3;
  a.x[3] = 4;
  test_struct(&a);
}
