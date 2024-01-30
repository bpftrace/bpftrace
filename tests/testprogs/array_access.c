#include <stdint.h>

struct A {
  int x[4];
  uint8_t y[4];
};

struct B {
  int y[2][2];
};

struct C {
  int *z[4];
};

struct D {
  int x;
  int y[0];
  int z;
};

void test_array(int *a __attribute__((unused)))
{
}

void test_arrays(struct A *a __attribute__((unused)),
                 struct A *d __attribute__((unused)))
{
}

void test_struct(struct A *a __attribute__((unused)),
                 struct B *b __attribute__((unused)))
{
}

void test_ptr_array(struct C *c __attribute__((unused)))
{
}

void test_variable_array(struct D *d __attribute__((unused)))
{
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  struct A a;
  a.x[0] = 1;
  a.x[1] = 2;
  a.x[2] = 3;
  a.x[3] = 4;
  a.y[0] = 0xaa;
  a.y[1] = 0xbb;
  a.y[2] = 0xcc;
  a.y[3] = 0xdd;

  struct B b;
  b.y[0][0] = 5;
  b.y[0][1] = 6;
  b.y[1][0] = 7;
  b.y[1][1] = 8;
  test_struct(&a, &b);
  test_array(a.x);

  struct C c;
  c.z[0] = &a.x[0];
  c.z[1] = &a.x[1];
  c.z[2] = &a.x[2];
  c.z[3] = &a.x[3];
  test_ptr_array(&c);

  struct A d;
  d.x[0] = 4;
  d.x[1] = 3;
  d.x[2] = 2;
  d.x[3] = 1;
  test_arrays(&a, &d);

  struct D e;
  e.z = 1;
  test_variable_array(&e);
}
