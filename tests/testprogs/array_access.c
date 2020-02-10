typedef struct MY_STRUCT{
  int x[4];

}mystruct;

void test_struct(mystruct *s __attribute__((unused))) { }

int main(int argc __attribute__((unused)), char ** argv __attribute__((unused)))
{
  mystruct s;
  s.x[0] = 1;
  test_struct(&s);
}
