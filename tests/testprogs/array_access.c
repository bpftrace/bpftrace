typedef struct MY_STRUCT{
  int x[4];

}mystruct;

void test_struct(mystruct *s) { }

int main(int argc, char **argv)
{
  mystruct s;
  s.x[0] = 1;
  test_struct(&s);
}
