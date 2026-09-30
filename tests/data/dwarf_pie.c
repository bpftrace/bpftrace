__attribute__((noinline)) int pie_target(int value)
{
  return value + 1;
}

int main(void)
{
  return pie_target(41);
}
