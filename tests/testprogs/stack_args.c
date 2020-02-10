#define ARG(x) int (x) __attribute((unused))

// Declare enough args that some are placed on the stack
void too_many_args(ARG(a), ARG(b), ARG(c), ARG(d), ARG(e), ARG(f), ARG(g), ARG(h)) {}

int main(void)
{
  too_many_args(0, 1, 2, 4, 8, 16, 32, 64);
  return 0;
}
