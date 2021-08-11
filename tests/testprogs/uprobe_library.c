#include <stdio.h>

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  int val;
  FILE *fd = fopen("/dev/zero", "r");
  fread(&val, sizeof(int), 1, fd);
  fclose(fd);
}
