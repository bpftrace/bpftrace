#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char s[] = "mestring";

__attribute__((noinline)) void function1(char *first __attribute__((unused)),
                                         char *second __attribute__((unused)))
{
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  char *first = malloc(64 * sizeof(char));
  char *second = malloc(64 * sizeof(char));

  // Make sure bytes after the first string are 0s
  memset(first, 0, 64 * sizeof(char));
  memcpy(first, s, sizeof(s));

  // Make sure bytes after second string are 1s
  memset(second, 1, 64 * sizeof(char));
  memcpy(second, s, sizeof(s));

  function1(first, second);

  free(first);
  free(second);
  return 0;
}
