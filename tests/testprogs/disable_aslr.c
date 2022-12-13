#include <sys/personality.h>
#include <unistd.h>

int main(int argc __attribute__((unused)), char **argv)
{
  personality(ADDR_NO_RANDOMIZE);
  execv(argv[1], argv + 1);
}
