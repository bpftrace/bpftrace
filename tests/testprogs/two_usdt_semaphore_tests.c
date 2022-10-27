#include <unistd.h>

int main(int argc __attribute__((unused)), char **argv)
{
  int pid = fork();

  if (pid < 0)
    return 1;
  else if (pid == 0)
    // child, test 1
    execv("./testprogs/usdt_semaphore_test", argv);
  else
    // parent, test 2
    execv("./testprogs/usdt_semaphore_test", argv);

  return 0;
}
