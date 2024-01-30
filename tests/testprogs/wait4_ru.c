#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
  struct rusage rusage;
  pid_t pid;

  pid = fork();
  if (pid == 0) {
    exit(0);
  }

  wait4(pid, NULL, 0, &rusage);
  return 0;
}
