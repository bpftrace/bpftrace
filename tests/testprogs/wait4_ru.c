#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>

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
