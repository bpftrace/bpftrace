#include <stdlib.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* could be probed */
void stub(void)
{
}

void setname(const char *name)
{
  if (prctl(PR_SET_NAME, name, 0, 0, 0)) {
    perror("prctl: failed to set process name");
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char *argv[])
{
  pid_t son;

  setname("parent-proc");

  son = fork();
  if (son == 0) {
    pid_t grandson;

    setname("son-proc");
    stub();
    grandson = fork();
    if (grandson == 0) {
      setname("grandson-proc");
      stub();
      exit(0);
    }
    waitpid(grandson, NULL, 0);
    exit(0);
  }

  waitpid(son, NULL, 0);
  return 0;
}
