#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  struct timespec req;
  req.tv_sec = 0;
  req.tv_nsec = 100;
  double time = 100000000.0;
  req.tv_sec = (int)(time / 1e9);
  req.tv_nsec = (int)(time - req.tv_sec * 1e9);
  for (int i = 0; i < 10000; ++i) {
    int r = syscall(SYS_nanosleep, &req, NULL);
    if (r) {
      perror("Error in syscall nanosleep");
      return 1;
    }
  }
  return 0;
}
