#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define FILE_NAME_LENGTH 50
#define MAX_ARG_LENGTH 20

void usage()
{
  printf("Usage:\n");
  printf("\t./syscall <syscall name> [<arguments>]\n");
  printf("Supported Syscalls:\n");
  printf("\t nanosleep [$N] (default args: 100ns)\n");
  printf("\t open\n");
  printf("\t openat\n");
  printf("\t read\n");
}

void gen_nanosleep(int argc, char *argv[])
{
  struct timespec req;
  const char *arg = argv[2];
  req.tv_sec = 0;
  req.tv_nsec = 100;
  if (argc > 2)
  {
    if (!isdigit(*arg) || !isdigit(arg[strlen(arg) - 1]))
    {
      printf("Invalid argument: %s; the argument should be a non-negative "
             "number with no sign\n",
             arg);
      return;
    }
    double time;
    char tail = '\0';
    sscanf(arg, "%le%c", &time, &tail);
    if (tail != '\0')
    {
      printf("Argument '%s' should only contain numerial charactors.\n", arg);
      return;
    }
    if (time < 0)
    {
      printf("Invalid argument '%s', the argument should not be negative", arg);
      return;
    }
    // if time is less than 1 nsec, round up to 1 nsec, as with sleep command
    if (time > 0 && time < 1)
    {
      time = 1;
    }
    req.tv_sec = (int)(time / 1e9);
    req.tv_nsec = (int)(time - req.tv_sec * 1e9);
  }
  int r = syscall(SYS_nanosleep, &req, NULL);
  if (r)
    perror("Error in syscall nanosleep");
}

void gen_open_openat(bool is_sys_open)
{
  const char *file_path = "/tmp/bpftrace_runtime_test_syscall_gen_open_temp";
  int fd = is_sys_open ? syscall(SYS_open, file_path, O_CREAT)
                       : syscall(SYS_openat, AT_FDCWD, file_path, O_CREAT);
  if (fd < 0)
  {
    perror("Error in syscall open/openat");
    return;
  }
  close(fd);
  remove(file_path);
}

void gen_read()
{
  const char *file_path = "/tmp/bpftrace_runtime_test_syscall_gen_read_temp";
  int fd = open(file_path, O_CREAT);
  if (fd < 0)
  {
    perror("Error in syscall read when creating temp file");
    return;
  }
  char buf[10];
  int r = syscall(SYS_read, fd, (void *)buf, 0);
  if (r < 0)
  {
    perror("Error in syscall read");
  }
  close(fd);
  remove(file_path);
}

int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    usage();
    return 0;
  }
  const char *syscall_name = argv[1];
  bool is_sys_open = false;

  if (strcmp("--help", syscall_name) == 0 || strcmp("-h", syscall_name) == 0)
  {
    usage();
  }
  else if (strcmp("nanosleep", syscall_name) == 0)
  {
    gen_nanosleep(argc, argv);
  }
  else if ((is_sys_open = (strcmp("open", syscall_name) == 0)) ||
           strcmp("openat", syscall_name) == 0)
  {
    gen_open_openat(is_sys_open);
  }
  else if (strcmp("read", syscall_name) == 0)
  {
    gen_read();
  }
  else if (strcmp("nop", syscall_name) == 0)
  {
    // do nothing
  }
  else
  {
    printf("%s is not supported yet\n", syscall_name);
    usage();
  }

  return 0;
}