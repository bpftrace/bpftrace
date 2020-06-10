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

void usage()
{
  printf("Usage:\n");
  printf("\t./syscall <syscall name> [<arguments>]\n");
  printf("Supported Syscalls:\n");
  printf("\t nanosleep [$N] (default args: 100ns)\n");
  printf("\t open\n");
  printf("\t openat\n");
  printf("\t read\n");
  printf("\t execve <path> [<argument>] (allows at most 1 argument for now)\n");
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
      exit(1);
    }
    double time;
    char tail = '\0';
    sscanf(arg, "%le%c", &time, &tail);
    if (tail != '\0')
    {
      printf("Argument '%s' should only contain numerial charactors\n", arg);
      exit(1);
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
  {
    perror("Error in syscall nanosleep");
    exit(1);
  }
}

// the returned string was created with malloc()
// @ path_suffix should start with '/'
char *get_tmp_file_path(const char *path_suffix)
{
  const char *tmpdir = getenv("TMPDIR");
  if (tmpdir == NULL)
  {
    tmpdir = "/tmp";
  }
  int path_len = strlen(tmpdir) + strlen(path_suffix);
  char *path = (char *)malloc((path_len + 1) * sizeof(char));
  memset(path, '\0', path_len + 1);
  strncat(path, tmpdir, strlen(tmpdir));
  strncat(path, path_suffix, strlen(path_suffix));
  return path;
}

void gen_open_openat(bool is_sys_open)
{
  char *file_path = get_tmp_file_path(
      "/bpftrace_runtime_test_syscall_gen_open_temp");
  int fd = is_sys_open ? syscall(SYS_open, file_path, O_CREAT)
                       : syscall(SYS_openat, AT_FDCWD, file_path, O_CREAT);
  if (fd < 0)
  {
    perror("Error in syscall open/openat");
    free(file_path);
    exit(1);
  }
  close(fd);
  remove(file_path);
  free(file_path);
}

void gen_read()
{
  char *file_path = get_tmp_file_path(
      "/bpftrace_runtime_test_syscall_gen_read_temp");
  int fd = open(file_path, O_CREAT);
  if (fd < 0)
  {
    perror("Error in syscall read when creating temp file");
    free(file_path);
    exit(1);
  }
  char buf[10];
  int r = syscall(SYS_read, fd, (void *)buf, 0);
  close(fd);
  remove(file_path);
  free(file_path);
  if (r < 0)
  {
    perror("Error in syscall read");
    exit(1);
  }
}

void gen_execve(int argc, char *argv[])
{
  if (argc < 3)
  {
    printf("Indicate which process to execute.\n");
    exit(1);
  }
  char *newargv[] = { argv[2], NULL, NULL };
  char *newenv[] = { NULL };
  if (argc > 3)
  {
    newargv[1] = argv[3];
  }
  syscall(SYS_execve, argv[2], newargv, newenv);
  // execve returns on error
  perror("Error in syscall execve");
  exit(1);
}

int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    usage();
    exit(1);
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
  else if (strcmp("execve", syscall_name) == 0)
  {
    gen_execve(argc, argv);
  }
  else
  {
    printf("%s is not supported yet\n", syscall_name);
    usage();
  }

  return 0;
}