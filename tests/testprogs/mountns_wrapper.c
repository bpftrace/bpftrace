#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <libgen.h>
#include <linux/limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define errExit(msg)                                                           \
  do                                                                           \
  {                                                                            \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

/*
Run another simple test program in a different mount namespace.

usage: mountns_wrapper some_testprog

The test program directory is bind-mounted into a path that is private to
its mount namespace.

bpftrace will run from the caller's mount namespace, before the unshare. This
will cause bpftrace to not be able to see the path within its own mount
namespace. To access the path, bpftrace must use /proc/PID/root, to see the
mount namespace from the target PID's perspective.

This is useful for both uprobe and USDT tests, to ensure that bpftrace can
target processes running in containers, such as docker.

LIMITATIONS: doesn't pass arguments to test program, as this hasn't been
necessary yet.
*/

int main(int argc, char *argv[])
{

  const char *private_mount = "/tmp/bpftrace-unshare-mountns-test";
  char dpath[PATH_MAX];
  char exe[PATH_MAX];

  if (argc != 2)
    errExit("Must specify test program as only argument.");

  // Enter a new mount namespace
  if (unshare(CLONE_NEWNS) != 0)
    errExit("Failed to unshare");

  // Recursively set the mount namespace to private, so caller can't see
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
    errExit("Failed to make mount private");

  // make a tempdir and bind mount containing testprog folder to it
  if (mkdir(private_mount, 0770) != 0 && (errno != EEXIST))
    errExit("Failed to make private mount dir");

  int idx = readlink("/proc/self/exe", dpath, sizeof(dpath) - 1);
  dpath[idx] = '\0';

  char *dname = dirname(dpath);
  if (mount(dname, private_mount, NULL, MS_BIND, NULL) != 0)
    errExit("Failed to set up private bind mount");

  snprintf(exe, PATH_MAX, "%s/%s", private_mount, argv[1]);
  char *args[] = { exe, NULL };

  return execvp(args[0], args);
}
