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
#include <sys/syscall.h>
#include <unistd.h>

#define errExit(msg)                                                           \
  do                                                                           \
  {                                                                            \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

/*
Run another simple test program in a different mount namespace, to which we
have used pivot root.

usage: mountns_pivot_wrapper some_testprog

This wrapper is very similar to mountns_wrapper, but it pivots the root
before executing the programk. Docker and containerd use pivot_root to
change the root of the running process.

This means that when examining the process via /proc on the host,
realpath of the executable will report paths in the mounted namespace
rather than in the host namespace.

Any binary for use with this wrapper should be compiled as static as it
will not have access to shared libraries.
*/

int main(int argc, char *argv[])
{

  const char *private_mount = "/tmp1/bpftrace-unshare-mountns-pivot-test";
  char dpath[PATH_MAX];
  char exe[PATH_MAX];
  char oldroot[PATH_MAX];

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

  snprintf(oldroot, PATH_MAX, "%s/%s", private_mount, "old");
  if (mkdir(oldroot, 0770) != 0 && (errno != EEXIST))
    errExit("Failed to make old root directory for pivot_root");

  if (syscall(SYS_pivot_root, private_mount, oldroot) != 0) {
    errExit("Couldn't pivot to new root");
  }

  snprintf(exe, PATH_MAX, "/%s", argv[1]);
  char *args[] = { exe, NULL };

  if (chroot("/") != 0) {
    errExit("Couldn't chroot to new root");
  }
  return execvp(args[0], args);
}
