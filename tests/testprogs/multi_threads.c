#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

/* could be probed in tests */
void stub(void)
{
}

void set_thread_name(const char *name)
{
  if (pthread_setname_np(pthread_self(), name)) {
    perror("pthread_setname_np");
    exit(EXIT_FAILURE);
  }
}

void *grandson_work(void *)
{
  set_thread_name("grandson-thread");
  stub();
  return NULL;
}

void *son_work(void *)
{
  pthread_t tid;

  set_thread_name("son-thread");
  stub();

  if (pthread_create(&tid, NULL, grandson_work, 0)) {
    perror("pthread_create");
    exit(EXIT_FAILURE);
  }

  if (pthread_join(tid, NULL)) {
    perror("pthread_join");
    exit(EXIT_FAILURE);
  }

  return NULL;
}

void real_parent(void)
{
  pthread_t tid;

  set_thread_name("parent-thread");

  if (pthread_create(&tid, NULL, son_work, 0)) {
    perror("pthread_create");
    exit(EXIT_FAILURE);
  }

  if (pthread_join(tid, NULL)) {
    perror("pthread_join");
    exit(EXIT_FAILURE);
  }
  exit(EXIT_SUCCESS);
}

int main(void)
{
  pid_t pid;

  // When testing pcomm, pcomm=$SHELL is uncertain (bash, sh, zsh, etc.), so a
  // new process needs to be forked first to act as the real_parent.
  pid = fork();
  if (pid == 0) {
    real_parent();
  }

  waitpid(pid, NULL, 0);
  return 0;
}
