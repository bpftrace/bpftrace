#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/* could be probed in tests */
void stub(void)
{
}

void setname(const char *name)
{
  if (pthread_setname_np(pthread_self(), name)) {
    perror("pthread_setname_np");
    exit(EXIT_FAILURE);
  }
}

void *grandson_work(void *)
{
  setname("grandson-thread");
  stub();
  return NULL;
}

void *son_work(void *)
{
  pthread_t tid;

  setname("son-thread");
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

int main(void)
{
  pthread_t tid;

  setname("parent-thread");

  if (pthread_create(&tid, NULL, son_work, 0)) {
    perror("pthread_create");
    exit(EXIT_FAILURE);
  }

  if (pthread_join(tid, NULL)) {
    perror("pthread_join");
    exit(EXIT_FAILURE);
  }
  return 0;
}
