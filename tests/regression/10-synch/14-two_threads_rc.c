// SKIP PARAM: --set ana.activated[+] thread
#include <pthread.h>
#include <stdio.h>

int myglobal;

void *t_fun(void *arg) {
  myglobal=42; // RACE!
  return NULL;
}

int main(void) {
  pthread_t t1, t2;
  myglobal = 1; // NORACE
  pthread_create(&t1, NULL, t_fun, NULL);
  pthread_create(&t2, NULL, t_fun, NULL);
  myglobal = 2; // RACE!
  pthread_join (t1, NULL);
  pthread_join (t2, NULL);
  myglobal = 3; // NORACE
  return 0;
}
