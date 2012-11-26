// PARAM: --set ana.activated[0][+] "'var_eq'"  --set ana.activated[0][+] "'symb_locks'"  --set ana.activated[0][+] "'region'"  --set exp.region-offsets true
#include<pthread.h>
#include<stdlib.h>
#include<stdio.h>

#define N 10

struct s {
  int datum;
  struct s *next;
};

struct s *new(int x) {
  struct s *p = malloc(sizeof(struct s));
  p->datum = x;
  p->next = NULL;
  return p;
}

void list_add(struct s *node, struct s *list) {
  struct s *temp = list->next;
  list->next = node;
  node->next = temp;
}

pthread_mutex_t mutex[N];
struct s *slot[N];

void *t_fun(void *arg) {
  int i;
  for (i=0; i<N; i++) {
    pthread_mutex_lock(&mutex[i]);
    list_add(new(N+i), slot[i]);
    pthread_mutex_unlock(&mutex[i]);
  }
  return NULL;
}

int main () {
  int j;
  struct s *p;
  pthread_t t1;
 
  for (j=0; j<N; j++) {
    pthread_mutex_init(&mutex[j],NULL);
    slot[j] = new(0);
  }

  pthread_create(&t1, NULL, t_fun, NULL);
  
  for (j=0; j<N; j++) {
    pthread_mutex_lock(&mutex[j]);
    list_add(new(j), slot[j]);
    p = slot[j]->next; // NORACE
    printf("%d\n", p->datum);
    pthread_mutex_unlock(&mutex[j]);
  }
  return 0;
}
