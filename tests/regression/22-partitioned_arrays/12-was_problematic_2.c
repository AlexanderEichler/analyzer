// PARAM: --set solver td3 --enable ana.int.interval  --enable exp.partition-arrays.enabled  --set ana.activated "['base','threadid','threadflag','escape','expRelation','mallocWrapper']" --set exp.privatization none
int main(void)
{
  int arr[260];
  int n;

  n = 5;
  arr[0] = 0;

  while (n > 1) { //here
    arr[1] = 7;
    n--;
  }

  int arr2[260];

  n = 5;
  arr2[259] = 0;

  while (n > 1) {
    arr2[258] = 7;
    n--;
  }
}
