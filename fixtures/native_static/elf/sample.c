#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int g = 5;
const char *s = "hello";
__thread int tls = 3;
static int counter;
int helper(int x) { return x * 3 + counter++; }
int main(int argc, char **argv) {
  char b[32];
  strcpy(b, argv[0]);
  puts(b);
  printf("%d %d\n", g, helper(argc));
  free(malloc(10));
  return (int)strlen(s) + tls;
}
