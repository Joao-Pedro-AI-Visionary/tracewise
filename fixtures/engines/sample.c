#include <stdio.h>
#include <string.h>

volatile int engine_counter = 7;
const char engine_banner[] = "ENGINE_FIXTURE_BANNER";

__attribute__((noinline, used)) int engine_leaf(int value) {
  puts("ENGINE_LEAF_MESSAGE");
  return value + engine_counter;
}

__attribute__((noinline, used)) int engine_branch(int value) {
  if (value > 10) {
    return engine_leaf(value);
  }
  return engine_leaf(-value);
}

__attribute__((noinline, used)) int engine_apply(int (*callback)(int), int value) {
  return callback(value);
}

__attribute__((noinline, used)) size_t engine_measure(const char *text) {
  return strlen(text) + (size_t)engine_counter;
}

__attribute__((noinline, used)) int engine_entry(int argc) {
  int total = engine_branch(argc * 4);
  total += engine_apply(engine_branch, argc);
  total += (int)engine_measure(engine_banner);
  return total;
}

int main(int argc, char **argv) {
  (void)argv;
  printf("%d\n", engine_entry(argc));
  return 0;
}
