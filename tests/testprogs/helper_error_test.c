#include <stdio.h>

struct foo {
    int a;
};

void test_helper_error(struct foo *ptr) {
    printf("test %llu\n", (long long unsigned)ptr);
}

int main() {
    test_helper_error(NULL);
    return 0;
}
