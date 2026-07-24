#include <stdio.h>

struct foo {
    int a;
};

void test_helper_error(struct foo *ptr) {
    printf("test\n");
}

int main() {
    test_helper_error(NULL);
    return 0;
}
