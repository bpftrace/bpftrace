#include <stdio.h>
#include <stdint.h>

struct x {
    unsigned long x;
};

void test_signed_ints(struct x *ptr) {
    printf("test\n");
}

int main() {
    struct x test_struct = { .x = 0 };
    test_signed_ints(&test_struct);
    return 0;
}
