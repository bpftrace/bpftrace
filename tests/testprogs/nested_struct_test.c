#include <stdio.h>

struct Foo {
    int m;
    struct {
        int x;
        int y;
    } bar;
    int n;
};

void test_nested_struct(struct Foo *foo) {
    printf("test\n");
}

int main() {
    struct Foo foo = {
        .m = 10,
        .bar = { .x = 20, .y = 30 },
        .n = 40
    };

    test_nested_struct(&foo);
    return 0;
}
