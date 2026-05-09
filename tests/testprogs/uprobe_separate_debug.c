int __attribute__((noinline)) fn(int n, const char *str __attribute__((unused))) {
    return n * n;
}

int main(void) {
    return fn(123, "Hello world!");
}
