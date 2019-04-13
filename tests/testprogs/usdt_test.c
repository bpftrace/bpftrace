#include <sys/sdt.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>

static long
myclock() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    DTRACE_PROBE1(tracetest, testprobe, tv.tv_sec);
    DTRACE_PROBE1(tracetest, testprobe2, tv.tv_sec);
    DTRACE_PROBE1(tracetest2, testprobe2, tv.tv_sec);
    return tv.tv_sec;
}

int
main(int argc, char **argv) {
    usleep(2000000);
    myclock();
    return 0;
}
