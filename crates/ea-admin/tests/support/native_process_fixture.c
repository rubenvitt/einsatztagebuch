/* Bounded real-pipe regression fixture; no native credentials or account APIs. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static void pause_ms(long ms) {
    struct timespec interval = {ms / 1000, (ms % 1000) * 1000000};
    nanosleep(&interval, NULL);
}
static long long epoch_us(void) {
    struct timeval now;
    gettimeofday(&now, NULL);
    return (long long)now.tv_sec * 1000000 + now.tv_usec;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "no-read")) { pause_ms(2000); return 0; }
    while (getchar() != EOF) {}
    if (!strcmp(argv[1], "late")) {
        if (argc != 3) return 2;
        const long long earliest = atoll(argv[2]);
        while (epoch_us() < earliest) {
            struct timespec interval = {0, 100000};
            nanosleep(&interval, NULL);
        }
        printf("{\"emitted_us\":%lld}\n", epoch_us());
        return 0;
    }
    puts("{}");
    fflush(stdout);
    if (!strcmp(argv[1], "no-eof")) pause_ms(2000);
    if (!strcmp(argv[1], "no-exit")) {
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        pause_ms(2000);
    }
    return 0;
}
