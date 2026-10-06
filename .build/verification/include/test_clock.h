#include <time.h>
#include <unistd.h>
int test_clock_gettime(clockid_t, struct timespec *);
int test_nanosleep(const struct timespec *, struct timespec *);
#define clock_gettime test_clock_gettime
#define nanosleep test_nanosleep
