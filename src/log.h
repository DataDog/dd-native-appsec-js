#define DEBUG 1

#if DEBUG == 1
#include <stdio.h>
#define mlog(X, ...) {                                  \
    fprintf(stderr, "%s:%d ", __FUNCTION__, __LINE__);  \
    fprintf(stderr, X, ##__VA_ARGS__);                  \
    fprintf(stderr, "\n");                  \
}
#else
#define mlog(X, ...) { }
#endif
