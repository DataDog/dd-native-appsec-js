/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#ifndef SRC_LOG_H_
#define SRC_LOG_H_
#define DEBUG 0
#include <cstdio>

#if DEBUG == 1
#define mlog(X, ...) {                                  \
    std::fprintf(stderr, "%s:%d ", __FUNCTION__, __LINE__);  \
    std::fprintf(stderr, X, ##__VA_ARGS__);                  \
    std::fprintf(stderr, "\n");                  \
}
#else
#define mlog(X, ...) { }
#endif

#endif  // SRC_LOG_H_
