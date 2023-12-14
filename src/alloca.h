/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#ifndef SRC_ALLOCA_H_
  #define SRC_ALLOCA_H_
  #ifdef _WIN32
    #include <malloc.h>
  #else
    #include <alloca.h>
  #endif
#endif  // SRC_ALLOCA_H_
