/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/

#ifndef SRC_METRICS_H_
#define SRC_METRICS_H_

#include <napi.h>

struct WAFTruncationMetrics {
  size_t max_truncated_string_length = 0;
  size_t max_truncated_container_size = 0;
  size_t max_truncated_container_depth = 0;
};

#endif  // SRC_METRICS_H_
