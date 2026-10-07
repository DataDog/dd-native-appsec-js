/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/

#ifndef SRC_METRICS_H_
#define SRC_METRICS_H_

#include <napi.h>

#include <cstddef>

struct WAFTruncationMetrics {
  size_t max_truncated_string_length = 0;
  size_t max_truncated_container_size = 0;
  size_t max_truncated_container_depth = 0;

  // Only the budget that first stopped the conversion is flagged: later charge
  // attempts made while the recursion unwinds bail out before any limit check.
  bool truncated_by_node_limit = false;
  bool truncated_by_byte_limit = false;

  bool charge_node(size_t limit) {
    if (conversion_exhausted()) {
      return false;
    }
    if (_converted_nodes >= limit) {
      truncated_by_node_limit = true;
      return false;
    }
    ++_converted_nodes;
    return true;
  }

  bool charge_utf8_bytes(size_t length, size_t limit) {
    if (conversion_exhausted()) {
      return false;
    }
    if (_converted_utf8_bytes > limit || length > limit - _converted_utf8_bytes) {
      truncated_by_byte_limit = true;
      return false;
    }
    _converted_utf8_bytes += length;
    return true;
  }

  bool conversion_exhausted() const {
    return truncated_by_node_limit || truncated_by_byte_limit;
  }

 private:
  size_t _converted_nodes = 0;
  size_t _converted_utf8_bytes = 0;
};

#endif  // SRC_METRICS_H_
