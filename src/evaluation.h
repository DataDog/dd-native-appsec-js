/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#ifndef SRC_EVALUATION_H_
#define SRC_EVALUATION_H_

#include <napi.h>
#include <ddwaf.h>

#include <cstdint>

#include "src/metrics.h"

bool validate_run_args(const Napi::CallbackInfo& info, const char* disposed_message,
                       bool disposed, int64_t* timeout);

Napi::Object eval_and_build_result(
  Napi::Env env,
  ddwaf_object* input,
  ddwaf_context target,
  ddwaf_allocator alloc,
  WAFTruncationMetrics* metrics,
  uint64_t timeout
);

Napi::Object eval_and_build_result(
  Napi::Env env,
  ddwaf_object* input,
  ddwaf_subcontext target,
  ddwaf_allocator alloc,
  WAFTruncationMetrics* metrics,
  uint64_t timeout
);

#endif  // SRC_EVALUATION_H_
