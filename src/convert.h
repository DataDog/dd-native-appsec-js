/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#ifndef SRC_CONVERT_H_
#define SRC_CONVERT_H_

#include <napi.h>
#include <ddwaf.h>
#include "src/jsset.h"
#include "src/metrics.h"

ddwaf_object* to_ddwaf_object(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Value val,
  int depth,
  bool lim,
  bool ignoreToJson,
  JsSet stack,
  WAFTruncationMetrics *metrics
);

Napi::Value from_ddwaf_object(const ddwaf_object *object, Napi::Env env);

#endif  // SRC_CONVERT_H_
