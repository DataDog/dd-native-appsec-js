/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#ifndef SRC_CONVERT_H_
#define SRC_CONVERT_H_

#include <napi.h>
#include <ddwaf.h>

#include <array>
#include <cstddef>

#include "src/metrics.h"

constexpr size_t WAF_MAX_STRING_LENGTH = 4096;
constexpr size_t WAF_MAX_CONTAINER_DEPTH = 20;
constexpr size_t WAF_MAX_CONTAINER_SIZE = 256;

class ObjectStack {
 public:
  bool contains(const Napi::Value& value) const {
    for (size_t i = 0; i < _size; ++i) {
      if (_values[i].StrictEquals(value)) {
        return true;
      }
    }
    return false;
  }

  bool push(const Napi::Value& value) {
    if (_size >= _values.size()) return false;
    _values[_size++] = value;
    return true;
  }

  void pop() {
    --_size;
  }

 private:
  std::array<Napi::Value, WAF_MAX_CONTAINER_DEPTH> _values;
  size_t _size = 0;
};

// Marshals a JS value into writable storage for one ddwaf_object. Nested allocations use alloc;
// destroy the result with ddwaf_object_destroy(object, alloc) unless ownership transfers to libddwaf.
ddwaf_object* to_ddwaf_object(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Value val,
  int depth,
  bool lim,
  bool ignoreToJson,
  ObjectStack *stack,
  WAFTruncationMetrics *metrics,
  ddwaf_allocator alloc
);

Napi::Value from_ddwaf_object(const ddwaf_object *object, Napi::Env env);
bool define_own_property(Napi::Object target, const Napi::Name& name, Napi::Value value);
bool define_own_property(Napi::Object target, const char* name, Napi::Value value);
bool define_own_property(Napi::Object target, uint32_t index, Napi::Value value);

#endif  // SRC_CONVERT_H_
