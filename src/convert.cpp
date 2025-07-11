/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#include <math.h>
#include <napi.h>
#include <napi-inl.h>
#include <ddwaf.h>

#include <limits>
#include <string>
#include <algorithm>

#include "src/convert.h"
#include "src/log.h"
#include "src/jsset.h"

ddwaf_object* to_ddwaf_object(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Value val,
  int depth,
  bool lim,
  bool ignoreToJSON,
  JsSet stack,
  WAFTruncationMetrics* metrics
);

ddwaf_object* to_ddwaf_object_array(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Array arr,
  int depth,
  bool lim,
  bool ignoreToJSON,
  JsSet stack,
  WAFTruncationMetrics* metrics
) {
  if (!ignoreToJSON) {
    Napi::Value toJSON = arr.Get("toJSON");
    if (toJSON.IsFunction()) {
      Napi::Value toJSONResult = toJSON.As<Napi::Function>().Call(arr, {});
      if (env.IsExceptionPending()) {
        mlog("Exception pending");
        env.GetAndClearPendingException();
        return ddwaf_object_invalid(object);
      }
      return to_ddwaf_object(object, env, toJSONResult, depth, lim, true, stack, metrics);
    }
  }

  uint32_t len = arr.Length();
  if (env.IsExceptionPending()) {
    mlog("Exception pending");
    return nullptr;
  }
  ddwaf_object* objectRes = ddwaf_object_array(object);
  if (objectRes == nullptr) {
    mlog("failed to create array");
    return nullptr;
  }
  // TODO(@vdeturckheim): handle arrays with
  // more than DDWAF_MAX_CONTAINER_SIZE chars
  if (lim && len > DDWAF_MAX_CONTAINER_SIZE) {
    if (metrics) {
      metrics->max_truncated_container_size = std::max(metrics->max_truncated_container_size,
                                                       static_cast<size_t>(len));
    }
    len = DDWAF_MAX_CONTAINER_SIZE;
  }
  for (uint32_t i = 0; i < len; ++i) {
    Napi::Value item  = arr.Get(i);
    ddwaf_object val;
    to_ddwaf_object(&val, env, item, depth, lim, false, stack, metrics);
    if (!ddwaf_object_array_add(object, &val)) {
      mlog("add to array failed, freeing");
      ddwaf_object_free(&val);
    }
  }

  return object;
}

ddwaf_object* to_ddwaf_object_object(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Object obj,
  int depth,
  bool lim,
  bool ignoreToJSON,
  JsSet stack,
  WAFTruncationMetrics* metrics
) {
  if (!ignoreToJSON) {
    Napi::Value toJSON = obj.Get("toJSON");
    if (toJSON.IsFunction()) {
      Napi::Value toJSONResult = toJSON.As<Napi::Function>().Call(obj, {});
      if (env.IsExceptionPending()) {
        mlog("Exception pending");
        env.GetAndClearPendingException();
        return ddwaf_object_invalid(object);
      }
      return to_ddwaf_object(object, env, toJSONResult, depth, lim, true, stack, metrics);
    }
  }

  Napi::Array properties = obj.GetPropertyNames();
  uint32_t len = properties.Length();
  if (lim && len > DDWAF_MAX_CONTAINER_SIZE) {
    if (metrics) {
      metrics->max_truncated_container_size = std::max(metrics->max_truncated_container_size,
                                                       static_cast<size_t>(len));
    }
    len = DDWAF_MAX_CONTAINER_SIZE;
  }
  if (env.IsExceptionPending()) {
    mlog("Exception pending");
    return nullptr;
  }

  ddwaf_object* map = ddwaf_object_map(object);
  if (map == nullptr) {
    mlog("failed to create map");
    return nullptr;
  }

  for (uint32_t i = 0; i < len; ++i) {
    mlog("Getting properties");
    Napi::Value keyV = properties.Get(i);
    if (!obj.HasOwnProperty(keyV) || !keyV.IsString()) {
      // We avoid inherited properties here.
      // If the key is not a String, well this is weird
      continue;
    }
    std::string key = keyV.ToString().Utf8Value();
    Napi::Value valV = obj.Get(keyV);
    mlog("Looping into ToPWArgs");
    ddwaf_object val;
    to_ddwaf_object(&val, env, valV, depth, lim, false, stack, metrics);
    if (!ddwaf_object_map_add(map, key.c_str(), &val)) {
      mlog("add to object failed, freeing");
      ddwaf_object_free(&val);
    }
  }

  return object;
}

ddwaf_object* to_ddwaf_string(
  ddwaf_object *object,
  Napi::Value val,
  bool lim,
  WAFTruncationMetrics* metrics
) {
  std::string str = val.ToString().Utf8Value();
  int len = str.length();
  if (lim && len > DDWAF_MAX_STRING_LENGTH) {
    if (metrics) {
      metrics->max_truncated_string_length = std::max(metrics->max_truncated_string_length,
                                                      static_cast<size_t>(len));
    }
    len = DDWAF_MAX_STRING_LENGTH;
  }
  return ddwaf_object_stringl(object, str.c_str(), len);
}

ddwaf_object* to_ddwaf_object(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Value val,
  int depth,
  bool lim,
  bool ignoreToJson,
  JsSet stack,
  WAFTruncationMetrics* metrics
) {
  mlog("starting to convert an object");
  if (depth >= DDWAF_MAX_CONTAINER_DEPTH) {
    mlog("Max depth reached");
    if (metrics) {
      metrics->max_truncated_container_depth = std::max(metrics->max_truncated_container_depth,
                                                        static_cast<size_t>(depth));
    }
    return ddwaf_object_map(object);
  }
  if (val.IsNull()) {
    mlog("creating Null");
    return ddwaf_object_null(object);
  }
  if (val.IsString()) {
    mlog("creating String");
    return to_ddwaf_string(object, val, lim, metrics);
  }
  if (val.IsNumber()) {
    mlog("creating Number");
    double value = val.ToNumber().DoubleValue();

    // Using fpclassify because NaN value does not match C++ quiet_NaN probably due to a mismatch between C++
    // and IEEE754 standards.
    switch (fpclassify(value)) {
    case FP_NAN:
      value = std::numeric_limits<double>::quiet_NaN();
      break;
    case FP_INFINITE:
      value = std::numeric_limits<double>::infinity();
      break;
    default:
      break;
    }

    return ddwaf_object_float(object, value);
  }
  if (val.IsBoolean()) {
    mlog("creating Boolean");
    bool boolValue = val.ToBoolean().Value();
    return ddwaf_object_bool(object, boolValue);
  }
  if (val.IsFunction()) {
    // Special case because a function will evaluate true for both IsFunction and IsObject.
    return ddwaf_object_invalid(object);
  }
  if (stack.Has(val)) {
    mlog("Circular dependency")
    return ddwaf_object_invalid(object);
  }

  if (val.IsArray()) {
    stack.Add(val);
    mlog("creating Array");
    auto result =
      to_ddwaf_object_array(object, env, val.ToObject().As<Napi::Array>(), depth + 1, lim, ignoreToJson, stack,
                            metrics);
    stack.Delete(val);
    return result;
  }
  if (val.IsObject()) {
    stack.Add(val);
    mlog("creating Object");
    auto result = to_ddwaf_object_object(object, env, val.ToObject(), depth + 1, lim, ignoreToJson, stack, metrics);
    stack.Delete(val);
    return result;
  }
  mlog("creating invalid object");
  return ddwaf_object_invalid(object);
}

Napi::Value from_ddwaf_object(const ddwaf_object *object, Napi::Env env) {
  DDWAF_OBJ_TYPE type = object->type;

  Napi::Value result;

  switch (type) {
    case DDWAF_OBJ_NULL:
      result = env.Null();
      break;
    case DDWAF_OBJ_BOOL:
      result = Napi::Boolean::New(env, object->boolean);
      break;
    case DDWAF_OBJ_SIGNED:
      result = Napi::Number::New(env, object->intValue);
      break;
    case DDWAF_OBJ_UNSIGNED:
      result = Napi::Number::New(env, object->uintValue);
      break;
    case DDWAF_OBJ_FLOAT:
      result = Napi::Number::New(env, object->f64);
      break;
    case DDWAF_OBJ_STRING:
      result = Napi::String::New(env, object->stringValue, object->nbEntries);
      break;
    case DDWAF_OBJ_ARRAY: {
      Napi::Array arr = Napi::Array::New(env, object->nbEntries);

      if (env.IsExceptionPending()) {
        mlog("Exception pending");
        return env.Null();
      }

      for (uint32_t i = 0; i < object->nbEntries; ++i) {
        const ddwaf_object* e = &object->array[i];
        Napi::Value v = from_ddwaf_object(e, env);
        arr[i] = v;
      }

      result = arr;
      break;
    }
    case DDWAF_OBJ_MAP: {
      Napi::Object obj = Napi::Object::New(env);

      for (uint32_t i = 0; i < object->nbEntries; ++i) {
        const ddwaf_object* e = &object->array[i];
        Napi::String k = Napi::String::New(env, e->parameterName, e->parameterNameLength);
        if (env.IsExceptionPending()) {
          mlog("Exception pending");
          continue;
        }
        Napi::Value v = from_ddwaf_object(e, env);
        obj.Set(k, v);
      }

      result = obj;
      break;
    }
    default:
      result = env.Null();
      break;
  }

  if (env.IsExceptionPending()) {
    mlog("Exception pending");
    return env.Null();
  }

  return result;
}
