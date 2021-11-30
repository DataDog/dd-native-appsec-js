/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#include <napi.h>
#include <napi-inl.h>
#include <ddwaf.h>
#include <string>
#include "src/convert.h"
#include "src/log.h"

/** TODO
USE
#define DDWAF_MAX_STRING_LENGTH 4096
#define DDWAF_MAX_MAP_DEPTH 20
#define DDWAF_MAX_ARRAY_LENGTH 256
**/

ddwaf_object* to_ddwaf_object_array(ddwaf_object *object, Napi::Env env,
                                              Napi::Array arr, int depth) {
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
  // more than DDWAF_MAX_ARRAY_LENGTH chars
  len = len < DDWAF_MAX_ARRAY_LENGTH ? len : DDWAF_MAX_ARRAY_LENGTH;
  for (uint32_t i = 0; i < len; ++i) {
    Napi::Value item  = arr.Get(i);
    ddwaf_object val;
    to_ddwaf_object(&val, env, item, depth);
    if (!ddwaf_object_array_add(object, &val)) {
      mlog("add to array failed, freeing");
      ddwaf_object_free(&val);
    }
  }
  return object;
}

ddwaf_object* to_ddwaf_object_object(ddwaf_object *object, Napi::Env env,
                                              Napi::Object obj, int depth) {
  Napi::Array properties = obj.GetPropertyNames();
  uint32_t len = properties.Length();
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
    Napi::Value keyV  = properties.Get(i);
    if (!obj.HasOwnProperty(keyV) || !keyV.IsString()) {
      // We avoid inherited properties here.
      // If the key is not a String, well this is weird
      continue;
    }
    std::string key   = keyV.ToString().Utf8Value();
    Napi::Value valV  = obj.Get(keyV);
    mlog("Looping into ToPWArgs");
    ddwaf_object val;
    // TODO(@vdeturckheim): this could be nullptr
    to_ddwaf_object(&val, env, valV, depth);
    if (!ddwaf_object_map_add(map, key.c_str(), &val)) {
      mlog("add to object failed, freeing");
      ddwaf_object_free(&val);
    }
  }
  return object;
}

ddwaf_object* to_ddwaf_object(ddwaf_object *object, Napi::Env env,
                                                Napi::Value val, int depth) {
  mlog("starting to convert an object");
  if (depth >= DDWAF_MAX_MAP_DEPTH) {
    mlog("Max depth reached");
    return ddwaf_object_invalid(object);
  }
  if (val.IsString()) {
    mlog("creating String");
    std::string str = val.ToString().Utf8Value();
    if (str.length() > DDWAF_MAX_STRING_LENGTH) {
      str = str.substr(DDWAF_MAX_STRING_LENGTH - 1);
    }
    return ddwaf_object_string(object, str.c_str());
  }
  if (val.IsNumber()) {
    mlog("creating Number");
    // FIXME: libddwaf does not support floats I believe
    return ddwaf_object_signed(object, val.ToNumber().Int64Value());
  }
  if(val.IsBoolean()) {
    mlog("creating Boolean");
    int64_t nb = val.ToBoolean().Value() ? 1 : 0;
    return ddwaf_object_signed(object, nb);
  }
  if (val.IsArray()) {
    mlog("creating Array");
    return to_ddwaf_object_array(object, env,
              val.ToObject().As<Napi::Array>(), depth + 1);
  }
  if (val.IsObject()) {
    mlog("creating Object");
    return to_ddwaf_object_object(object, env, val.ToObject(), depth + 1);
  }
  mlog("returning nullptr");
  return nullptr;
}

ddwaf_object* to_ddwaf_object(ddwaf_object *object,
                          Napi::Env env, Napi::Value val) {
  return to_ddwaf_object(object, env, val, 0);
}
