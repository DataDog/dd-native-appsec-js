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


ddwaf_object* to_ddwaf_object_array(ddwaf_object *object, Napi::Env env, Napi::Array arr, int depth, bool lim) {
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
    len = DDWAF_MAX_CONTAINER_SIZE;
  }
  for (uint32_t i = 0; i < len; ++i) {
    Napi::Value item  = arr.Get(i);
    ddwaf_object val;
    to_ddwaf_object(&val, env, item, depth, lim);
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
  bool coerceBoolToInt
) {
  Napi::Array properties = obj.GetPropertyNames();
  uint32_t len = properties.Length();
  if (lim && len > DDWAF_MAX_CONTAINER_SIZE) {
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
    to_ddwaf_object(&val, env, valV, depth, lim, coerceBoolToInt);
    if (!ddwaf_object_map_add(map, key.c_str(), &val)) {
      mlog("add to object failed, freeing");
      ddwaf_object_free(&val);
    }
  }
  return object;
}

ddwaf_object* to_ddwaf_object(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Value val,
  int depth,
  bool lim,
  bool coerceBoolToInt
) {
  mlog("starting to convert an object");
  if (depth >= DDWAF_MAX_CONTAINER_DEPTH) {
    mlog("Max depth reached");
    return ddwaf_object_map(object);
  }
  if (val.IsString()) {
    mlog("creating String");
    std::string str = val.ToString().Utf8Value();
    if (lim && str.length() > DDWAF_MAX_STRING_LENGTH) {
      str = str.substr(DDWAF_MAX_STRING_LENGTH - 1);
    }
    return ddwaf_object_string(object, str.c_str());
  }
  if (val.IsNumber()) {
    mlog("creating Number");
    return ddwaf_object_signed(object, val.ToNumber().Int64Value());
  }
  if (val.IsBoolean()) {
    mlog("creating Boolean");
    if (coerceBoolToInt) {
      mlog("turning boolean to int");
      int64_t nb = val.ToBoolean().Value() ? 1 : 0;
      return ddwaf_object_signed(object, nb);
    } else {
      mlog("keeping boolean type");
      return ddwaf_object_bool(object, val.ToBoolean().Value());
    }
  }
  if (val.IsArray()) {
    mlog("creating Array");
    return to_ddwaf_object_array(object, env, val.ToObject().As<Napi::Array>(), depth + 1, lim);
  }
  if (val.IsObject()) {
    mlog("creating Object");
    return to_ddwaf_object_object(object, env, val.ToObject(), depth + 1, lim, coerceBoolToInt);
  }
  mlog("creating empty map");
  // we use empty maps for now instead of null. See issue !43
  return ddwaf_object_map(object);
}

Napi::Value from_ddwaf_object(ddwaf_object *object, Napi::Env env, int depth) {
  if (depth >= DDWAF_MAX_CONTAINER_DEPTH) {
    mlog("Max depth reached");
    return env.Null();
  }

  DDWAF_OBJ_TYPE type = object->type;

  Napi::Value result;

  switch (type) {
    case DDWAF_OBJ_SIGNED:
      result = Napi::Number::New(env, object->intValue);
      break;
    case DDWAF_OBJ_UNSIGNED:
      result = Napi::Number::New(env, object->uintValue);
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
        ddwaf_object* e = &object->array[i];
        Napi::Value v = from_ddwaf_object(e, env, depth + 1);
        arr[i] = v;
      }

      result = arr;
      break;
    }
    case DDWAF_OBJ_MAP: {
      Napi::Object obj = Napi::Object::New(env);

      for (uint32_t i = 0; i < object->nbEntries; ++i) {
        ddwaf_object* e = &object->array[i];
        Napi::String k = Napi::String::New(env, e->parameterName, e->parameterNameLength);
        if (env.IsExceptionPending()) {
          mlog("Exception pending");
          continue;
        }
        Napi::Value v = from_ddwaf_object(e, env, depth + 1);
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
