#include <napi.h>
#include <napi-inl.h>
#include "convert.h"
#include "ddwaf.h"
#include "log.h"

/** TODO
USE
#define DDWAF_MAX_STRING_LENGTH 4096
#define DDWAF_MAX_MAP_DEPTH 20
#define DDWAF_MAX_ARRAY_LENGTH 256
**/

ddwaf_object* to_ddwaf_object_array(ddwaf_object *object, Napi::Env env, Napi::Array arr, int depth) {
  uint32_t len = arr.Length();
  if (env.IsExceptionPending()) {
    mlog("Exception pending");
    return nullptr;
  }
  ddwaf_object_array(object);
  if (object == nullptr) {
    mlog("failed to create array");
    return nullptr;
  }

  for (uint32_t i = 0; i < len; ++i) {
    Napi::Value item  = arr.Get(i);
    ddwaf_object val;
    to_ddwaf_object(&val, env, item, depth);
    if(!ddwaf_object_array_add(object, &val)) {
      mlog("add to array failed, freeing");
      ddwaf_object_free(&val);
    }
  }
  return object;
}

ddwaf_object* to_ddwaf_object_object(ddwaf_object *object, Napi::Env env, Napi::Object obj, int depth) {
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
      // We avoid inherited properties here. If the key is not a String, well this is weird
      continue;
    }
    std::string key   = keyV.ToString().Utf8Value();
    Napi::Value valV  = obj.Get(keyV);
    mlog("Looping into ToPWArgs");
    ddwaf_object val;
    to_ddwaf_object(&val, env, valV, depth); // TODO: this could be nullptr
    if(!ddwaf_object_map_add(map, key.c_str(), &val)) {
      mlog("add to object failed, freeing");
      ddwaf_object_free(&val);
    }
  }
  return object;
}

ddwaf_object* to_ddwaf_object(ddwaf_object *object, Napi::Env env, Napi::Value val, int depth) {
  mlog("starting to convert an object");
  if (depth >= DDWAF_MAX_MAP_DEPTH) {
    mlog("Max depth reached");
    return ddwaf_object_invalid(object);
  }
  if (val.IsString()) {
    mlog("creating String");
    return ddwaf_object_string(object, val.ToString().Utf8Value().c_str());
  }
  if (val.IsNumber()) {
    mlog("creating Number");
    // FIXME: libddwaf does not support floats I believe
    return ddwaf_object_signed(object, val.ToNumber().Int64Value());
  }
  if (val.IsArray()) {
    mlog("creating Array");
    return to_ddwaf_object_array(object, env, val.ToObject().As<Napi::Array>(), depth + 1);
  }
  if (val.IsObject()) {
    mlog("creating Object");
    return to_ddwaf_object_object(object, env, val.ToObject(), depth + 1);
  }
  mlog("returning nullptr");
  return nullptr;
}

ddwaf_object* to_ddwaf_object(ddwaf_object *object, Napi::Env env, Napi::Value val) {
  return to_ddwaf_object(object, env, val, 0);
}

