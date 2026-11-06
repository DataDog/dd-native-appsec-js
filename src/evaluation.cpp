/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
// min support Node.js 18.0.0 - https://nodejs.org/api/n-api.html#node-api-version-matrix
#define NAPI_VERSION  8
#include <napi.h>
#include <ddwaf.h>

#include <cstring>

#include "src/alloca.h"
#include "src/main.h"
#include "src/log.h"
#include "src/convert.h"

// libddwaf result field name constants
constexpr size_t EVENTS_LEN = 6;
constexpr size_t ACTIONS_LEN = 7;
constexpr size_t ATTRIBUTES_LEN = 10;
constexpr size_t KEEP_LEN = 4;
constexpr size_t DURATION_LEN = 8;
constexpr size_t TIMEOUT_LEN = 7;

Napi::Value DDWAFContext::run(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (this->_disposed) {
    Napi::Error::New(env, "Calling run on a disposed context").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (info.Length() < 2) {  // payload, timeout
    Napi::Error::New(env, "Wrong number of arguments, 2 expected").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!info[0].IsObject()) {
    Napi::TypeError::New(
            env,
            "Payload data must be an object")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object payload = info[0].As<Napi::Object>();
  Napi::Value persistent = payload.Get("persistent");
  Napi::Value ephemeral = payload.Get("ephemeral");

  if (!persistent.IsObject() && !ephemeral.IsObject()) {
    Napi::TypeError::New(env, "Persistent or ephemeral must be an object").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!info[1].IsNumber()) {
    Napi::TypeError::New(env, "Timeout argument must be a number").ThrowAsJavaScriptException();
    return env.Null();
  }

  int64_t timeout = info[1].ToNumber().Int64Value();
  if (timeout <= 0) {
    Napi::TypeError::New(env, "Timeout argument must be greater than 0").ThrowAsJavaScriptException();
    return env.Null();
  }

  ddwaf_object *ddwafPersistent = nullptr;
  this->_metrics = {};

  if (persistent.IsObject()) {
    ddwafPersistent = static_cast<ddwaf_object *>(alloca(sizeof(ddwaf_object)));
    to_ddwaf_object(ddwafPersistent, env, persistent, 0, true, false, JsSet::Create(env), &this->_metrics);
  }

  ddwaf_object *ddwafEphemeral = nullptr;

  if (ephemeral.IsObject()) {
    ddwafEphemeral = static_cast<ddwaf_object *>(alloca(sizeof(ddwaf_object)));
    to_ddwaf_object(ddwafEphemeral, env, ephemeral, 0, true, false, JsSet::Create(env), &this->_metrics);
  }

  ddwaf_object result;

  DDWAF_RET_CODE code = ddwaf_run(
    this->_context,
    ddwafPersistent,
    ddwafEphemeral,
    &result,
    static_cast<uint64_t>(timeout));

  Napi::Object res = Napi::Object::New(env);
  Napi::Object metrics = Napi::Object::New(env);

  res.Set("metrics", metrics);

  if (this->_metrics.max_truncated_string_length > 0) {
    metrics.Set("maxTruncatedString",
                Napi::Number::New(env, this->_metrics.max_truncated_string_length));
  }

  if (this->_metrics.max_truncated_container_size > 0) {
    metrics.Set("maxTruncatedContainerSize",
                Napi::Number::New(env, this->_metrics.max_truncated_container_size));
  }

  if (this->_metrics.max_truncated_container_depth > 0) {
    metrics.Set("maxTruncatedContainerDepth",
                Napi::Number::New(env, this->_metrics.max_truncated_container_depth));
  }

  // Report if there is an error first
  switch (code) {
    case DDWAF_ERR_INTERNAL:
    case DDWAF_ERR_INVALID_OBJECT:
    case DDWAF_ERR_INVALID_ARGUMENT:
      res.Set("errorCode", Napi::Number::New(env, code));
      ddwaf_object_free(&result);
      return res;
    default:
      break;
  }

  // No error. Collect result data and return

  const ddwaf_object *events = nullptr, *actions = nullptr, *attributes = nullptr,
                     *keep = nullptr, *duration = nullptr, *run_timeout = nullptr;

  for (size_t i = 0; i < ddwaf_object_size(&result); ++i) {
    const ddwaf_object *child = ddwaf_object_get_index(&result, i);
    if (child == nullptr) {
      mlog("ddwaf result child is null")
      continue;
    }

    size_t length = 0;
    const char *key = ddwaf_object_get_key(child, &length);
    if (key == nullptr) {
      mlog("ddwaf result key is null")
      continue;
    }

    if (length == EVENTS_LEN && memcmp(key, "events", EVENTS_LEN) == 0) {
      events = child;
    } else if (length == ACTIONS_LEN && memcmp(key, "actions", ACTIONS_LEN) == 0) {
      actions = child;
    } else if (length == ATTRIBUTES_LEN && memcmp(key, "attributes", ATTRIBUTES_LEN) == 0) {
      attributes = child;
    } else if (length == KEEP_LEN && memcmp(key, "keep", KEEP_LEN) == 0) {
      keep = child;
    } else if (length == DURATION_LEN && memcmp(key, "duration", DURATION_LEN) == 0) {
      duration = child;
    } else if (length == TIMEOUT_LEN && memcmp(key, "timeout", TIMEOUT_LEN) == 0) {
      run_timeout = child;
    }
  }

  mlog("Set timeout");
  if (run_timeout && run_timeout->type == DDWAF_OBJ_BOOL) {
    res.Set("timeout", Napi::Boolean::New(env, run_timeout->boolean));
  }

  if (duration && duration->type == DDWAF_OBJ_UNSIGNED && duration->uintValue > 0) {
    mlog("Set duration");
    res.Set("duration", Napi::Number::New(env, duration->uintValue));
  }

  if (attributes && ddwaf_object_size(attributes) > 0) {
    mlog("Set attributes");
    res.Set("attributes", from_ddwaf_object(attributes, env));
  }

  if (code == DDWAF_MATCH) {
    mlog("ddwaf result is a match")
    res.Set("status", Napi::String::New(env, "match"));

    if (events) {
      mlog("Set events")
      res.Set("events", from_ddwaf_object(events, env));
    }

    if (actions) {
      mlog("Set actions")
      res.Set("actions", from_ddwaf_object(actions, env));
    }
  }

  if (keep && keep->type == DDWAF_OBJ_BOOL) {
    mlog("Set keep")
    res.Set("keep", Napi::Boolean::New(env, keep->boolean));
  }

  ddwaf_object_free(&result);

  return res;
}
