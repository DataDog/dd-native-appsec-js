/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
// min support Node.js 16.0.0 - https://nodejs.org/api/n-api.html#node-api-version-matrix
#define NAPI_VERSION  8
#include <napi.h>
#include <stdio.h>
#include <ddwaf.h>

#include <string>

#include "src/alloca.h"
#include "src/main.h"
#include "src/log.h"
#include "src/convert.h"

static std::string &rulesetVersion() {
  static std::string version;
  return version;
}

Napi::Object DDWAF::Init(Napi::Env env, Napi::Object exports) {
  mlog("Setting up class DDWAF");
  Napi::Function func = DefineClass(env, "DDWAF", {
    StaticMethod<&DDWAF::version>("version"),
    StaticMethod<&DDWAF::getRulesetVersion>("getRulesetVersion"),
    InstanceMethod<&DDWAF::update>("update"),
    InstanceMethod<&DDWAF::createContext>("createContext"),
    InstanceMethod<&DDWAF::dispose>("dispose"),
    InstanceAccessor("disposed", &DDWAF::GetDisposed, nullptr, napi_enumerable),
    // TODO(simon-id): should we have an InstanceValue for rulesInfo and requiredAddresses here ?
  });
  exports.Set("DDWAF", func);
  return exports;
}

Napi::Value DDWAF::version(const Napi::CallbackInfo& info) {
  mlog("Get libddwaf version");
  return Napi::String::New(info.Env(), ddwaf_get_version());
}

Napi::Value DDWAF::getRulesetVersion(const Napi::CallbackInfo &info) {
  mlog("Get ruleset version");
  return Napi::String::New(info.Env(), rulesetVersion());
}

Napi::Value DDWAF::GetDisposed(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), this->_disposed);
}

DDWAF::DDWAF(const Napi::CallbackInfo& info) : Napi::ObjectWrap<DDWAF>(info) {
  Napi::Env env = info.Env();
  size_t arg_len = info.Length();
  if (arg_len < 1) {
    Napi::Error::New(env, "Wrong number of arguments, expected at least 1").ThrowAsJavaScriptException();
    return;
  }
  if (!info[0].IsObject()) {
    Napi::TypeError::New(env, "First argument must be an object").ThrowAsJavaScriptException();
    return;
  }

  ddwaf_config waf_config{{0, 0, 0}, {nullptr, nullptr}, ddwaf_object_free};

  // do not touch these strings after the c_str() assigment
  std::string key_regex_str;
  std::string value_regex_str;

  if (arg_len >= 2) {  // TODO(@simon-id): there is a bug here ?
    // TODO(@simon-id) make a macro here someday
    if (!info[1].IsObject()) {
      Napi::TypeError::New(env, "Second argument must be an object").ThrowAsJavaScriptException();
      return;
    }

    Napi::Object config = info[1].ToObject();

    if (config.Has("obfuscatorKeyRegex")) {
      Napi::Value key_regex = config.Get("obfuscatorKeyRegex");

      if (!key_regex.IsString()) {
        Napi::TypeError::New(env, "obfuscatorKeyRegex must be a string").ThrowAsJavaScriptException();
        return;
      }

      key_regex_str = key_regex.ToString().Utf8Value();
      waf_config.obfuscator.key_regex = key_regex_str.c_str();
    }

    if (config.Has("obfuscatorValueRegex")) {
      Napi::Value value_regex = config.Get("obfuscatorValueRegex");

      if (!value_regex.IsString()) {
        Napi::TypeError::New(env, "obfuscatorValueRegex must be a string").ThrowAsJavaScriptException();
        return;
      }

      value_regex_str = value_regex.ToString().Utf8Value();
      waf_config.obfuscator.value_regex = value_regex_str.c_str();
    }
  }

  ddwaf_object rules;
  mlog("building rules");
  to_ddwaf_object(&rules, env, info[0], 0, false, false, JsSet::Create(env), nullptr);

  ddwaf_object diagnostics;

  mlog("Init WAF");
  ddwaf_handle handle = ddwaf_init(&rules, &waf_config, &diagnostics);
  ddwaf_object_free(&rules);

  Napi::Value diagnostics_js = from_ddwaf_object(&diagnostics, env);
  info.This().As<Napi::Object>().Set("diagnostics", diagnostics_js);

  // Extract ruleset_version if available
  if (diagnostics_js.IsObject()) {
    Napi::Object diagObj = diagnostics_js.As<Napi::Object>();
    if (diagObj.Has("ruleset_version") && diagObj.Get("ruleset_version").IsString()) {
      rulesetVersion() = diagObj.Get("ruleset_version").ToString().Utf8Value();
    }
  }

  ddwaf_object_free(&diagnostics);

  if (handle == nullptr) {
    Napi::Error::New(env, "Invalid rules").ThrowAsJavaScriptException();
    return;
  }

  this->_handle = handle;
  this->_disposed = false;

  this->update_known_addresses(info);
  this->update_known_actions(info);
}

void DDWAF::Finalize(Napi::Env env) {
  mlog("calling finalize on DDWAF");
  if (this->_disposed) {
    return;
  }
  ddwaf_destroy(this->_handle);
  this->_disposed = true;
}

void DDWAF::dispose(const Napi::CallbackInfo& info) {
  mlog("calling dispose on DDWAF instance");
  return this->Finalize(info.Env());
}

void DDWAF::update(const Napi::CallbackInfo& info) {
  mlog("calling update on DDWAF");

  Napi::Env env = info.Env();

  if (this->_disposed) {
    Napi::Error::New(env, "Could not update a disposed WAF instance").ThrowAsJavaScriptException();
    return;
  }

  if (info.Length() < 1) {
    Napi::Error::New(env, "Wrong number of arguments, expected at least 1").ThrowAsJavaScriptException();
    return;
  }
  if (!info[0].IsObject()) {
    Napi::TypeError::New(env, "First argument must be an object").ThrowAsJavaScriptException();
    return;
  }

  ddwaf_object update;
  mlog("building rules update");
  to_ddwaf_object(&update, env, info[0], 0, false, false, JsSet::Create(env), nullptr);

  ddwaf_object diagnostics;

  mlog("Update DDWAF instance");
  ddwaf_handle updated_handle = ddwaf_update(this->_handle, &update, &diagnostics);
  ddwaf_object_free(&update);

  Napi::Value diagnostics_js = from_ddwaf_object(&diagnostics, env);
  info.This().As<Napi::Object>().Set("diagnostics", diagnostics_js);

  if (diagnostics_js.IsObject()) {
    Napi::Object diagObj = diagnostics_js.As<Napi::Object>();
    if (diagObj.Has("ruleset_version") && diagObj.Get("ruleset_version").IsString()) {
      rulesetVersion() = diagObj.Get("ruleset_version").ToString().Utf8Value();
    }
  }

  ddwaf_object_free(&diagnostics);

  if (updated_handle == nullptr) {
    mlog("DDWAF updated handle is null");
    Napi::Error::New(env, "WAF has not been updated").ThrowAsJavaScriptException();
    return;
  }

  mlog("New DDWAF updated instance")
  ddwaf_destroy(this->_handle);
  this->_handle = updated_handle;

  this->update_known_addresses(info);
  this->update_known_actions(info);
}

void DDWAF::update_known_addresses(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  uint32_t size = 0;
  const char* const* known_addresses = ddwaf_known_addresses(this->_handle, &size);

  Napi::Value set = env.RunScript("new Set()");
  Napi::Function set_add = set.As<Napi::Object>().Get("add").As<Napi::Function>();

  for (uint32_t i = 0; i < size; ++i) {
    Napi::String address = Napi::String::New(env, known_addresses[i]);
    set_add.Call(set, {address});
  }

  info.This().As<Napi::Object>().Set("knownAddresses", set);
}

void DDWAF::update_known_actions(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  uint32_t size = 0;
  const char* const* known_actions = ddwaf_known_actions(this->_handle, &size);

  Napi::Value set = env.RunScript("new Set()");
  Napi::Function set_add = set.As<Napi::Object>().Get("add").As<Napi::Function>();

  for (uint32_t i = 0; i < size; ++i) {
    Napi::String address = Napi::String::New(env, known_actions[i]);
    set_add.Call(set, {address});
  }

  info.This().As<Napi::Object>().Set("knownActions", set);
}

Napi::Value DDWAF::createContext(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (this->_disposed) {
    Napi::Error::New(env, "Calling createContext on a disposed DDWAF instance").ThrowAsJavaScriptException();
    return env.Null();
  }
  mlog("Create context");
  Napi::Object context = env.GetInstanceData<Napi::FunctionReference>()->New({});
  DDWAFContext* raw = Napi::ObjectWrap<DDWAFContext>::Unwrap(context);
  if (!raw->init(this->_handle)) {
    Napi::Error::New(env, "Could not create context").ThrowAsJavaScriptException();
    return env.Null();
  }
  return context;
}

DDWAFContext::DDWAFContext(const Napi::CallbackInfo& info) : Napi::ObjectWrap<DDWAFContext>(info) {
  this->_disposed = false;
}

bool DDWAFContext::init(ddwaf_handle handle) {
  ddwaf_context context = ddwaf_context_init(handle);
  if (context == nullptr) {
    return false;
  }
  this->_context = context;
  return true;
}

void DDWAFContext::Finalize(Napi::Env env) {
  mlog("calling finalize on context");
  if (this->_disposed) {
    return;
  }
  ddwaf_context_destroy(this->_context);
  this->_disposed = true;
}

void DDWAFContext::dispose(const Napi::CallbackInfo& info) {
  mlog("calling dispose on context");
  return this->Finalize(info.Env());
}

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

  ddwaf_result result;

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
      ddwaf_result_free(&result);
      return res;
    default:
      break;
  }
  // there is no error. We need to collect perf data

  mlog("Set timeout");
  res.Set("timeout", Napi::Boolean::New(env, result.timeout));

  if (result.total_runtime) {
    mlog("Set total_runtime");
    res.Set("totalRuntime", Napi::Number::New(env, result.total_runtime));
  }

  if (ddwaf_object_size(&result.derivatives)) {
    res.Set("derivatives", from_ddwaf_object(&result.derivatives, env));
  }

  if (code == DDWAF_MATCH) {
    res.Set("status", Napi::String::New(env, "match"));
    res.Set("events", from_ddwaf_object(&result.events, env));
    res.Set("actions", from_ddwaf_object(&result.actions, env));
  }

  ddwaf_result_free(&result);

  return res;
}

Napi::Value DDWAFContext::GetDisposed(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), this->_disposed);
}

Napi::Object DDWAFContext::Init(Napi::Env env, Napi::Object exports) {
  mlog("Setting up class DDWAFContext");
  Napi::Function func = DefineClass(env, "DDWAFContext", {
    InstanceMethod<&DDWAFContext::run>("run"),
    InstanceMethod<&DDWAFContext::dispose>("dispose"),
    InstanceAccessor("disposed", &DDWAFContext::GetDisposed, nullptr, napi_enumerable),
  });

  Napi::FunctionReference* constructor = new Napi::FunctionReference();
  *constructor = Napi::Persistent(func);
  env.SetInstanceData(constructor);
  return exports;
}

// Initialize native add-on
Napi::Object Init(Napi::Env env, Napi::Object exports) {
  DDWAF::Init(env, exports);
  DDWAFContext::Init(env, exports);
  return exports;
}

// Register and initialize native add-on
NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
