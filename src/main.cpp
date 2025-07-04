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


Napi::Object DDWAF::Init(Napi::Env env, Napi::Object exports) {
  mlog("Setting up class DDWAF");
  Napi::Function func = DefineClass(env, "DDWAF", {
    StaticMethod<&DDWAF::version>("version"),
    InstanceMethod<&DDWAF::update_config>("createOrUpdateConfig"),
    InstanceMethod<&DDWAF::remove_config>("removeConfig"),
    InstanceAccessor("configPaths", &DDWAF::GetConfigPaths, nullptr, napi_enumerable),
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

Napi::Value DDWAF::GetDisposed(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), this->_disposed);
}

DDWAF::DDWAF(const Napi::CallbackInfo& info) : Napi::ObjectWrap<DDWAF>(info) {
  Napi::Env env = info.Env();
  size_t arg_len = info.Length();
  if (arg_len < 2) {
    Napi::Error::New(env, "Wrong number of arguments, expected at least 2").ThrowAsJavaScriptException();
    return;
  }

  if (!info[0].IsObject()) {
    Napi::TypeError::New(env, "First argument must be an object").ThrowAsJavaScriptException();
    return;
  }

  if (!info[1].IsString()) {
    Napi::TypeError::New(env, "Second argument must be a string").ThrowAsJavaScriptException();
    return;
  }

  ddwaf_config waf_config{{0, 0, 0}, {nullptr, nullptr}, ddwaf_object_free};

  // do not touch these strings after the c_str() assigment
  std::string key_regex_str;
  std::string value_regex_str;

  if (arg_len >= 3) {  // TODO(@simon-id): there is a bug here ?
    // TODO(@simon-id) make a macro here someday
    if (!info[2].IsObject()) {
      Napi::TypeError::New(env, "Second argument must be an object").ThrowAsJavaScriptException();
      return;
    }

    Napi::Object config = info[2].ToObject();

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
  std::string config_path = info[1].As<Napi::String>().Utf8Value();

  ddwaf_object diagnostics;

  mlog("Init Builder");
  ddwaf_builder builder = ddwaf_builder_init(&waf_config);
  bool result = ddwaf_builder_add_or_update_config(builder, LSTRARG(config_path.c_str()), &rules, &diagnostics);

  ddwaf_object_free(&rules);

  Napi::Value diagnostics_js = from_ddwaf_object(&diagnostics, env);
  info.This().As<Napi::Object>().Set("diagnostics", diagnostics_js);

  ddwaf_object_free(&diagnostics);

  if (!result) {
    Napi::Error::New(env, "Invalid rules").ThrowAsJavaScriptException();
    return;
  }

  mlog("Init WAF");
  ddwaf_handle handle = ddwaf_builder_build_instance(builder);

  if (handle == nullptr) {
    Napi::Error::New(env, "Invalid rules").ThrowAsJavaScriptException();
    return;
  }

  this->_builder = builder;
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
  ddwaf_builder_destroy(this->_builder);
  this->_disposed = true;
}

void DDWAF::dispose(const Napi::CallbackInfo& info) {
  mlog("calling dispose on DDWAF instance");
  return this->Finalize(info.Env());
}

Napi::Value DDWAF::update_config(const Napi::CallbackInfo& info) {
  mlog("Calling update config on DDWAF");

  Napi::Env env = info.Env();

  if (this->_disposed) {
    Napi::Error::New(env, "Could not update a disposed WAF instance").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  if (info.Length() < 2) {
    Napi::Error::New(env, "Wrong number of arguments, expected at least 2").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  if (!info[0].IsObject()) {
    Napi::TypeError::New(env, "First argument must be an object").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  if (!info[1].IsString()) {
    Napi::TypeError::New(env, "Second argument must be a string").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  ddwaf_object update;
  mlog("Building config update");
  to_ddwaf_object(&update, env, info[0], 0, false, false, JsSet::Create(env), nullptr);

  mlog("Obtaining config update path");
  std::string config_path = info[1].As<Napi::String>().Utf8Value();

  ddwaf_object diagnostics;

  mlog("Applying new config to builder");
  bool update_result = ddwaf_builder_add_or_update_config(
    this->_builder,
    LSTRARG(config_path.c_str()),
    &update, &diagnostics);

  Napi::Value diagnostics_js = from_ddwaf_object(&diagnostics, env);
  info.This().As<Napi::Object>().Set("diagnostics", diagnostics_js);

  ddwaf_object_free(&diagnostics);

  if (!update_result) {
    mlog("DDWAF Builder update config has failed");
    return Napi::Boolean::New(env, false);
  }

  mlog("Update DDWAF instance");
  ddwaf_handle updated_handle = ddwaf_builder_build_instance(this->_builder);
  ddwaf_object_free(&update);

  if (updated_handle != nullptr) {
    mlog("New DDWAF updated instance")
    ddwaf_destroy(this->_handle);
    this->_handle = updated_handle;

    this->update_known_addresses(info);
    this->update_known_actions(info);
  }

  return Napi::Boolean::New(env, true);
}

Napi::Value DDWAF::remove_config(const Napi::CallbackInfo& info) {
  mlog("Calling remove config on DDWAF");

  Napi::Env env = info.Env();

  if (this->_disposed) {
    Napi::Error::New(env, "Could not update a disposed WAF instance").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  if (info.Length() < 1) {
    Napi::Error::New(env, "Wrong number of arguments, expected at least 1").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  if (!info[0].IsString()) {
    Napi::TypeError::New(env, "First argument must be a string").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  mlog("Obtaining config remove path");
  std::string config_path = info[0].As<Napi::String>().Utf8Value();

  mlog("Applying removed config to builder");
  bool remove_result = ddwaf_builder_remove_config(this->_builder, LSTRARG(config_path.c_str()));

  if (!remove_result) {
    mlog("DDWAF Builder remove config has failed");
    return Napi::Boolean::New(env, false);
  }

  mlog("Update DDWAF instance");
  ddwaf_handle updated_handle = ddwaf_builder_build_instance(this->_builder);

  if (updated_handle != nullptr) {
    mlog("New DDWAF updated instance")
    ddwaf_destroy(this->_handle);
    this->_handle = updated_handle;

    this->update_known_addresses(info);
    this->update_known_actions(info);
  }

  return Napi::Boolean::New(env, true);
}

Napi::Value DDWAF::GetConfigPaths(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (this->_disposed) {
    return Napi::Array::New(env, 0);
  }

  ddwaf_object config_paths;
  ddwaf_builder_get_config_paths(this->_builder, &config_paths, nullptr, 0);

  Napi::Value config_paths_js = from_ddwaf_object(&config_paths, env);

  ddwaf_object_free(&config_paths);

  return config_paths_js;
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
  // there is no error. We need to collect perf data

  // Extract all relevant objects efficiently using a loop
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

    if (length == (sizeof("events") - 1) && memcmp(key, "events", length) == 0) {
      events = child;
    } else if (length == (sizeof("actions") - 1) && memcmp(key, "actions", length) == 0) {
      actions = child;
    } else if (length == (sizeof("attributes") - 1) && memcmp(key, "attributes", length) == 0) {
      attributes = child;
    } else if (length == (sizeof("keep") - 1) && memcmp(key, "keep", length) == 0) {
      keep = child;
    } else if (length == (sizeof("duration") - 1) && memcmp(key, "duration", length) == 0) {
      duration = child;
    } else if (length == (sizeof("timeout") - 1) && memcmp(key, "timeout", length) == 0) {
      run_timeout = child;
    }
  }

  // Now use the extracted objects
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
    res.Set("attributes", from_ddwaf_object(const_cast<ddwaf_object*>(attributes), env));
  }

  if (code == DDWAF_MATCH) {
    mlog("ddwaf result is a match")
    res.Set("status", Napi::String::New(env, "match"));

    if (events) {
      mlog("Set events")
      res.Set("events", from_ddwaf_object(const_cast<ddwaf_object*>(events), env));
    }

    if (actions) {
      mlog("Set actions")
      res.Set("actions", from_ddwaf_object(const_cast<ddwaf_object*>(actions), env));
    }
  }

  if (keep && keep->type == DDWAF_OBJ_BOOL) {
    mlog("Set keep")
    res.Set("keep", Napi::Boolean::New(env, keep->boolean));
  }

  ddwaf_object_free(&result);

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
