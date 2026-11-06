/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
// min support Node.js 18.0.0 - https://nodejs.org/api/n-api.html#node-api-version-matrix
#define NAPI_VERSION  8
#include <napi.h>
#include <ddwaf.h>

#include <cstring>
#include <string>

#include "src/main.h"
#include "src/log.h"
#include "src/convert.h"

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

  // The caller owns the input config even when the builder rejects it.
  ddwaf_object_free(&update);

  Napi::Value diagnostics_js = from_ddwaf_object(&diagnostics, env);
  info.This().As<Napi::Object>().Set("diagnostics", diagnostics_js);

  ddwaf_object_free(&diagnostics);

  if (!update_result) {
    mlog("DDWAF Builder update config has failed");
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
