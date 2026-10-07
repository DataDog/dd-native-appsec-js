/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#define NAPI_VERSION  8
#include <napi.h>
#include <ddwaf.h>

#include <cstring>
#include <string>
#include <vector>

#include "src/main.h"
#include "src/log.h"
#include "src/convert.h"
#include "src/waf_internal.h"

static bool is_obfuscator_config_path(const std::string& path) {
  return path.length() == OBFUSCATOR_CONFIG_PATH_LEN &&
         memcmp(path.data(), OBFUSCATOR_CONFIG_PATH, OBFUSCATOR_CONFIG_PATH_LEN) == 0;
}

// Reject empty paths because libddwaf leaves diagnostics uninitialized; reserve the internal obfuscator path.
bool validate_config_path(Napi::Env env, const std::string& path) {
  if (path.empty()) {
    Napi::TypeError::New(env, "Config path must not be empty").ThrowAsJavaScriptException();
    return false;
  }
  if (is_obfuscator_config_path(path)) {
    Napi::Error::New(env, "Config path is reserved").ThrowAsJavaScriptException();
    return false;
  }
  return true;
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

  mlog("Obtaining config update path");
  std::string config_path = info[1].As<Napi::String>().Utf8Value();
  if (!validate_config_path(env, config_path)) {
    return env.Undefined();
  }

  ddwaf_allocator alloc = ddwaf_get_default_allocator();

  ddwaf_object update;
  ddwaf_object_set_invalid(&update);
  mlog("Building config update");
  ObjectStack update_stack;
  to_ddwaf_object(&update, env, info[0], 0, false, false, &update_stack, nullptr, alloc);

  if (env.IsExceptionPending()) {
    mlog("Exception pending while building config update");
    ddwaf_object_destroy(&update, alloc);
    return env.Undefined();
  }

  if (this->_disposed) {
    ddwaf_object_destroy(&update, alloc);
    Napi::Error::New(env, "Could not update a disposed WAF instance").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  if (!validate_obfuscator_config(&update)) {
    ddwaf_object_destroy(&update, alloc);
    // No builder diagnostics exist for a validation failure; discard the previous update's.
    if (!define_own_property(info.This().As<Napi::Object>(), "diagnostics", Napi::Object::New(env))) {
      return env.Undefined();
    }
    return Napi::Boolean::New(env, false);
  }

  ddwaf_object diagnostics;
  ddwaf_object_set_invalid(&diagnostics);

  mlog("Applying new config to builder");
  bool update_result = ddwaf_builder_add_or_update_config(
    this->_builder,
    config_path.data(), static_cast<uint32_t>(config_path.length()),
    &update, &diagnostics);

  // The builder copies the configuration, so the source is always safe to release.
  ddwaf_object_destroy(&update, alloc);

  // A failed same-path replacement may still remove the previous builder configuration.
  this->rebuild_instance();

  Napi::Value diagnostics_js = from_ddwaf_object(&diagnostics, env);
  bool diagnostics_published = define_own_property(
    info.This().As<Napi::Object>(), "diagnostics", diagnostics_js);

  ddwaf_object_destroy(&diagnostics, alloc);

  if (!diagnostics_published) {
    mlog("Exception pending while reporting diagnostics");
    return env.Undefined();
  }

  this->update_known_addresses(info);
  this->update_known_actions(info);

  if (env.IsExceptionPending()) {
    mlog("Exception pending while reporting known metadata");
    return env.Undefined();
  }

  if (!update_result) {
    mlog("DDWAF Builder update config has failed");
    return Napi::Boolean::New(env, false);
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
  if (!validate_config_path(env, config_path)) {
    return env.Undefined();
  }

  mlog("Applying removed config to builder");
  bool remove_result = ddwaf_builder_remove_config(this->_builder, config_path.data(),
                                                   static_cast<uint32_t>(config_path.length()));

  if (!remove_result) {
    mlog("DDWAF Builder remove config has failed");
    return Napi::Boolean::New(env, false);
  }

  this->rebuild_instance();
  this->update_known_addresses(info);
  this->update_known_actions(info);

  if (env.IsExceptionPending()) {
    mlog("Exception pending while reporting known metadata");
    return env.Undefined();
  }

  return Napi::Boolean::New(env, true);
}

void DDWAF::rebuild_instance() {
  mlog("Update DDWAF instance");
  ddwaf_handle updated_handle = ddwaf_builder_build_instance(this->_builder);

  ddwaf_destroy(this->_handle);
  this->_handle = updated_handle;
}

Napi::Value DDWAF::GetConfigPaths(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (this->_disposed) {
    return Napi::Array::New(env, 0);
  }

  ddwaf_allocator alloc = ddwaf_get_default_allocator();

  ddwaf_object config_paths;
  ddwaf_object_set_invalid(&config_paths);
  ddwaf_builder_get_config_paths(this->_builder, &config_paths, nullptr, 0);

  size_t size = ddwaf_object_get_size(&config_paths);
  Napi::Array config_paths_js = Napi::Array::New(env);
  if (env.IsExceptionPending()) {
    ddwaf_object_destroy(&config_paths, alloc);
    return config_paths_js;
  }
  uint32_t count = 0;

  for (size_t i = 0; i < size; ++i) {
    const ddwaf_object* entry = ddwaf_object_at_value(&config_paths, i);
    if (entry == nullptr) {
      continue;
    }

    size_t length = 0;
    const char* path = ddwaf_object_get_string(entry, &length);
    if (path == nullptr) {
      continue;
    }

    // Skip the internal obfuscator configuration.
    if (length == OBFUSCATOR_CONFIG_PATH_LEN &&
        memcmp(path, OBFUSCATOR_CONFIG_PATH, OBFUSCATOR_CONFIG_PATH_LEN) == 0) {
      continue;
    }

    Napi::Value path_js = Napi::String::New(env, path, length);
    if (env.IsExceptionPending() || !define_own_property(config_paths_js, count, path_js)) {
      break;
    }
    ++count;
  }

  ddwaf_object_destroy(&config_paths, alloc);

  return config_paths_js;
}

static void set_string_set(const Napi::CallbackInfo& info, const char* property,
                           const char* const* values, uint32_t size) {
  std::vector<std::string> owned_values;
  owned_values.reserve(size);
  for (uint32_t i = 0; i < size; ++i) {
    owned_values.emplace_back(values[i]);
  }

  Napi::Env env = info.Env();
  if (env.IsExceptionPending()) {
    return;
  }

  Napi::Array items = Napi::Array::New(env, size);
  if (env.IsExceptionPending()) {
    return;
  }

  for (uint32_t i = 0; i < size; ++i) {
    Napi::Value item = Napi::String::New(env, owned_values[i]);
    if (env.IsExceptionPending() || !define_own_property(items, i, item)) {
      return;
    }
  }

  Napi::Value set_constructor = env.Global().Get("Set");
  if (env.IsExceptionPending()) {
    return;
  }
  if (!set_constructor.IsFunction()) {
    Napi::TypeError::New(env, "Set is not a constructor").ThrowAsJavaScriptException();
    return;
  }

  Napi::Value set = set_constructor.As<Napi::Function>().New({items});
  if (env.IsExceptionPending()) {
    return;
  }

  // A replaced Set may return a non-Set; require callable has() for membership tests.
  Napi::Value has = set.IsObject() ? set.As<Napi::Object>().Get("has") : env.Undefined();
  if (env.IsExceptionPending()) {
    return;
  }
  if (!has.IsFunction()) {
    Napi::TypeError::New(env, "Set did not produce a usable set").ThrowAsJavaScriptException();
    return;
  }

  define_own_property(info.This().As<Napi::Object>(), property, set);
}

void DDWAF::update_known_addresses(const Napi::CallbackInfo& info) {
  uint32_t size = 0;
  const char* const* known_addresses = this->_handle == nullptr
    ? nullptr
    : ddwaf_known_addresses(this->_handle, &size);

  set_string_set(info, "knownAddresses", known_addresses, size);
}

void DDWAF::update_known_actions(const Napi::CallbackInfo& info) {
  uint32_t size = 0;
  const char* const* known_actions = this->_handle == nullptr
    ? nullptr
    : ddwaf_known_actions(this->_handle, &size);

  set_string_set(info, "knownActions", known_actions, size);
}
