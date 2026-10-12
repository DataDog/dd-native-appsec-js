/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#define NAPI_VERSION 8
#include <napi.h>
#include <ddwaf.h>

#include <cstring>
#include <string>

#include "src/log.h"
#include "src/waf_internal.h"

#define LSTRARG(value) value, static_cast<uint32_t>(strlen(value))

static bool set_map_string(ddwaf_object* map, const char* key, uint32_t key_length, const std::string& value,
                           ddwaf_allocator alloc) {
  ddwaf_object* slot = ddwaf_object_insert_key(map, key, key_length, alloc);
  if (slot == nullptr) {
    return false;
  }
  return ddwaf_object_set_string(slot, value.c_str(), static_cast<uint32_t>(value.length()), alloc) != nullptr;
}

// Property access may run user JS; return false if it throws.
static bool read_optional_regex(Napi::Env env, Napi::Object config, const char* name, std::string* out) {
  bool has_option = config.HasOwnProperty(name);
  if (env.IsExceptionPending()) {
    return false;
  }
  if (!has_option) {
    return true;
  }

  Napi::Value value = config.Get(name);
  if (env.IsExceptionPending()) {
    return false;
  }
  if (!value.IsString()) {
    Napi::TypeError::New(env, std::string(name) + " must be a string").ThrowAsJavaScriptException();
    return false;
  }

  *out = value.ToString().Utf8Value();
  return !env.IsExceptionPending();
}

bool configure_obfuscator(const Napi::CallbackInfo& info, ddwaf_builder builder) {
  Napi::Env env = info.Env();
  const size_t arg_len = info.Length();
  ddwaf_allocator alloc = ddwaf_get_default_allocator();

  std::string key_regex_str;
  std::string value_regex_str;

  if (arg_len >= 3) {
    if (!info[2].IsObject()) {
      Napi::TypeError::New(env, "Third argument must be an object").ThrowAsJavaScriptException();
      return false;
    }

    Napi::Object config = info[2].ToObject();

    if (!read_optional_regex(env, config, "obfuscatorKeyRegex", &key_regex_str) ||
        !read_optional_regex(env, config, "obfuscatorValueRegex", &value_regex_str)) {
      return false;
    }
  }

  // In libddwaf 2.x, absent regexes use defaults while empty regexes disable that dimension.
  // When either option is set, write both so the other remains disabled as before 2.x.
  if (!key_regex_str.empty() || !value_regex_str.empty()) {
    mlog("Applying obfuscator configuration");

    ddwaf_object obfuscator_config;
    ddwaf_object_set_invalid(&obfuscator_config);

    ddwaf_object* root = ddwaf_object_set_map(&obfuscator_config, 1, alloc);
    ddwaf_object* obfuscator = root == nullptr ? nullptr : ddwaf_object_insert_key(root, LSTRARG("obfuscator"), alloc);

    bool applied = obfuscator != nullptr && ddwaf_object_set_map(obfuscator, 2, alloc) != nullptr &&
                   set_map_string(obfuscator, LSTRARG("key_regex"), key_regex_str, alloc) &&
                   set_map_string(obfuscator, LSTRARG("value_regex"), value_regex_str, alloc);

    if (applied) {
      ddwaf_object obfuscator_diagnostics;
      ddwaf_object_set_invalid(&obfuscator_diagnostics);

      applied = ddwaf_builder_add_or_update_config(builder, OBFUSCATOR_CONFIG_PATH,
                                                   static_cast<uint32_t>(OBFUSCATOR_CONFIG_PATH_LEN),
                                                   &obfuscator_config, &obfuscator_diagnostics);
      ddwaf_object_destroy(&obfuscator_diagnostics, alloc);
    }

    ddwaf_object_destroy(&obfuscator_config, alloc);

    // Fail closed rather than run the WAF without requested redaction.
    if (!applied) {
      Napi::Error::New(env, "Could not apply obfuscator configuration").ThrowAsJavaScriptException();
      return false;
    }
  }

  return true;
}
