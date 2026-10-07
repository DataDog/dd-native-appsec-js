/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#define NAPI_VERSION  8
#include <napi.h>
#include <ddwaf.h>

#include <cstring>
#include <limits>
#include <string>

#include "src/log.h"
#include "src/waf_internal.h"

#define LSTRARG(value) value, static_cast<uint32_t>(strlen(value))

static bool set_map_string(
  ddwaf_object* map,
  const char* key,
  uint32_t key_length,
  const std::string& value,
  ddwaf_allocator alloc
) {
  ddwaf_object* slot = ddwaf_object_insert_key(map, key, key_length, alloc);
  if (slot == nullptr) {
    return false;
  }
  return ddwaf_object_set_string(slot, value.c_str(),
                                 static_cast<uint32_t>(value.length()), alloc) != nullptr;
}

static bool build_regex_probe(ddwaf_object* probe, const std::string& candidate,
                              ddwaf_allocator alloc) {
  // libddwaf 2.1.0 silently falls back on invalid obfuscator regexes without
  // reporting a compilation error in diagnostics. A temporary scanner uses the
  // same RE2 engine and memory limit, and exposes compilation errors through the
  // builder. Keep this workaround confined to configuration validation; replace
  // it with obfuscator diagnostics when libddwaf exposes them.
  ddwaf_object* root = ddwaf_object_set_map(probe, 1, alloc);
  ddwaf_object* scanners = root == nullptr
    ? nullptr
    : ddwaf_object_insert_key(root, LSTRARG("scanners"), alloc);
  if (scanners == nullptr || ddwaf_object_set_array(scanners, 1, alloc) == nullptr) {
    return false;
  }

  ddwaf_object* scanner = ddwaf_object_insert(scanners, alloc);
  if (scanner == nullptr || ddwaf_object_set_map(scanner, 3, alloc) == nullptr ||
      !set_map_string(scanner, LSTRARG("id"), "__regex_probe", alloc)) {
    return false;
  }

  ddwaf_object* tags = ddwaf_object_insert_key(scanner, LSTRARG("tags"), alloc);
  if (tags == nullptr || ddwaf_object_set_map(tags, 0, alloc) == nullptr) {
    return false;
  }

  ddwaf_object* value = ddwaf_object_insert_key(scanner, LSTRARG("value"), alloc);
  if (value == nullptr || ddwaf_object_set_map(value, 2, alloc) == nullptr ||
      !set_map_string(value, LSTRARG("operator"), "match_regex", alloc)) {
    return false;
  }

  ddwaf_object* parameters = ddwaf_object_insert_key(value, LSTRARG("parameters"), alloc);
  return parameters != nullptr &&
         ddwaf_object_set_map(parameters, 1, alloc) != nullptr &&
         set_map_string(parameters, LSTRARG("regex"), candidate, alloc);
}

static bool validate_obfuscator_regex(const std::string& candidate) {
  if (candidate.empty()) {
    return true;
  }
  if (candidate.length() > std::numeric_limits<uint32_t>::max()) {
    return false;
  }

  ddwaf_allocator alloc = ddwaf_get_default_allocator();
  ddwaf_object probe;
  ddwaf_object diagnostics;
  ddwaf_object_set_invalid(&probe);
  ddwaf_object_set_invalid(&diagnostics);

  ddwaf_builder builder = ddwaf_builder_init();
  bool valid = builder != nullptr && build_regex_probe(&probe, candidate, alloc) &&
               ddwaf_builder_add_or_update_config(
                 builder, LSTRARG("__regex_probe"), &probe, &diagnostics);

  ddwaf_object_destroy(&diagnostics, alloc);
  ddwaf_object_destroy(&probe, alloc);
  if (builder != nullptr) {
    ddwaf_builder_destroy(builder);
  }
  return valid;
}

static bool validate_obfuscator_field(const ddwaf_object* obfuscator,
                                       const char* field, size_t field_length) {
  const ddwaf_object* value = ddwaf_object_find(obfuscator, field, field_length);
  if (value == nullptr) {
    return true;
  }
  if (!ddwaf_object_is_string(value)) {
    return false;
  }

  size_t length = 0;
  const char* candidate = ddwaf_object_get_string(value, &length);
  if (length == 0) {
    return true;
  }
  return candidate != nullptr && validate_obfuscator_regex(std::string(candidate, length));
}

bool validate_obfuscator_config(const ddwaf_object* config) {
  if (!ddwaf_object_is_map(config)) {
    return true;
  }

  const ddwaf_object* obfuscator = ddwaf_object_find(config, LSTRARG("obfuscator"));
  if (obfuscator == nullptr) {
    return true;
  }
  if (!ddwaf_object_is_map(obfuscator)) {
    return false;
  }

  bool key_valid = validate_obfuscator_field(obfuscator, LSTRARG("key_regex"));
  bool value_valid = validate_obfuscator_field(obfuscator, LSTRARG("value_regex"));
  return key_valid && value_valid;
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

  bool key_regex_valid = validate_obfuscator_regex(key_regex_str);
  bool value_regex_valid = validate_obfuscator_regex(value_regex_str);
  if (!key_regex_valid || !value_regex_valid) {
    Napi::Error::New(env, "Invalid obfuscator regular expression").ThrowAsJavaScriptException();
    return false;
  }

  // In libddwaf 2.x, absent regexes use defaults while empty regexes disable that dimension.
  // When either option is set, write both so the other remains disabled as before 2.x.
  if (!key_regex_str.empty() || !value_regex_str.empty()) {
    mlog("Applying obfuscator configuration");

    ddwaf_object obfuscator_config;
    ddwaf_object_set_invalid(&obfuscator_config);

    ddwaf_object* root = ddwaf_object_set_map(&obfuscator_config, 1, alloc);
    ddwaf_object* obfuscator = root == nullptr
      ? nullptr
      : ddwaf_object_insert_key(root, LSTRARG("obfuscator"), alloc);

    bool applied = obfuscator != nullptr &&
                   ddwaf_object_set_map(obfuscator, 2, alloc) != nullptr &&
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
