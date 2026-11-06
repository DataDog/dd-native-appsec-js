/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
// min support Node.js 18.0.0 - https://nodejs.org/api/n-api.html#node-api-version-matrix
#define NAPI_VERSION  8
#include <napi.h>
#include <ddwaf.h>

#include <string>

#include "src/waf_internal.h"

bool configure_obfuscator(const Napi::CallbackInfo& info, ddwaf_config* waf_config,
                           std::string* key_regex_str, std::string* value_regex_str) {
  Napi::Env env = info.Env();
  size_t arg_len = info.Length();

  if (arg_len >= 3) {  // TODO(@simon-id): there is a bug here ?
    // TODO(@simon-id) make a macro here someday
    if (!info[2].IsObject()) {
      Napi::TypeError::New(env, "Second argument must be an object").ThrowAsJavaScriptException();
      return false;
    }

    Napi::Object config = info[2].ToObject();

    if (config.Has("obfuscatorKeyRegex")) {
      Napi::Value key_regex = config.Get("obfuscatorKeyRegex");

      if (!key_regex.IsString()) {
        Napi::TypeError::New(env, "obfuscatorKeyRegex must be a string").ThrowAsJavaScriptException();
        return false;
      }

      *key_regex_str = key_regex.ToString().Utf8Value();
      waf_config->obfuscator.key_regex = key_regex_str->c_str();
    }

    if (config.Has("obfuscatorValueRegex")) {
      Napi::Value value_regex = config.Get("obfuscatorValueRegex");

      if (!value_regex.IsString()) {
        Napi::TypeError::New(env, "obfuscatorValueRegex must be a string").ThrowAsJavaScriptException();
        return false;
      }

      *value_regex_str = value_regex.ToString().Utf8Value();
      waf_config->obfuscator.value_regex = value_regex_str->c_str();
    }
  }

  return true;
}
