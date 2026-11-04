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
#include "src/waf_internal.h"

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

  if (!configure_obfuscator(info, &waf_config, &key_regex_str, &value_regex_str)) {
    return;
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
