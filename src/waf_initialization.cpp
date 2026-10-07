/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#define NAPI_VERSION  8
#include <napi.h>
#include <ddwaf.h>

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

  std::string config_path = info[1].As<Napi::String>().Utf8Value();
  if (!validate_config_path(env, config_path)) {
    return;
  }

  ddwaf_allocator alloc = ddwaf_get_default_allocator();

  mlog("Init Builder");
  ddwaf_builder builder = ddwaf_builder_init();

  if (builder == nullptr) {
    Napi::Error::New(env, "Could not create the WAF builder").ThrowAsJavaScriptException();
    return;
  }

  if (!configure_obfuscator(info, builder)) {
    ddwaf_builder_destroy(builder);
    return;
  }

  ddwaf_object rules;
  ddwaf_object_set_invalid(&rules);
  mlog("building rules");
  ObjectStack rules_stack;
  to_ddwaf_object(&rules, env, info[0], 0, false, false, &rules_stack, nullptr, alloc);

  if (env.IsExceptionPending()) {
    mlog("Exception pending while building rules");
    ddwaf_object_destroy(&rules, alloc);
    ddwaf_builder_destroy(builder);
    return;
  }

  if (!validate_obfuscator_config(&rules)) {
    ddwaf_object_destroy(&rules, alloc);
    ddwaf_builder_destroy(builder);
    Napi::Error::New(env, "Invalid obfuscator regular expression").ThrowAsJavaScriptException();
    return;
  }

  ddwaf_object diagnostics;
  ddwaf_object_set_invalid(&diagnostics);

  bool result = ddwaf_builder_add_or_update_config(builder, config_path.data(),
                                                   static_cast<uint32_t>(config_path.length()),
                                                   &rules, &diagnostics);

  // The builder copies the configuration, so the source is safe to release.
  ddwaf_object_destroy(&rules, alloc);

  Napi::Value diagnostics_js = from_ddwaf_object(&diagnostics, env);
  bool diagnostics_published = define_own_property(
    info.This().As<Napi::Object>(), "diagnostics", diagnostics_js);

  ddwaf_object_destroy(&diagnostics, alloc);

  if (!diagnostics_published) {
    mlog("Exception pending while reporting diagnostics");
    ddwaf_builder_destroy(builder);
    return;
  }

  if (!result) {
    ddwaf_builder_destroy(builder);
    Napi::Error::New(env, "Invalid rules").ThrowAsJavaScriptException();
    return;
  }

  mlog("Init WAF");
  ddwaf_handle handle = ddwaf_builder_build_instance(builder);

  if (handle == nullptr) {
    ddwaf_builder_destroy(builder);
    Napi::Error::New(env, "Invalid rules").ThrowAsJavaScriptException();
    return;
  }

  this->_builder = builder;
  this->_handle = handle;
  this->_disposed = false;

  this->update_known_addresses(info);
  if (!env.IsExceptionPending()) {
    this->update_known_actions(info);
  }
  if (env.IsExceptionPending()) {
    // Failed construction deletes the wrapper without calling Finalize().
    this->Finalize(env);
  }
}
