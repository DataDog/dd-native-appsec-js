/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#define NAPI_VERSION  8
#include <napi.h>
#include <ddwaf.h>

#include "src/main.h"
#include "src/convert.h"
#include "src/log.h"

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
  });
  if (!define_own_property(exports, "DDWAF", func)) {
    return exports;
  }
  return exports;
}

Napi::Value DDWAF::version(const Napi::CallbackInfo& info) {
  mlog("Get libddwaf version");
  return Napi::String::New(info.Env(), ddwaf_get_version());
}

Napi::Value DDWAF::GetDisposed(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), this->_disposed);
}

void DDWAF::Finalize(Napi::Env env) {
  mlog("calling finalize on DDWAF");
  if (this->_disposed) {
    return;
  }
  this->_disposed = true;
  ddwaf_destroy(this->_handle);
  ddwaf_builder_destroy(this->_builder);
  this->_handle = nullptr;
  this->_builder = nullptr;
}

void DDWAF::dispose(const Napi::CallbackInfo& info) {
  mlog("calling dispose on DDWAF instance");
  return this->Finalize(info.Env());
}

Napi::Value DDWAF::createContext(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (this->_disposed) {
    Napi::Error::New(env, "Calling createContext on a disposed DDWAF instance").ThrowAsJavaScriptException();
    return env.Null();
  }
  // A null handle is valid after all configurations are removed; expose it as no context.
  if (this->_handle == nullptr) {
    mlog("No ruleset, no context");
    return env.Null();
  }
  mlog("Create context");
  Napi::Object context = env.GetInstanceData<AddonData>()->context_constructor.New({});
  DDWAFContext* raw = Napi::ObjectWrap<DDWAFContext>::Unwrap(context);
  if (!raw->init(this->_handle)) {
    Napi::Error::New(env, "Could not create context").ThrowAsJavaScriptException();
    return env.Null();
  }
  return context;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  env.SetInstanceData(new AddonData());

  DDWAF::Init(env, exports);
  DDWAFContext::Init(env, exports);
  DDWAFSubcontext::Init(env, exports);
  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
