/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
// min support Node.js 18.0.0 - https://nodejs.org/api/n-api.html#node-api-version-matrix
#define NAPI_VERSION  8
#include <napi.h>
#include <ddwaf.h>

#include "src/main.h"
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

// Initialize native add-on
Napi::Object Init(Napi::Env env, Napi::Object exports) {
  DDWAF::Init(env, exports);
  DDWAFContext::Init(env, exports);
  return exports;
}

// Register and initialize native add-on
NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
