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
