/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#define NAPI_VERSION  4
#include <napi.h>
#include <stdio.h>
#include <ddwaf.h>
#include "src/main.h"
#include "src/log.h"
#include "src/convert.h"

Napi::FunctionReference* constructor = new Napi::FunctionReference();

Napi::Object DDWAF::Init(Napi::Env env, Napi::Object exports) {
    mlog("Setting up class DDWAF");
    Napi::Function func = DefineClass(env, "DDWAF", {
      StaticMethod<&DDWAF::version>("version"),
      InstanceMethod<&DDWAF::createContext>("createContext"),
      InstanceMethod<&DDWAF::dispose>("dispose"),
      InstanceAccessor(
        "disposed",
        &DDWAF::GetDisposed,
        nullptr,
        napi_enumerable),
    });
    exports.Set("DDWAF", func);
    return exports;
}

Napi::Value DDWAF::version(const Napi::CallbackInfo& info) {
  mlog("Get libddwaf version");
  Napi::Env       env       = info.Env();
  Napi::Object    result    = Napi::Object::New(env);
  ddwaf_version version;
  ddwaf_get_version(&version);

  result.Set(Napi::String::New(env, "major"),
      Napi::Number::New(env, version.major));
  result.Set(Napi::String::New(env, "minor"),
      Napi::Number::New(env, version.minor));
  result.Set(Napi::String::New(env, "patch"),
      Napi::Number::New(env, version.patch));
  return result;
}

Napi::Value DDWAF::GetDisposed(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), this->_disposed);
}

DDWAF::DDWAF(const Napi::CallbackInfo& info) : Napi::ObjectWrap<DDWAF>(info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    Napi::Error::New(env,
                      "Wrong number of arguments, expected 1")
                      .ThrowAsJavaScriptException();
    return;
  }
  if (!info[0].IsObject()) {
    Napi::TypeError::New(env,
                          "Wrong argument, expected an object")
                          .ThrowAsJavaScriptException();
    return;
  }
  ddwaf_object rules;
  mlog("building rules");
  to_ddwaf_object(&rules, env, info[0]);
  mlog("Init WAF");
  ddwaf_handle handle = ddwaf_init(&rules, nullptr);
  if (handle == nullptr) {
      Napi::Error::New(env, "Invalid rules").ThrowAsJavaScriptException();
      return;
  }

  this->_handle = handle;
  this->_disposed = false;
}

void DDWAF::Finalize(Napi::Env env) {
  mlog("calling finalize on DDWAF");
  if (this->_disposed) {
    return;
  }
  ddwaf_destroy(this->_handle);
  this->_disposed = true;
}

void DDWAF::dispose(const Napi::CallbackInfo& info) {
  mlog("calling dispose on DDWAF instance");
  return this->Finalize(info.Env());
}

Napi::Value DDWAF::createContext(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (this->_disposed) {
    Napi::Error::New(env,
          "Calling createContext on a disposed DDWAF instance")
           .ThrowAsJavaScriptException();
    return info.Env().Null();
  }
  mlog("Create context");
  Napi::Value context = constructor->New({});
  DDWAFContext* raw = Napi::ObjectWrap<DDWAFContext>::Unwrap(
                                      context.As<Napi::Object>());
  // TODO(@vdeturckheim): dispose check
  if (!raw->init(this->_handle)) {
    Napi::Error::New(env, "Could not create context")
                           .ThrowAsJavaScriptException();
    return env.Null();
  }
  return context;
}

DDWAFContext::DDWAFContext(const Napi::CallbackInfo& info) :
                          Napi::ObjectWrap<DDWAFContext>(info) {
  this->_disposed = false;
}

bool DDWAFContext::init(ddwaf_handle handle) {
  ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
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

Napi::Value DDWAFContext::run(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (this->_disposed) {
    Napi::Error::New(env,
                          "Calling run on a disposed context")
                          .ThrowAsJavaScriptException();
    return info.Env().Null();
  }
  if (info.Length() < 2) {  // inputs, timeout
    Napi::Error::New(env,
                          "Wrong number of arguments, expected 2")
                          .ThrowAsJavaScriptException();
    return info.Env().Null();
  }
  if (!info[0].IsObject()) {
    Napi::TypeError::New(env,
                          "First argument must be an object")
                          .ThrowAsJavaScriptException();
    return info.Env().Null();
  }
  if (!info[1].IsNumber()) {
    Napi::TypeError::New(env,
                          "Second argument must be a number")
                          .ThrowAsJavaScriptException();
    return info.Env().Null();
  }
  int64_t timeout = info[1].ToNumber().Int64Value();
  if (timeout <= 0) {
    Napi::TypeError::New(env,
                         "Second argument must be a positive number")
                         .ThrowAsJavaScriptException();
    return info.Env().Null();
  }

  ddwaf_result result;
  ddwaf_object data;
  to_ddwaf_object(&data, env, info[0]);

  DDWAF_RET_CODE code = ddwaf_run(this->_context, &data,
                                  &result, (uint64_t) timeout);
  mlog("Run result action %i", result.action);

  switch (code) {
    case DDWAF_ERR_INTERNAL:
      Napi::Error::New(env, "Internal error").ThrowAsJavaScriptException();
      return info.Env().Null();
    case DDWAF_ERR_INVALID_OBJECT:
      Napi::Error::New(env, "Invalid ddwaf object")
                          .ThrowAsJavaScriptException();
      return info.Env().Null();
    case DDWAF_ERR_INVALID_ARGUMENT:
      Napi::Error::New(env, "Invalid arguments").ThrowAsJavaScriptException();
      return info.Env().Null();
    case DDWAF_ERR_TIMEOUT:
      Napi::Error::New(env, "ddwaf timeout").ThrowAsJavaScriptException();
      return info.Env().Null();
    default:
      break;
  }
  // there is not error. We need to collect perf and potential error data
  Napi::Object res = Napi::Object::New(env);
  if (result.perfData) {
    mlog("Set perfData");
    res.Set(
      Napi::String::New(env, "perfData"),
      Napi::String::New(env, result.perfData));
  }
  if (result.perfTotalRuntime) {
    mlog("Set perfTotalRuntime");
    res.Set(
      Napi::String::New(env, "perfTotalRuntime"),
      Napi::Number::New(env, result.perfTotalRuntime));
  }
  mlog("Set perf results ok");
  if (code != DDWAF_GOOD) {
    res.Set(
      Napi::String::New(env, "data"),
      Napi::String::New(env, result.data));
  }
  if (code == DDWAF_MONITOR) {
    res.Set(
      Napi::String::New(env, "action"),
      Napi::String::New(env, "monitor"));
  }
  if (code == DDWAF_BLOCK) {
    res.Set(
      Napi::String::New(env, "action"),
      Napi::String::New(env, "block"));
  }
  return res;
}
Napi::Value DDWAFContext::GetDisposed(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), this->_disposed);
}

Napi::Object DDWAFContext::Init(Napi::Env env, Napi::Object exports) {
    mlog("Setting up class DDWAFContext");
    Napi::Function func = DefineClass(env, "DDWAFContext", {
      InstanceMethod<&DDWAFContext::run>("run"),
      InstanceMethod<&DDWAFContext::dispose>("dispose"),
      InstanceAccessor(
        "disposed",
        &DDWAFContext::GetDisposed,
        nullptr,
        napi_enumerable),
    });
    *constructor = Napi::Persistent(func);
    return exports;
}

// Initialize native add-on
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    DDWAF::Init(env, exports);
    DDWAFContext::Init(env, exports);
    return exports;
}

// Register and initialize native add-on
NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
