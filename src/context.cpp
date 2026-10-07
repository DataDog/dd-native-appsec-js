/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#define NAPI_VERSION  8
#include <napi.h>
#include <ddwaf.h>

#include "src/main.h"
#include "src/log.h"
#include "src/convert.h"
#include "src/evaluation.h"

DDWAFContext::DDWAFContext(const Napi::CallbackInfo& info) : Napi::ObjectWrap<DDWAFContext>(info) {}

bool DDWAFContext::init(ddwaf_handle handle) {
  // The allocator must outlive the context; the default is safe because it is a process-wide singleton.
  ddwaf_allocator alloc = ddwaf_get_default_allocator();
  ddwaf_context context = ddwaf_context_init(handle, alloc);
  if (context == nullptr) {
    return false;
  }
  this->_context = context;
  this->_alloc = alloc;
  this->_disposed = false;
  return true;
}

void DDWAFContext::Finalize(Napi::Env env) {
  mlog("calling finalize on context");
  if (this->_disposed) {
    return;
  }
  this->_disposed = true;
  ddwaf_context_destroy(this->_context);
  this->_context = nullptr;
}

void DDWAFContext::dispose(const Napi::CallbackInfo& info) {
  mlog("calling dispose on context");
  return this->Finalize(info.Env());
}

Napi::Value DDWAFContext::run(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  int64_t timeout = 0;
  if (!validate_run_args(info, "Calling run on a disposed context", this->_disposed, &timeout)) {
    return env.Null();
  }

  // Per call, not per object: marshalling can re-enter run() through a getter.
  WAFTruncationMetrics metrics;

  ddwaf_object input;
  ddwaf_object_set_invalid(&input);
  ObjectStack stack;
  to_ddwaf_object(&input, env, info[0], 0, true, false, &stack, &metrics, this->_alloc);

  // Marshalling ran user JS, which may have thrown or disposed this object.
  if (env.IsExceptionPending()) {
    ddwaf_object_destroy(&input, this->_alloc);
    return env.Null();
  }
  if (this->_disposed) {
    ddwaf_object_destroy(&input, this->_alloc);
    Napi::Error::New(env, "Context was disposed while reading the data").ThrowAsJavaScriptException();
    return env.Null();
  }

  return eval_and_build_result(env, &input, this->_context, this->_alloc,
                               &metrics, static_cast<uint64_t>(timeout));
}

Napi::Value DDWAFContext::createSubcontext(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (this->_disposed) {
    Napi::Error::New(env, "Calling createSubcontext on a disposed context").ThrowAsJavaScriptException();
    return env.Null();
  }

  mlog("Create subcontext");
  Napi::Object subcontext = env.GetInstanceData<AddonData>()->subcontext_constructor.New({});
  DDWAFSubcontext* raw = Napi::ObjectWrap<DDWAFSubcontext>::Unwrap(subcontext);
  if (!raw->init(this->_context, this->_alloc)) {
    Napi::Error::New(env, "Could not create subcontext").ThrowAsJavaScriptException();
    return env.Null();
  }
  return subcontext;
}

Napi::Value DDWAFContext::GetDisposed(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), this->_disposed);
}

Napi::Object DDWAFContext::Init(Napi::Env env, Napi::Object exports) {
  mlog("Setting up class DDWAFContext");
  Napi::Function func = DefineClass(env, "DDWAFContext", {
    InstanceMethod<&DDWAFContext::run>("run"),
    InstanceMethod<&DDWAFContext::createSubcontext>("createSubcontext"),
    InstanceMethod<&DDWAFContext::dispose>("dispose"),
    InstanceAccessor("disposed", &DDWAFContext::GetDisposed, nullptr, napi_enumerable),
  });

  env.GetInstanceData<AddonData>()->context_constructor = Napi::Persistent(func);
  return exports;
}

DDWAFSubcontext::DDWAFSubcontext(const Napi::CallbackInfo& info) : Napi::ObjectWrap<DDWAFSubcontext>(info) {}

bool DDWAFSubcontext::init(ddwaf_context context, ddwaf_allocator alloc) {
  ddwaf_subcontext subcontext = ddwaf_subcontext_init(context);
  if (subcontext == nullptr) {
    return false;
  }
  this->_subcontext = subcontext;
  this->_alloc = alloc;
  this->_disposed = false;
  return true;
}

void DDWAFSubcontext::Finalize(Napi::Env env) {
  mlog("calling finalize on subcontext");
  if (this->_disposed) {
    return;
  }
  this->_disposed = true;
  ddwaf_subcontext_destroy(this->_subcontext);
  this->_subcontext = nullptr;
}

void DDWAFSubcontext::dispose(const Napi::CallbackInfo& info) {
  mlog("calling dispose on subcontext");
  return this->Finalize(info.Env());
}

Napi::Value DDWAFSubcontext::run(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  int64_t timeout = 0;
  if (!validate_run_args(info, "Calling run on a disposed subcontext", this->_disposed, &timeout)) {
    return env.Null();
  }

  // Per call, not per object: marshalling can re-enter run() through a getter.
  WAFTruncationMetrics metrics;

  ddwaf_object input;
  ddwaf_object_set_invalid(&input);
  ObjectStack stack;
  to_ddwaf_object(&input, env, info[0], 0, true, false, &stack, &metrics, this->_alloc);

  // Marshalling ran user JS, which may have thrown or disposed this object.
  if (env.IsExceptionPending()) {
    ddwaf_object_destroy(&input, this->_alloc);
    return env.Null();
  }
  if (this->_disposed) {
    ddwaf_object_destroy(&input, this->_alloc);
    Napi::Error::New(env, "Subcontext was disposed while reading the data").ThrowAsJavaScriptException();
    return env.Null();
  }

  return eval_and_build_result(env, &input, this->_subcontext, this->_alloc,
                               &metrics, static_cast<uint64_t>(timeout));
}

Napi::Value DDWAFSubcontext::GetDisposed(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), this->_disposed);
}

Napi::Object DDWAFSubcontext::Init(Napi::Env env, Napi::Object exports) {
  mlog("Setting up class DDWAFSubcontext");
  Napi::Function func = DefineClass(env, "DDWAFSubcontext", {
    InstanceMethod<&DDWAFSubcontext::run>("run"),
    InstanceMethod<&DDWAFSubcontext::dispose>("dispose"),
    InstanceAccessor("disposed", &DDWAFSubcontext::GetDisposed, nullptr, napi_enumerable),
  });

  env.GetInstanceData<AddonData>()->subcontext_constructor = Napi::Persistent(func);
  return exports;
}
