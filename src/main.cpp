/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#define NAPI_VERSION  4
#include <napi.h>
#include <stdio.h>
#include <ddwaf.h>
#include <string>
#include "src/main.h"
#include "src/log.h"
#include "src/convert.h"

Napi::FunctionReference* constructor = new Napi::FunctionReference();

Napi::Object DDWAF::Init(Napi::Env env, Napi::Object exports) {
  mlog("Setting up class DDWAF");
  Napi::Function func = DefineClass(env, "DDWAF", {
    StaticMethod<&DDWAF::version>("version"),
    InstanceMethod<&DDWAF::updateRuleData>("updateRuleData"),
    InstanceMethod<&DDWAF::createContext>("createContext"),
    InstanceMethod<&DDWAF::dispose>("dispose"),
    InstanceAccessor("disposed", &DDWAF::GetDisposed, nullptr, napi_enumerable),
    // TODO(simon-id): should we have an InstanceValue for rulesInfo here ?
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

DDWAF::DDWAF(const Napi::CallbackInfo& info) : Napi::ObjectWrap<DDWAF>(info) {
  Napi::Env env = info.Env();
  size_t arg_len = info.Length();
  if (arg_len < 1) {
    Napi::Error::New(env, "Wrong number of arguments, expected at least 1").ThrowAsJavaScriptException();
    return;
  }
  if (!info[0].IsObject()) {
    Napi::TypeError::New(env, "First argument must be an object").ThrowAsJavaScriptException();
    return;
  }

  ddwaf_config waf_config{{0, 0, 0}, {nullptr, nullptr}, ddwaf_object_free};

  // do not touch these strings after the c_str() assigment
  std::string key_regex_str;
  std::string value_regex_str;

  if (arg_len >= 2) {
    // TODO(@simon-id) make a macro here someday
    if (!info[1].IsObject()) {
      Napi::TypeError::New(env, "Second argument must be an object").ThrowAsJavaScriptException();
      return;
    }

    Napi::Object config = info[1].ToObject();

    if (config.Has("obfuscatorKeyRegex")) {
      Napi::Value key_regex = config.Get("obfuscatorKeyRegex");

      if (!key_regex.IsString()) {
        Napi::TypeError::New(env, "obfuscatorKeyRegex must be a string").ThrowAsJavaScriptException();
        return;
      }

      key_regex_str = key_regex.ToString().Utf8Value();
      waf_config.obfuscator.key_regex = key_regex_str.c_str();
    }

    if (config.Has("obfuscatorValueRegex")) {
      Napi::Value value_regex = config.Get("obfuscatorValueRegex");

      if (!value_regex.IsString()) {
        Napi::TypeError::New(env, "obfuscatorValueRegex must be a string").ThrowAsJavaScriptException();
        return;
      }

      value_regex_str = value_regex.ToString().Utf8Value();
      waf_config.obfuscator.value_regex = value_regex_str.c_str();
    }
  }

  ddwaf_object rules;
  mlog("building rules");
  to_ddwaf_object(&rules, env, info[0], 0, false);

  ddwaf_ruleset_info rules_info;

  mlog("Init WAF");
  ddwaf_handle handle = ddwaf_init(&rules, &waf_config, &rules_info);
  ddwaf_object_free(&rules);

  Napi::Object result = Napi::Object::New(env);

  if (rules_info.version != nullptr) {
    result.Set("version", Napi::String::New(env, rules_info.version));
  }
  result.Set("loaded", Napi::Number::New(env, rules_info.loaded));
  result.Set("failed", Napi::Number::New(env, rules_info.failed));
  Napi::Value errors = from_ddwaf_object(&rules_info.errors, env);
  result.Set("errors", errors);

  Napi::PropertyDescriptor pd = Napi::PropertyDescriptor::Value("rulesInfo", result, napi_enumerable);

  info.This().As<Napi::Object>().DefineProperty(pd);

  ddwaf_ruleset_info_free(&rules_info);

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

void DDWAF::updateRuleData(const Napi::CallbackInfo& info) {
  mlog("Updating rule data on DDWAF");
  Napi::Env env = info.Env();
  if (this->_disposed) {
    Napi::Error::New(env, "Could not update rule data on a disposed WAF").ThrowAsJavaScriptException();
    return;
  }
  if (info.Length() < 1) {
    Napi::Error::New(env, "Wrong number of arguments, expected 1").ThrowAsJavaScriptException();
    return;
  }
  if (!info[0].IsArray()) {
    Napi::TypeError::New(env, "First argument must be an array").ThrowAsJavaScriptException();
    return;
  }

  ddwaf_object data;
  to_ddwaf_object(&data, env, info[0], 0, false);

  DDWAF_RET_CODE code = ddwaf_update_rule_data(this->_handle, &data);

  switch (code) {
    case DDWAF_ERR_INTERNAL:
      Napi::Error::New(env, "Internal error").ThrowAsJavaScriptException();
      break;
    case DDWAF_ERR_INVALID_OBJECT:
      Napi::Error::New(env, "Invalid ddwaf object").ThrowAsJavaScriptException();
      break;
    case DDWAF_ERR_INVALID_ARGUMENT:
      Napi::Error::New(env, "Invalid arguments").ThrowAsJavaScriptException();
      break;
    default:
      break;
  }
  ddwaf_object_free(&data);
}

Napi::Value DDWAF::createContext(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (this->_disposed) {
    Napi::Error::New(env, "Calling createContext on a disposed DDWAF instance").ThrowAsJavaScriptException();
    return env.Null();
  }
  mlog("Create context");
  Napi::Value context = constructor->New({});
  DDWAFContext* raw = Napi::ObjectWrap<DDWAFContext>::Unwrap(context.As<Napi::Object>());
  // TODO(@vdeturckheim): dispose check
  if (!raw->init(this->_handle)) {
    Napi::Error::New(env, "Could not create context").ThrowAsJavaScriptException();
    return env.Null();
  }
  return context;
}

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

Napi::Value DDWAFContext::run(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (this->_disposed) {
    Napi::Error::New(env, "Calling run on a disposed context").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (info.Length() < 2) {  // inputs, timeout
    Napi::Error::New(env, "Wrong number of arguments, expected 2").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!info[0].IsObject()) {
    Napi::TypeError::New(env, "First argument must be an object").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!info[1].IsNumber()) {
    Napi::TypeError::New(env, "Second argument must be a number").ThrowAsJavaScriptException();
    return env.Null();
  }
  int64_t timeout = info[1].ToNumber().Int64Value();
  if (timeout <= 0) {
    Napi::TypeError::New(env, "Second argument must be greater than 0").ThrowAsJavaScriptException();
    return env.Null();
  }

  ddwaf_result result;
  ddwaf_object data;
  to_ddwaf_object(&data, env, info[0], 0, true);

  DDWAF_RET_CODE code = ddwaf_run(this->_context, &data, &result, (uint64_t) timeout);

  switch (code) {
    case DDWAF_ERR_INTERNAL:
      Napi::Error::New(env, "Internal error").ThrowAsJavaScriptException();
      return env.Null();
    case DDWAF_ERR_INVALID_OBJECT:
      Napi::Error::New(env, "Invalid ddwaf object").ThrowAsJavaScriptException();
      return env.Null();
    case DDWAF_ERR_INVALID_ARGUMENT:
      Napi::Error::New(env, "Invalid arguments").ThrowAsJavaScriptException();
      // TODO(simon-id): we should free the data here
      return env.Null();
    default:
      break;
  }
  // there is no error. We need to collect perf data
  Napi::Object res = Napi::Object::New(env);
  mlog("Set timeout");
  res.Set("timeout", Napi::Boolean::New(env, result.timeout));
  if (result.total_runtime) {
    mlog("Set total_runtime");
    res.Set("totalRuntime", Napi::Number::New(env, result.total_runtime));
  }
  if (code == DDWAF_MATCH) {
    res.Set("status", Napi::String::New(env, "match"));
    res.Set("data", Napi::String::New(env, result.data));
    Napi::Array actions = Napi::Array::New(env, result.actions.size);
    for (uint32_t i = 0; i < result.actions.size; ++i) {
      actions[i] = Napi::String::New(env, result.actions.array[i]);
    }
    res.Set("actions", actions);
  }
  ddwaf_result_free(&result);
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
    InstanceAccessor("disposed", &DDWAFContext::GetDisposed, nullptr, napi_enumerable),
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
