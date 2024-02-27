/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/

#ifndef SRC_JSSET_H_
#define SRC_JSSET_H_

#include <napi.h>
class JsSet : public Napi::Object {
  public:
    JsSet(napi_env env, napi_value value) : Object(env, value) {}

    static JsSet Create(Napi::Env env) {
        return env.Global().Get("Set").As<Napi::Function>().New({}).As<JsSet>();
    }

    void Add(Napi::Value value) {
        Get("add").As<Napi::Function>().Call(*this, {value});
    }

    bool Has(Napi::Value value) {
        return Get("has").As<Napi::Function>().Call(*this, {value}).ToBoolean().Value();
    }

    void Delete(Napi::Value value) {
        Get("delete").As<Napi::Function>().Call(*this, {value});
    }
};
#endif  // SRC_JSSET_H_
