#ifndef DD_NATIVE_APPSEC_JS_JSSET_H
#include <napi.h>
#define DD_NATIVE_APPSEC_JS_JSSET_H
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
#endif //DD_NATIVE_APPSEC_JS_JSSET_H
