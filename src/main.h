/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#ifndef SRC_MAIN_H_
#define SRC_MAIN_H_
#include <napi.h>
#include <ddwaf.h>

// TODO(@vdeturckheim): logs with ddwaf_set_log_cb
// TODO(@vdeturckheim): fix issue when used with workers

class DDWAF : public Napi::ObjectWrap<DDWAF> {
 public:
    // Static JS methods
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    static Napi::Value version(const Napi::CallbackInfo& info);

    // JS constructor
    explicit DDWAF(const Napi::CallbackInfo& info);

    // JS instance methods
    void update(const Napi::CallbackInfo& info);
    Napi::Value createContext(const Napi::CallbackInfo& info);
    void Finalize(Napi::Env env);
    Napi::Value GetDisposed(const Napi::CallbackInfo& info);
    void dispose(const Napi::CallbackInfo& info);

 private:
    void update_known_addresses(const Napi::CallbackInfo& info);

    bool _disposed;
    ddwaf_handle _handle;
};

class DDWAFContext : public Napi::ObjectWrap<DDWAFContext> {
 public:
    // Static JS methods
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    // JS constructor
    explicit DDWAFContext(const Napi::CallbackInfo& info);

    // JS instance methods
    Napi::Value run(const Napi::CallbackInfo& info);
    Napi::Value GetDisposed(const Napi::CallbackInfo& info);
    void dispose(const Napi::CallbackInfo& info);
    void Finalize(Napi::Env env);

    // C++ only instance method
    bool init(ddwaf_handle handle);

 private:
    bool _disposed;
    ddwaf_context _context;
};
#endif  // SRC_MAIN_H_
