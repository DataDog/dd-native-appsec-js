/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#ifndef SRC_MAIN_H_
#define SRC_MAIN_H_
#include <napi.h>
#include <ddwaf.h>

struct AddonData {
  Napi::FunctionReference context_constructor;
  Napi::FunctionReference subcontext_constructor;
};

// TODO(@vdeturckheim): logs with ddwaf_set_log_cb

class DDWAF : public Napi::ObjectWrap<DDWAF> {
 public:
    // Static JS methods
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    static Napi::Value version(const Napi::CallbackInfo& info);

    // JS constructor
    explicit DDWAF(const Napi::CallbackInfo& info);

    // JS instance methods
    Napi::Value update_config(const Napi::CallbackInfo& info);
    Napi::Value remove_config(const Napi::CallbackInfo& info);
    Napi::Value GetConfigPaths(const Napi::CallbackInfo& info);
    Napi::Value createContext(const Napi::CallbackInfo& info);
    void Finalize(Napi::Env env);
    Napi::Value GetDisposed(const Napi::CallbackInfo& info);
    void dispose(const Napi::CallbackInfo& info);

 private:
    void update_known_addresses(const Napi::CallbackInfo& info);
    void update_known_actions(const Napi::CallbackInfo& info);
    void rebuild_instance();

    bool _disposed{true};
    ddwaf_builder _builder{nullptr};
    ddwaf_handle _handle{nullptr};
};

class DDWAFContext : public Napi::ObjectWrap<DDWAFContext> {
 public:
    // Static JS methods
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    // JS constructor
    explicit DDWAFContext(const Napi::CallbackInfo& info);

    // JS instance methods
    Napi::Value run(const Napi::CallbackInfo& info);
    Napi::Value createSubcontext(const Napi::CallbackInfo& info);
    Napi::Value GetDisposed(const Napi::CallbackInfo& info);
    void dispose(const Napi::CallbackInfo& info);
    void Finalize(Napi::Env env);

    // C++ only instance method
    bool init(ddwaf_handle handle);

 private:
    bool _disposed{true};
    ddwaf_context _context{nullptr};
    ddwaf_allocator _alloc{nullptr};
};

class DDWAFSubcontext : public Napi::ObjectWrap<DDWAFSubcontext> {
 public:
    // Static JS methods
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    // JS constructor
    explicit DDWAFSubcontext(const Napi::CallbackInfo& info);

    // JS instance methods
    Napi::Value run(const Napi::CallbackInfo& info);
    Napi::Value GetDisposed(const Napi::CallbackInfo& info);
    void dispose(const Napi::CallbackInfo& info);
    void Finalize(Napi::Env env);

    // C++ only instance method
    bool init(ddwaf_context context, ddwaf_allocator alloc);

 private:
    bool _disposed{true};
    ddwaf_subcontext _subcontext{nullptr};
    ddwaf_allocator _alloc{nullptr};
};
#endif  // SRC_MAIN_H_
