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

class DDWAF : public Napi::ObjectWrap<DDWAF> {
 public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    static Napi::Value version(const Napi::CallbackInfo& info);

    explicit DDWAF(const Napi::CallbackInfo& info);

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
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    explicit DDWAFContext(const Napi::CallbackInfo& info);

    Napi::Value run(const Napi::CallbackInfo& info);
    Napi::Value createSubcontext(const Napi::CallbackInfo& info);
    Napi::Value GetDisposed(const Napi::CallbackInfo& info);
    void dispose(const Napi::CallbackInfo& info);
    void Finalize(Napi::Env env);

    bool init(ddwaf_handle handle);

 private:
    bool _disposed{true};
    ddwaf_context _context{nullptr};
    ddwaf_allocator _alloc{nullptr};
};

// A subcontext inherits parent data while keeping its own data and side effects local.
// It shares ownership of the ruleset and parent store, but not the parent itself, so either may be destroyed first.
// The parent must be alive when the subcontext is created.
class DDWAFSubcontext : public Napi::ObjectWrap<DDWAFSubcontext> {
 public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    explicit DDWAFSubcontext(const Napi::CallbackInfo& info);

    Napi::Value run(const Napi::CallbackInfo& info);
    Napi::Value GetDisposed(const Napi::CallbackInfo& info);
    void dispose(const Napi::CallbackInfo& info);
    void Finalize(Napi::Env env);

    bool init(ddwaf_context context, ddwaf_allocator alloc);

 private:
    bool _disposed{true};
    ddwaf_subcontext _subcontext{nullptr};
    ddwaf_allocator _alloc{nullptr};
};
#endif  // SRC_MAIN_H_
