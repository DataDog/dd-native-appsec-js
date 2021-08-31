#include <napi.h>
#include "ddwaf.h"

// TODO: logs with ddwaf_set_log_cb
// TODO: fix issue when used with workers

class DDWAF : public Napi::ObjectWrap<DDWAF> {
  public:
    // Static JS methods
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    static Napi::Value version(const Napi::CallbackInfo& info);

    // JS constructor
    DDWAF(const Napi::CallbackInfo& info);

    // JS instance methods
    Napi::Value createContext(const Napi::CallbackInfo& info);
    void Finalize(Napi::Env env);
    Napi::Value GetDisposed(const Napi::CallbackInfo& info);
    void dispose(const Napi::CallbackInfo& info);

  private:
    bool _disposed;
    ddwaf_handle _handle;
};

class DDWAFContext : public Napi::ObjectWrap<DDWAFContext> {
  public:
    // Static JS methods
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    // JS constructor
    DDWAFContext(const Napi::CallbackInfo& info);

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
