#include <napi.h>
#include "ddwaf.h"

ddwaf_object* to_ddwaf_object(ddwaf_object *object, Napi::Env env, Napi::Value val, int depth);
ddwaf_object* to_ddwaf_object(ddwaf_object *object, Napi::Env env, Napi::Value val);
